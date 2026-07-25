//! The runner half: leases cases to a pool of warm workers and reports each case individually.
//!
//! This is what breaks the tradeoff the harness exists to fix. A conventional runner spawns one
//! process per test, so every case pays the full setup cost; batching cases to avoid that normally
//! means collapsing them into one coarse test, which loses the ability to name, filter, time, and
//! report them separately. Here the two are decoupled: [`Runner::run`] takes N individually named
//! [`Case`]s, executes them inside a handful of long-lived workers, and returns N individual
//! [`CaseResult`]s. Batching is an execution detail nothing downstream can observe.
//!
//! Cases carry an optional [`Case::group`], meaning "these can share one piece of expensive state".
//! For kernel tests the group is the fixture, so a worker opens that database once and every case
//! against it follows immediately. A group in progress is reserved to its worker rather than shared,
//! since a second worker joining it would have to open the same database and undo the saving. Work
//! that cannot share state, anything that writes, is left ungrouped and stays available to every
//! worker, so it parallelizes exactly as it does today.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use crate::lifecycle::Nursery;
use crate::protocol::{Event, Line, Request, Status, read_line};

/// One case to run, named uniquely within the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    /// The name the worker resolves and the report shows.
    pub name: String,
    /// Cases sharing a group are cheaper to run back to back on one worker.
    pub group: Option<String>,
}

impl Case {
    /// A case with no group, run wherever a worker is free.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            group: None,
        }
    }

    /// Sets the affinity group, usually the fixture the case needs open.
    #[must_use]
    pub fn group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }
}

/// What one case did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseResult {
    /// The case's name, as given in its [`Case`].
    pub name: String,
    /// How it finished.
    pub status: Status,
    /// Wall time of the case body, in milliseconds.
    pub millis: u64,
    /// Failure reason, skip reason, or one-line summary.
    pub message: String,
    /// Everything the case (or the kernel underneath it) printed.
    pub output: Vec<String>,
}

/// Spawns and drives a pool of workers over a set of cases.
#[derive(Debug, Clone)]
pub struct Runner {
    program: PathBuf,
    worker_args: Vec<OsString>,
    workers: usize,
}

impl Runner {
    /// A runner that spawns `program` in worker mode.
    ///
    /// `worker_args` are the arguments that put the binary into its worker loop.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>, worker_args: &[&str]) -> Self {
        Self {
            program: program.into(),
            worker_args: worker_args.iter().map(OsString::from).collect(),
            workers: default_workers(),
        }
    }

    /// Sets how many workers run concurrently. Zero is treated as one.
    #[must_use]
    pub const fn workers(mut self, workers: usize) -> Self {
        self.workers = if workers == 0 { 1 } else { workers };
        self
    }

    /// Runs every case and returns one result per case, in completion order.
    ///
    /// Never spawns more workers than there are cases, so a short run does not pay for setup it
    /// cannot use.
    ///
    /// # Errors
    /// If the nursery cannot be created, which would leave workers able to outlive the runner.
    ///
    /// # Panics
    /// If a worker thread panicked while holding the scheduler or results lock, which would mean
    /// the runner's own bookkeeping is no longer trustworthy.
    pub fn run(&self, cases: Vec<Case>) -> io::Result<Vec<CaseResult>> {
        if cases.is_empty() {
            return Ok(Vec::new());
        }
        let nursery = Nursery::new()?;
        let scheduler = Mutex::new(Scheduler {
            pending: cases,
            workers: HashMap::new(),
        });
        let results = Mutex::new(Vec::new());
        let count = self
            .workers
            .min(scheduler.lock().expect("fresh lock").pending.len());

        std::thread::scope(|scope| {
            for _ in 0..count {
                scope.spawn(|| {
                    // A worker that cannot start is reported against the cases it would have run,
                    // rather than aborting the whole run.
                    if let Err(err) = self.serve(&nursery, &scheduler, &results) {
                        drain_as_failed(&scheduler, &results, &err.to_string());
                    }
                });
            }
        });

        Ok(results
            .into_inner()
            .expect("no thread panicked while holding"))
    }

    /// One worker's whole life: spawn, run cases until none are left, then shut it down.
    fn serve(
        &self,
        nursery: &Nursery,
        scheduler: &Mutex<Scheduler>,
        results: &Mutex<Vec<CaseResult>>,
    ) -> io::Result<()> {
        let mut worker = self.spawn(nursery)?;
        let mut last_group = None;

        while let Some(case) = next_case(scheduler, last_group.as_deref()) {
            last_group.clone_from(&case.group);
            let result = worker.run_case(&case.name);
            let alive = result.is_ok();
            results
                .lock()
                .expect("results lock")
                .push(result.unwrap_or_else(|err| crashed(&case.name, &err.to_string())));
            if !alive {
                // The worker died mid-case, so a fresh one takes over and the rest of the queue is
                // unaffected. `last_group` deliberately stays put: the replacement inherits the
                // group claim, which would otherwise be held by a process that no longer exists and
                // strand every case still in that group.
                worker = self.spawn(nursery)?;
            }
        }

        worker.shutdown();
        Ok(())
    }

    /// Spawns one worker with its streams wired up.
    fn spawn(&self, nursery: &Nursery) -> io::Result<Worker> {
        let mut command = Command::new(&self.program);
        command.args(&self.worker_args).stdin(Stdio::piped());

        // stdout and stderr share one pipe so a case's output cannot be reordered relative to the
        // control frames that bracket it, which is what makes attribution exact.
        let (reader, writer) = io::pipe()?;
        let errors = writer.try_clone()?;
        command.stdout(writer).stderr(errors);

        nursery.configure(&mut command);
        let mut child = command.spawn()?;
        nursery.adopt(&child)?;

        let stdin = child.stdin.take().expect("stdin was piped");
        Ok(Worker {
            child,
            stdin,
            output: BufReader::new(reader),
        })
    }
}

/// A spawned worker and its two control streams.
struct Worker {
    child: Child,
    stdin: std::process::ChildStdin,
    output: BufReader<io::PipeReader>,
}

impl Worker {
    /// Leases one case to this worker and collects its result.
    ///
    /// # Errors
    /// If the worker died or its stream ended before reporting the case, in which case the caller
    /// replaces it.
    fn run_case(&mut self, name: &str) -> io::Result<CaseResult> {
        Request::Run(name.to_owned()).write_to(&mut self.stdin)?;

        let mut output = Vec::new();
        loop {
            match read_line(&mut self.output)? {
                Some(Line::Output(text)) => output.push(text),
                Some(Line::Control(Event::Start(_))) => {}
                Some(Line::Control(Event::End {
                    status,
                    millis,
                    message,
                })) => {
                    return Ok(CaseResult {
                        name: name.to_owned(),
                        status,
                        millis,
                        message,
                        output,
                    });
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("worker exited during {name}:\n{}", output.join("\n")),
                    ));
                }
            }
        }
    }

    /// Asks the worker to exit and waits for it, ignoring errors from an already-dead process.
    fn shutdown(mut self) {
        let _ = Request::Quit.write_to(&mut self.stdin);
        drop(self.stdin);
        let _ = self.child.wait();
    }
}

/// Hands out pending cases, keeping each worker on one group for as long as that group has work.
///
/// Staying put is what makes grouping pay: for kernel tests the group is the fixture, so a worker
/// that never leaves mid-stream opens that database exactly once no matter how many cases run
/// against it.
///
/// Choosing where to go next is a question of marginal benefit, since joining a group costs one
/// more database open. A group is scored by its pending cases divided by the workers it would then
/// have, so an untouched group (no workers yet) is preferred automatically, and a large group
/// already in progress can still be worth joining: a second worker on sixty pending cases buys
/// about thirty of them for one open, which beats opening a fresh group of eleven. Exclusivity is
/// therefore a consequence of low ratios rather than a rule, so one big group is never pinned to a
/// single worker and serialized.
///
/// An ungrouped case shares nothing, so it scores as the one case its own open would buy.
struct Scheduler {
    pending: Vec<Case>,
    /// How many workers are currently on each group, the denominator of that group's score.
    workers: HashMap<String, usize>,
}

impl Scheduler {
    fn take(&mut self, current: Option<&str>) -> Option<Case> {
        // Never leave a group that still has work: doing so would pay to reopen it later.
        if let Some(group) = current {
            if let Some(index) = self
                .pending
                .iter()
                .position(|case| case.group.as_deref() == Some(group))
            {
                return Some(self.pending.remove(index));
            }
            self.leave(group);
        }

        let case = self.pending.remove(self.best_index()?);
        if let Some(group) = &case.group {
            *self.workers.entry(group.clone()).or_default() += 1;
        }
        Some(case)
    }

    /// The pending case whose group offers the most work per additional open.
    fn best_index(&self) -> Option<usize> {
        let mut pending_per_group: HashMap<&str, usize> = HashMap::new();
        for case in &self.pending {
            if let Some(group) = case.group.as_deref() {
                *pending_per_group.entry(group).or_default() += 1;
            }
        }

        // Scores are compared as exact fractions (cross-multiplied) to keep the choice integral.
        let mut best: Option<(usize, usize, usize)> = None;
        for (index, case) in self.pending.iter().enumerate() {
            let (cases, workers) = match case.group.as_deref() {
                None => (1, 1),
                Some(group) => (
                    pending_per_group[group],
                    self.workers.get(group).copied().unwrap_or(0) + 1,
                ),
            };
            if best.is_none_or(|(_, best_cases, best_workers)| {
                cases * best_workers > best_cases * workers
            }) {
                best = Some((index, cases, workers));
            }
        }
        best.map(|(index, _, _)| index)
    }

    /// Records that a worker has finished with `group`.
    fn leave(&mut self, group: &str) {
        if let Some(count) = self.workers.get_mut(group) {
            *count -= 1;
            if *count == 0 {
                self.workers.remove(group);
            }
        }
    }

    /// Removes every pending case, for when the run cannot continue.
    fn drain(&mut self) -> Vec<Case> {
        std::mem::take(&mut self.pending)
    }
}

fn next_case(scheduler: &Mutex<Scheduler>, last_group: Option<&str>) -> Option<Case> {
    scheduler.lock().expect("scheduler lock").take(last_group)
}

/// Reports every remaining case as failed, for when a worker cannot be spawned at all.
///
/// Drains the queue directly rather than leasing case by case, since a claimed group would
/// otherwise be skipped and those cases would go unreported entirely.
fn drain_as_failed(scheduler: &Mutex<Scheduler>, results: &Mutex<Vec<CaseResult>>, reason: &str) {
    let stranded = scheduler.lock().expect("scheduler lock").drain();
    let mut results = results.lock().expect("results lock");
    results.extend(stranded.iter().map(|case| crashed(&case.name, reason)));
}

fn crashed(name: &str, reason: &str) -> CaseResult {
    CaseResult {
        name: name.to_owned(),
        status: Status::Failed,
        millis: 0,
        message: reason.to_owned(),
        output: Vec::new(),
    }
}

/// One worker per core, which is where throughput stops improving for kernel work.
fn default_workers() -> usize {
    std::thread::available_parallelism().map_or(4, std::num::NonZero::get)
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    fn scheduler(spec: &[(&str, Option<&str>)]) -> Scheduler {
        Scheduler {
            pending: spec
                .iter()
                .map(|(name, group)| Case {
                    name: (*name).to_owned(),
                    group: group.map(str::to_owned),
                })
                .collect(),
            workers: HashMap::new(),
        }
    }

    #[test]
    fn scheduler_never_leaves_a_group_that_still_has_work() {
        // Leaving early would mean paying to reopen the same database later.
        let mut scheduler = scheduler(&[("a1", Some("a")), ("b1", Some("b")), ("a2", Some("a"))]);
        assert!(scheduler.take(Some("a")).expect("a case").name == "a1");
        assert!(scheduler.take(Some("a")).expect("a case").name == "a2");
        assert!(scheduler.take(Some("a")).expect("a case").name == "b1");
    }

    #[test]
    fn scheduler_prefers_an_untouched_group_over_one_in_progress() {
        let mut scheduler = scheduler(&[
            ("a1", Some("a")),
            ("a2", Some("a")),
            ("b1", Some("b")),
            ("b2", Some("b")),
        ]);
        assert!(scheduler.take(None).expect("a case").name == "a1");
        // "a" would now cost a second open for its one remaining case; "b" costs one open for two.
        assert!(scheduler.take(None).expect("a case").name == "b1");
    }

    #[test]
    fn scheduler_joins_a_large_group_over_a_small_fresh_one() {
        // A second worker on seven remaining cases buys about half of them for one open, which
        // beats opening a fresh group that only holds two.
        let mut scheduler = scheduler(&[
            ("big1", Some("big")),
            ("big2", Some("big")),
            ("big3", Some("big")),
            ("big4", Some("big")),
            ("big5", Some("big")),
            ("big6", Some("big")),
            ("big7", Some("big")),
            ("big8", Some("big")),
            ("small1", Some("small")),
            ("small2", Some("small")),
        ]);
        assert!(scheduler.take(None).expect("a case").name == "big1");
        assert!(scheduler.take(None).expect("a case").name == "big2");
    }

    #[test]
    fn scheduler_opens_a_fresh_group_when_the_busy_one_is_nearly_done() {
        // The mirror image: with little left in "big", a second open there is not worth it.
        let mut scheduler = scheduler(&[
            ("big1", Some("big")),
            ("big2", Some("big")),
            ("big3", Some("big")),
            ("fresh1", Some("fresh")),
            ("fresh2", Some("fresh")),
            ("fresh3", Some("fresh")),
        ]);
        assert!(scheduler.take(None).expect("a case").name == "big1");
        assert!(scheduler.take(None).expect("a case").name == "fresh1");
    }

    #[test]
    fn leaving_an_exhausted_group_releases_it() {
        let mut scheduler = scheduler(&[("a1", Some("a")), ("b1", Some("b"))]);
        assert!(scheduler.take(None).expect("a case").name == "a1");
        assert!(scheduler.workers.get("a") == Some(&1));
        // "a" has nothing left, so the worker moves on and leaves no stale worker count behind to
        // discount it against a future worker.
        assert!(scheduler.take(Some("a")).expect("a case").name == "b1");
        assert!(!scheduler.workers.contains_key("a"));
    }

    #[test]
    fn ungrouped_cases_share_nothing_and_are_always_reachable() {
        // Anything that writes is left ungrouped, so it never waits on another worker's database.
        let mut scheduler = scheduler(&[("w1", None), ("w2", None), ("w3", None)]);
        assert!(scheduler.take(None).is_some());
        assert!(scheduler.take(None).is_some());
        assert!(scheduler.take(None).is_some());
        assert!(scheduler.take(None).is_none());
    }

    #[test]
    fn scheduler_drains_to_empty() {
        let mut scheduler = scheduler(&[("only", None)]);
        assert!(scheduler.take(None).is_some());
        assert!(scheduler.take(None).is_none());
    }

    #[test]
    fn zero_workers_is_treated_as_one() {
        let runner = Runner::new("x", &["--worker"]).workers(0);
        assert!(runner.workers == 1);
    }

    #[test]
    fn an_empty_run_spawns_nothing() {
        let results = Runner::new("does-not-exist", &["--worker"])
            .run(Vec::new())
            .expect("empty run");
        assert!(results.is_empty());
    }
}
