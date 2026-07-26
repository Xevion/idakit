//! Driver and worker for the whole kernel-touching suite: every `#[kernel_test]` and every corpus
//! invariant, run as individually reported cases across one pool of warm kernels.
//!
//! Both halves used to be their own binary with its own worker pool, which meant paying kernel
//! bring-up twice over for what is the same work: open a database, run things against it. They are
//! one plan here, so a worker that has the canonical database open serves its registered tests and
//! its corpus checks without reopening anything in between.
//!
//! Identity is what the pooling must not cost. Each case is named, timed, filtered, and reported on
//! its own, exactly as if it had a process to itself; an earlier version of the corpus half ran
//! every check for a fixture inside a single trial, so 74 trials stood in for 814 real cases and a
//! failure named only its fixture. [`idakit_runner`] is what decouples the two: this module plans N
//! named cases, and the runner executes them inside far fewer processes.
//!
//! The plan must be a pure function of the corpus manifest and the registry, since the driver
//! computes it in one process and the workers recompute it in another. [`plan`] is the only place
//! that decides, so the two cannot disagree.

use std::collections::HashMap;
use std::process::ExitCode;

use idakit::corpus::{self, Fixture, WorkingCopy};
use idakit::prelude::Ida;
use idakit_runner::{Case, CaseResult, Outcome, Runner, Status, expecting_panic, serve};

use super::TestDb;
use super::checks::{CHECKS, Check};
use super::registry::{Isolation, KernelTest, Warm};

/// Argument that turns this binary into a worker instead of the driver.
pub const WORKER_FLAG: &str = "--idakit-worker";

/// Case-name prefix for the corpus fan-out half, keeping it clear of the registry's module paths.
const CORPUS: &str = "corpus";

/// Which halves of the suite to plan, and how many workers to plan them across.
///
/// Both come from the environment rather than arguments because the callers that need them cannot
/// pass any. `cargo mutants` drives the suite through `cargo test` hundreds of times over, so it has
/// no channel for a positional filter, and it wants the registered tests without the corpus fan-out,
/// which dominates wall time while saying nothing about the code under test.
const SCOPE: &str = "IDAKIT_TEST_SCOPE";
const WORKERS: &str = "IDAKIT_TEST_WORKERS";

/// Which halves of the suite to plan.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Everything, which is what `just test` runs.
    All,
    /// Only the `#[kernel_test]`s, skipping the corpus fan-out.
    Registered,
    /// Only the corpus fan-out.
    Corpus,
}

impl Scope {
    /// Reads [`SCOPE`], defaulting to everything.
    ///
    /// An unrecognised value is an error rather than a fallback: silently widening or narrowing the
    /// suite on a typo is exactly the failure this switch could otherwise cause, and a run that
    /// checks less than it claims reports green either way.
    fn from_env() -> Result<Self, String> {
        match std::env::var(SCOPE) {
            Err(_) => Ok(Self::All),
            Ok(value) => match value.as_str() {
                "all" | "" => Ok(Self::All),
                "registered" => Ok(Self::Registered),
                "corpus" => Ok(Self::Corpus),
                other => Err(format!(
                    "{SCOPE}={other:?} is not one of all, registered, corpus"
                )),
            },
        }
    }
}

/// Reads [`WORKERS`], defaulting to the runner's own choice.
///
/// A cap is what keeps concurrent kernels (~0.85 GiB each) inside a machine's memory when something
/// outside this process is already running several suites at once, as a sharded mutants run does.
fn worker_cap() -> Result<Option<usize>, String> {
    match std::env::var(WORKERS) {
        Err(_) => Ok(None),
        Ok(value) => value
            .parse()
            .map(Some)
            .map_err(|_| format!("{WORKERS}={value:?} is not a worker count")),
    }
}

/// Runs the whole suite, as the driver or as a worker depending on how this process was started.
///
/// Positional arguments filter by substring, so one case can still be run alone; `--list` prints the
/// case names and runs nothing.
#[must_use]
pub fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == WORKER_FLAG) {
        return work();
    }
    let list = args.iter().any(|arg| arg == "--list");
    let filters: Vec<&str> = args
        .iter()
        .filter(|arg| !arg.starts_with('-'))
        .map(String::as_str)
        .collect();
    drive(&filters, list)
}

/// A database the suite opens, and what it contributes to the plan.
struct Site {
    fixture: Fixture,
    /// Whether the registered `#[kernel_test]`s run here. Their copy also goes to RAM rather than
    /// beside the corpus, since this is the database every writer reopens.
    canonical: bool,
    /// Whether the corpus checks fan out over this database.
    checks: bool,
}

/// One planned case: its name, where it runs, and what it does.
struct Planned {
    name: String,
    /// Index into the site list, which is also the case's affinity group.
    site: usize,
    body: Body,
    isolation: Isolation,
    /// Set when the case is inapplicable here, so it reports without opening anything.
    skip: Option<String>,
}

/// What a case actually does when it runs.
enum Body {
    /// A corpus invariant over the open database.
    Check(Check),
    /// A registered test, which reaches the database through the warm-kernel context.
    Test(&'static KernelTest),
}

/// Every database the suite opens, the manifest's fixtures plus wherever the canonical one lives.
fn sites() -> Vec<Site> {
    let mut sites: Vec<Site> = corpus::fixtures()
        .into_iter()
        .map(|fixture| Site {
            fixture,
            canonical: false,
            checks: true,
        })
        .collect();

    let Some(path) = TestDb::source() else {
        return sites;
    };
    if let Some(site) = sites.iter_mut().find(|s| s.fixture.path == path) {
        site.canonical = true;
    } else {
        // An `IDAKIT_TEST_DB` override names a database the manifest does not list, so it takes the
        // registered tests but stays out of the fan-out.
        sites.push(Site {
            fixture: Fixture {
                name: "canonical".to_owned(),
                path,
                skip_checks: Vec::new(),
                decompiler: true,
            },
            canonical: true,
            checks: false,
        });
    }
    sites
}

/// The case list `scope` asks for: every check against every fixture, and every registered test
/// against the canonical database.
fn plan(sites: &[Site], scope: Scope) -> Vec<Planned> {
    let mut planned = Vec::new();
    if scope != Scope::Registered {
        for (index, site) in sites.iter().enumerate().filter(|(_, s)| s.checks) {
            for &(check_name, check) in CHECKS {
                planned.push(Planned {
                    name: format!("{CORPUS}::{}::{check_name}", site.fixture.name),
                    site: index,
                    body: Body::Check(check),
                    isolation: Isolation::ReadOnly,
                    skip: effective_skip(&site.fixture, check_name),
                });
            }
        }
    }
    if scope != Scope::Corpus
        && let Some(index) = sites.iter().position(|s| s.canonical)
    {
        for test in inventory::iter::<KernelTest> {
            planned.push(Planned {
                name: test.case_name(),
                site: index,
                body: Body::Test(test),
                isolation: test.isolation,
                skip: None,
            });
        }
    }
    planned
}

/// Plans the case list, runs it across a pool of workers, and reports every case.
fn drive(filters: &[&str], list: bool) -> ExitCode {
    // A misconfigured corpus (a manifest that is present but broken) must fail loudly rather than
    // silently collapse to zero cases and a green run.
    if let Err(reason) = corpus::validate() {
        println!("manifest_is_valid ... FAILED\n  {reason}");
        return ExitCode::FAILURE;
    }

    let (scope, cap) = match (Scope::from_env(), worker_cap()) {
        (Ok(scope), Ok(cap)) => (scope, cap),
        (Err(reason), _) | (_, Err(reason)) => {
            println!("kernel: {reason}");
            return ExitCode::FAILURE;
        }
    };

    let sites = sites();
    if let Some(dup) = first_duplicate(sites.iter().map(|s| s.fixture.name.as_str())) {
        println!("fixtures collide on display name {dup:?}");
        return ExitCode::FAILURE;
    }
    let planned = plan(&sites, scope);
    if let Some(dup) = first_duplicate(planned.iter().map(|p| p.name.as_str())) {
        println!("cases collide on name {dup:?}");
        return ExitCode::FAILURE;
    }
    if planned.is_empty() {
        println!("kernel: no corpus configured, skipping");
        return ExitCode::SUCCESS;
    }

    let cases: Vec<Case> = planned
        .iter()
        .filter(|case| filters.is_empty() || filters.iter().any(|f| case.name.contains(f)))
        .map(|case| Case::new(case.name.clone()).group(sites[case.site].fixture.name.clone()))
        .collect();

    if list {
        for case in &cases {
            println!("{}", case.name);
        }
        return ExitCode::SUCCESS;
    }
    if cases.is_empty() {
        println!("kernel: no cases matched, skipping");
        return ExitCode::SUCCESS;
    }

    let program = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            println!("kernel: cannot resolve this executable: {err}");
            return ExitCode::FAILURE;
        }
    };
    let total = cases.len();
    let mut runner = Runner::new(program, &[WORKER_FLAG]);
    if let Some(cap) = cap {
        runner = runner.workers(cap);
    }
    match runner.run(cases) {
        Ok(results) => report(&results, total),
        Err(err) => {
            println!("kernel: could not start workers: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Brings the kernel up once, then serves cases, holding each database open across its whole group.
fn work() -> ExitCode {
    // The driver already rejected a bad value and would not have spawned anything, so agreeing with
    // it here is all that is left to do.
    let Ok(scope) = Scope::from_env() else {
        eprintln!("worker: bad {SCOPE}");
        return ExitCode::FAILURE;
    };
    let sites = sites();
    let plan: HashMap<String, Planned> = plan(&sites, scope)
        .into_iter()
        .map(|case| (case.name.clone(), case))
        .collect();

    let outcome = Ida::run(move |ida| {
        let mut open: Option<Open> = None;
        serve(move |name| {
            let Some(case) = plan.get(name) else {
                return Outcome::Failed(format!("no such case: {name}"));
            };
            if let Some(reason) = &case.skip {
                return Outcome::Skipped(reason.clone());
            }
            if let Err(reason) = ensure_open(&ida, &mut open, case.site, &sites[case.site]) {
                return Outcome::Failed(reason);
            }
            // Marked before the body runs, so a case that panics part-way through its writes still
            // forces the next one onto a freshly reopened database.
            if case.isolation == Isolation::Writes {
                open.as_mut().expect("ensure_open left one open").clean = false;
            }

            match &case.body {
                Body::Check(check) => {
                    let check = *check;
                    ida.call(move |idb| check(&*idb))
                        .map_or_else(|err| Outcome::Failed(err.to_string()), Outcome::from)
                }
                Body::Test(test) => {
                    let _warm = Warm::new(&ida);
                    invoke(test)
                }
            }
        })
    });

    match outcome {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(err)) => {
            eprintln!("worker stream ended: {err}");
            ExitCode::FAILURE
        }
        Err(err) => {
            eprintln!("kernel init failed: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Runs one registered test and turns what it did into an outcome.
///
/// A test that does not declare `should_panic` reports through the runner's own panic handling, so
/// a failure keeps its original location and message. One that does has to be caught here instead,
/// since only this side knows a panic was the point.
fn invoke(test: &KernelTest) -> Outcome {
    let Some(expected) = test.should_panic else {
        (test.run)();
        return Outcome::Passed(None);
    };
    expecting_panic(expected, test.run)
}

/// The database a worker currently has open, and the disposable copy backing it.
struct Open {
    site: usize,
    /// Must outlive the open database, since dropping it deletes the file.
    copy: Scratch,
    /// False once a case that writes has been handed out, meaning the next case needs a reopen.
    clean: bool,
}

/// A disposable copy of a fixture, in whichever scratch area suits it.
enum Scratch {
    /// The canonical database, which is reopened constantly, so it goes to a RAM disk where one
    /// exists.
    Ram(TestDb),
    /// A corpus fixture, copied beside the corpus: they are large enough that a RAM disk would
    /// compete with the kernel's own working set under fan-out.
    Corpus(WorkingCopy),
}

impl Scratch {
    fn path(&self) -> &str {
        match self {
            Self::Ram(db) => db.path(),
            Self::Corpus(copy) => copy.path(),
        }
    }
}

/// Leaves `site`'s database open and pristine, doing the least work that achieves it.
///
/// Three cases, cheapest first: already open and untouched, nothing happens; already open but
/// dirtied by a writer, the same copy is reopened; a different database, a fresh copy is taken.
/// Reopening rather than recopying is what makes a writer cheap, and it is sound because
/// `close(false)` deletes the sidecar files every mutation lives in and leaves the `.i64` container
/// untouched. `tests/reopen_is_pristine.rs` is the guard that keeps that true.
fn ensure_open(
    ida: &Ida,
    open: &mut Option<Open>,
    index: usize,
    site: &Site,
) -> Result<(), String> {
    if open.as_ref().is_some_and(|current| current.site == index) {
        let current = open.as_mut().expect("just checked");
        if current.clean {
            return Ok(());
        }
        let path = current.copy.path().to_owned();
        close(ida);
        open_at(ida, &path)?;
        current.clean = true;
        return Ok(());
    }
    if open.is_some() {
        close(ida);
        *open = None;
    }

    let copy = if site.canonical {
        Scratch::Ram(TestDb::copy_of(&site.fixture.path))
    } else {
        Scratch::Corpus(corpus::working_copy(&site.fixture.path).map_err(|e| e.to_string())?)
    };
    open_at(ida, copy.path())?;
    *open = Some(Open {
        site: index,
        copy,
        clean: true,
    });
    Ok(())
}

/// Closes the open database without saving, since every fixture on disk is read-only ground truth
/// for every other run.
fn close(ida: &Ida) {
    let _ = ida.call(|idb| idb.close(false));
}

fn open_at(ida: &Ida, path: &str) -> Result<(), String> {
    let path = path.to_owned();
    ida.call(move |idb| idb.open(&path).call().map_err(|e| e.to_string()))
        .map_err(|e| e.to_string())?
}

/// Whether `check` is inapplicable to `fixture`: declared in the manifest's `skip_checks`, or
/// implied for the decompiler-dependent checks by `decompiler = false`.
fn effective_skip(fixture: &Fixture, check: &str) -> Option<String> {
    if fixture.skips(check) {
        return Some("manifest".to_owned());
    }
    if !fixture.decompiler && matches!(check, "decompile" | "argloc") {
        return Some("no decompiler".to_owned());
    }
    None
}

/// The first name shared by two entries, if any.
fn first_duplicate<'a>(names: impl Iterator<Item = &'a str>) -> Option<String> {
    let mut names: Vec<&str> = names.collect();
    names.sort_unstable();
    names
        .windows(2)
        .find(|w| w[0] == w[1])
        .map(|w| w[0].to_owned())
}

/// Prints one line per case, then any failures in full, then a summary.
fn report(results: &[CaseResult], total: usize) -> ExitCode {
    let mut ordered: Vec<&CaseResult> = results.iter().collect();
    ordered.sort_by(|a, b| a.name.cmp(&b.name));

    let mut passed = 0usize;
    let mut skipped = 0usize;
    let mut failed = Vec::new();
    for result in &ordered {
        let (label, detail) = match result.status {
            Status::Passed => {
                passed += 1;
                ("ok", result.message.as_str())
            }
            Status::Skipped => {
                skipped += 1;
                ("skipped", result.message.as_str())
            }
            Status::Failed => {
                failed.push(*result);
                ("FAILED", result.message.as_str())
            }
        };
        if detail.is_empty() {
            println!("{} ... {label} ({}ms)", result.name, result.millis);
        } else {
            println!("{} ... {label} ({}ms) {detail}", result.name, result.millis);
        }
    }

    for result in &failed {
        println!("\nfailure: {}\n{}", result.name, result.message);
        for line in &result.output {
            println!("{line}");
        }
    }

    println!(
        "\nsummary: {passed} passed, {} failed, {skipped} skipped, {total} total",
        failed.len()
    );
    if failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
