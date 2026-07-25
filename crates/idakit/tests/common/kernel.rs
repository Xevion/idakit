//! Driver and worker for the `#[kernel_test]` binary, the counterpart to [`harness`] for tests
//! that all share one database rather than fanning out across the corpus.
//!
//! Every registered test used to be its own process, which meant a full kernel bring-up each time
//! even though the tests are indistinguishable from the kernel's point of view. Here they are
//! individually named, timed, and reported exactly as before, but executed inside a few long-lived
//! workers. Bring-up is paid per worker, and the database is reopened only when a test's
//! [`Isolation`] says the previous one may have dirtied it.
//!
//! Test bodies are untouched by this: they still call
//! [`with_canonical_db`](super::with_canonical_db), which notices it is inside a worker and uses
//! the kernel already running there.

use std::collections::HashMap;
use std::process::ExitCode;

use idakit::corpus;
use idakit::prelude::Ida;
use idakit_runner::{Case, Outcome, Runner, serve};

use super::TestDb;
use super::harness::{WORKER_FLAG, first_duplicate, report};
use super::registry::{Isolation, KernelTest, Warm};

/// Runs every registered kernel test, as the driver or as a worker depending on how this process
/// was started.
///
/// Positional arguments filter by substring, so one test can still be run alone; `--list` prints
/// the case names and runs nothing.
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

/// Plans the case list, runs it across a pool of workers, and reports every case.
fn drive(filters: &[&str], list: bool) -> ExitCode {
    // A misconfigured corpus (a manifest that is present but broken) must fail loudly rather than
    // silently collapse to zero cases and a green run.
    if let Err(reason) = corpus::validate() {
        println!("kernel_manifest_is_valid ... FAILED\n  {reason}");
        return ExitCode::FAILURE;
    }

    let names: Vec<String> = tests().map(KernelTest::case_name).collect();
    if let Some(dup) = first_duplicate(names.iter().map(String::as_str)) {
        println!("kernel tests collide on name {dup:?}");
        return ExitCode::FAILURE;
    }

    let cases: Vec<Case> = tests()
        .map(|test| (test, test.case_name()))
        .filter(|(_, name)| filters.is_empty() || filters.iter().any(|f| name.contains(f)))
        .map(|(test, name)| match test.isolation {
            // Every read-only test wants the same database, so grouping them lets one worker open
            // it once and run all of them. A writer shares nothing and stays ungrouped.
            Isolation::ReadOnly => Case::new(name).group("canonical"),
            Isolation::Writes => Case::new(name),
        })
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
    if corpus::canonical().is_none() {
        println!("kernel: no corpus configured, skipping");
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
    match Runner::new(program, &[WORKER_FLAG]).run(cases) {
        Ok(results) => report(&results, total),
        Err(err) => {
            println!("kernel: could not start workers: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Brings the kernel up once, then serves cases, reopening the database only when the last one may
/// have dirtied it.
fn work() -> ExitCode {
    let tests: HashMap<String, &'static KernelTest> =
        tests().map(|test| (test.case_name(), test)).collect();

    let outcome = Ida::run(move |ida| {
        let mut copy: Option<TestDb> = None;
        let mut clean = false;
        serve(move |name| {
            let Some(test) = tests.get(name) else {
                return Outcome::Failed(format!("no such kernel test: {name}"));
            };
            if !clean {
                match reset(&ida, &mut copy) {
                    Ok(()) => clean = true,
                    Err(reason) => return Outcome::Failed(reason),
                }
            }
            // Marked before the body runs, so a test that panics part-way through its writes still
            // forces the next one to get a fresh database.
            if test.isolation == Isolation::Writes {
                clean = false;
            }

            let _warm = Warm::new(&ida);
            (test.run)();
            Outcome::Passed(None)
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

/// Resets the worker's database to a pristine state, taking its private copy on the first call.
///
/// The copy is made once and reused, not remade per reset: `close(false)` deletes the sidecar files
/// every mutation lives in and leaves the `.i64` container untouched, so reopening the same file is
/// already a clean slate. That is the difference between a reset costing an open and one costing a
/// whole-file copy as well, and `reopen_is_pristine` is the guard that keeps it true.
fn reset(ida: &Ida, copy: &mut Option<TestDb>) -> Result<(), String> {
    if copy.is_some() {
        // Never save: the canonical database on disk is read-only ground truth for every other run.
        let _ = ida.call(|idb| idb.close(false));
    }
    let db = match copy {
        Some(db) => db,
        None => copy.insert(TestDb::acquire().ok_or("no canonical database")?),
    };
    let path = db.path().to_owned();
    ida.call(move |idb| idb.open(&path).call().map_err(|e| e.to_string()))
        .map_err(|e| e.to_string())??;
    Ok(())
}

fn tests() -> impl Iterator<Item = &'static KernelTest> {
    inventory::iter::<KernelTest>.into_iter()
}
