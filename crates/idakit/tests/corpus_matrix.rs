//! Corpus fan-out matrix: one runtime-generated test per database (see [`common::corpus`]). Each
//! opens one private copy and runs every [`common::checks`] invariant against it -- open dominates,
//! so it's amortized across the check axis rather than paid per check.
//!
//! `harness = false` + `libtest-mimic` because the corpus is discovered at runtime, not
//! compile-time. Under nextest each trial is its own process -- required, since the kernel is a
//! per-process singleton. No corpus, no cases.

mod common;

use std::path::Path;
use std::process::ExitCode;
use std::sync::Mutex;

use libtest_mimic::{Arguments, Failed, Trial};

use common::checks::Check;
use idakit::Ida;

// Serializes trials that share a process (bare `cargo test`); uncontended under nextest.
static KERNEL_GATE: Mutex<()> = Mutex::new(());

// Return the exit code from `main` rather than `Conclusion::exit()`, which calls
// `std::process::exit`. On Windows that is `ExitProcess`, which skips the CRT `atexit` handlers --
// including the facade's idalib exit-banner swallow (see runtime.cpp). Skipping it lets the banner
// corrupt `nextest --list` (an empty list becomes a stray `\r\n`). Returning from `main` takes the
// normal CRT exit path, so the swallow runs. (Unix was unaffected: its `process::exit` runs atexit.)
fn main() -> ExitCode {
    let args = Arguments::from_args();
    let fixtures = common::corpus::fixtures();

    let mut trials = Vec::new();
    for fx in fixtures {
        let name = fx.name.clone();
        let path = fx.path.clone();
        let skips = fx.skip_checks.clone();
        trials.push(Trial::test(name, move || run_db(&path, &skips)));
    }

    libtest_mimic::run(&args, trials).exit_code()
}

fn run_db(src: &Path, skips: &[String]) -> Result<(), Failed> {
    let _gate = KERNEL_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let db = common::corpus::working_copy(src).map_err(|e| Failed::from(e.to_string()))?;
    let path = db.path().to_owned();
    let skips = skips.to_vec();

    let outcome = Ida::run(move |ida| run_checks(&ida, &path, &skips));

    match outcome {
        Ok(Ok(report)) => report.into_failed(),
        Ok(Err(open_err)) => Err(Failed::from(open_err)),
        Err(init_err) => Err(Failed::from(init_err.to_string())),
    }
}

/// One `call` per check: the open persists on the actor between calls, and each call catches its
/// own panic, so a failing check neither re-opens, aborts the others, nor kills the kernel.
fn run_checks(ida: &Ida, path: &str, skips: &[String]) -> Result<Report, String> {
    let path_owned = path.to_owned();
    match ida.call(move |idb| idb.open(&path_owned).call().map_err(|e| e.to_string())) {
        Ok(Ok(())) => {}
        Ok(Err(open_err)) => return Err(open_err),
        Err(call_err) => return Err(call_err.to_string()),
    }

    let mut report = Report::default();
    for (name, check) in common::checks::CHECKS {
        let name = *name;
        if skips.iter().any(|s| s == name) {
            report.lines.push(format!("  {name}: skipped (manifest)"));
            continue;
        }
        let check: Check = *check;
        match ida.call(move |idb| check(idb)) {
            Ok(summary) => report.lines.push(format!("  {name}: {summary}")),
            Err(call_err) => report.failures.push(format!("{name}: {call_err}")),
        }
    }

    let _ = ida.call(|idb| idb.close(false));
    Ok(report)
}

/// Passing summaries in `lines`, panicked checks in `failures`; the trial fails iff any failed.
#[derive(Default)]
struct Report {
    lines: Vec<String>,
    failures: Vec<String>,
}

impl Report {
    fn into_failed(self) -> Result<(), Failed> {
        for line in &self.lines {
            println!("{line}");
        }
        if self.failures.is_empty() {
            Ok(())
        } else {
            Err(Failed::from(self.failures.join("\n")))
        }
    }
}
