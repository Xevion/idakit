//! Corpus fan-out matrix: one test per (database × invariant check), generated at runtime from
//! the discovered corpus (see [`common::corpus`]). Every fixture is copied to a scratch dir and
//! opened fresh for each check, so a run holds one database's working set at a time per process.
//!
//! `harness = false` + `libtest-mimic`: the corpus is machine-specific and runtime-discovered, so
//! the cases can't be `#[test]` fns or `rstest` `#[case]`s (both compile-time). Run under nextest,
//! which gives each generated case its own process -- the only way to run these in parallel, since
//! idakit's kernel is a per-process singleton. Without a corpus present, zero cases are generated.

mod common;

use std::path::Path;
use std::sync::Mutex;

use libtest_mimic::{Arguments, Failed, Trial};

use common::checks::Check;

// The kernel is a per-process singleton; serialize trials sharing a process (a direct
// `cargo test` run threads them). Under nextest each trial is its own process, so uncontended.
static KERNEL_GATE: Mutex<()> = Mutex::new(());

fn main() {
    let args = Arguments::from_args();
    let fixtures = common::corpus::fixtures();

    let mut trials = Vec::new();
    for fx in fixtures {
        for (check_name, check) in common::checks::CHECKS {
            let name = format!("{}::{}", fx.name, check_name);
            let path = fx.path.clone();
            let check: Check = *check;
            // A check the manifest declares inapplicable to this fixture is reported ignored,
            // not run -- a raw ROM legitimately has no symbols, and that is not a failure.
            let skipped = fx.skips(check_name);
            trials
                .push(Trial::test(name, move || run_one(&path, check)).with_ignored_flag(skipped));
        }
    }

    libtest_mimic::run(&args, trials).exit();
}

fn run_one(src: &Path, check: Check) -> Result<(), Failed> {
    let _gate = KERNEL_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let db = common::corpus::working_copy(src).map_err(|e| Failed::from(e.to_string()))?;
    let path = db.path().to_owned();

    let res = idakit::Ida::run(move |ida| {
        ida.call(move |idb| {
            idb.open(&path).call().map_err(|e| e.to_string())?;
            let summary = check(idb);
            idb.close(false);
            Ok::<String, String>(summary)
        })
    });

    match res {
        Ok(Ok(Ok(summary))) => {
            println!("{summary}");
            Ok(())
        }
        Ok(Ok(Err(open_err))) => Err(Failed::from(open_err)),
        // The check panicked; `ida.call`'s catch_unwind surfaced it as a CallError.
        Ok(Err(call_err)) => Err(Failed::from(call_err.to_string())),
        Err(init_err) => Err(Failed::from(init_err.to_string())),
    }
}
