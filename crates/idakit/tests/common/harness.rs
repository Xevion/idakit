//! Shared runtime harness for the kernel-touching [`libtest-mimic`](libtest_mimic) test
//! binaries: [`Suite`] registers cases, [`run`] fans them out across fixtures into trials.
//!
//! Every fixture's cases share one trial, so each fixture pays kernel bring-up and `open` once.
//!
//! The trial set must be a pure function of the corpus manifest: nextest lists trials in one
//! process and runs each in another, so anything that could pick a different set on the second
//! pass would list a trial it can never find.
//!
//! Every case prints `<name>: start` immediately before running and its result immediately after
//! (`println!` is line-buffered even into nextest's pipe), so a crash mid-trial leaves exactly
//! one unterminated `start` line naming the case that died.

use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError};

use idakit::prelude::{CallError, Database, Ida};
use libtest_mimic::{Arguments, Failed, Trial};

use idakit::corpus::{self, Fixture};

// Serializes trials that share a process (bare `cargo test`); uncontended under nextest, where
// each listed trial is its own process.
static KERNEL_GATE: Mutex<()> = Mutex::new(());

/// Which fixtures a [`Suite`] resolves against.
#[derive(Clone, Copy)]
pub enum Fixtures {
    /// The one manifest-designated canonical fixture ([`idakit::corpus::canonical`]).
    ///
    /// Its trial name elides to `"all"`, since naming the only fixture adds nothing.
    Canonical,
    /// Every openable corpus fixture ([`idakit::corpus::fixtures`]).
    All,
}

/// The result of running one case.
pub enum Outcome {
    /// The case ran to completion, with an optional one-line summary.
    Passed(Option<String>),
    /// The case did not run, for the given reason (an unmet precondition).
    Skipped(String),
}

impl From<String> for Outcome {
    fn from(summary: String) -> Self {
        Self::Passed(Some(summary))
    }
}

/// A named collection of kernel-test cases, run against a resolved fixture set.
///
/// Built with a fluent chain (`Suite::new("corpus").fixtures(Fixtures::All).case(...)`) and
/// consumed once by [`run`].
pub struct Suite {
    name: &'static str,
    fixtures: Option<Fixtures>,
    cases: Vec<CaseEntry>,
}

impl Suite {
    /// Starts a new suite named `name`, used to prefix its diagnostic trials.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            fixtures: None,
            cases: Vec::new(),
        }
    }

    /// Sets which fixtures this suite runs against. Required before [`run`].
    #[must_use]
    pub fn fixtures(mut self, mode: Fixtures) -> Self {
        self.fixtures = Some(mode);
        self
    }

    /// Registers a read-only case sharing one open database with every other case in this suite.
    #[must_use]
    pub fn case<O: Into<Outcome> + 'static>(
        mut self,
        name: &'static str,
        run: fn(&Database) -> O,
    ) -> Self {
        self.cases.push(CaseEntry {
            name: name.to_owned(),
            run: Arc::new(move |db| run(db).into()),
        });
        self
    }
}

#[derive(Clone)]
struct CaseEntry {
    name: String,
    run: Arc<dyn Fn(&Database) -> Outcome + Send + Sync>,
}

/// Builds one trial per fixture from `suite`'s cases and runs them.
///
/// # Panics
/// If `suite` never called [`Suite::fixtures`].
pub fn run(suite: Suite) -> ExitCode {
    let args = Arguments::from_args();

    let Suite {
        name: suite_name,
        fixtures: fixtures_mode,
        cases,
    } = suite;
    let fixtures_mode =
        fixtures_mode.expect("Suite::fixtures(...) must be called before harness::run");

    let mut trials = Vec::new();

    // A misconfigured corpus (manifest present but broken) must fail loudly rather than
    // silently collapse to zero trials and a green run.
    if let Err(reason) = corpus::validate() {
        trials.push(Trial::test(
            format!("{suite_name}_manifest_is_valid"),
            move || Err(Failed::from(reason)),
        ));
    }

    let fixtures: Vec<Arc<Fixture>> = resolve_fixtures(fixtures_mode)
        .into_iter()
        .map(Arc::new)
        .collect();

    // nextest runs trials by exact-match name, so a collision means one of the two silently
    // never runs rather than failing loudly; catch it here.
    if let Some(dup) = first_duplicate(fixtures.iter().map(|f| f.name.as_str()).collect()) {
        let reason = format!("{suite_name} fixtures collide on display name {dup:?}");
        trials.push(Trial::test(
            format!("{suite_name}_fixture_names_are_unique"),
            move || Err(Failed::from(reason)),
        ));
    }
    if let Some(dup) = first_duplicate(cases.iter().map(|c| c.name.as_str()).collect()) {
        let reason = format!("{suite_name} cases collide on name {dup:?}");
        trials.push(Trial::test(
            format!("{suite_name}_case_names_are_unique"),
            move || Err(Failed::from(reason)),
        ));
    }

    for fx in fixtures {
        let name = trial_name(fixtures_mode, &fx);
        let cases = cases.clone();
        trials.push(Trial::test(name, move || run_cases(fx, cases)));
    }

    // Hand the code back to `main` rather than calling `Conclusion::exit`: that exits via
    // Windows `ExitProcess`, skipping the CRT `atexit` handlers, including the facade's idalib
    // exit-banner swallow, whose banner then corrupts `nextest --list`.
    libtest_mimic::run(&args, trials).exit_code()
}

fn resolve_fixtures(mode: Fixtures) -> Vec<Fixture> {
    match mode {
        Fixtures::All => corpus::fixtures(),
        // Wrapped so the canonical database is an ordinary one-element fixture list, sharing
        // every code path with `Fixtures::All`.
        Fixtures::Canonical => corpus::canonical()
            .into_iter()
            .map(|path| Fixture {
                name: "canonical".to_owned(),
                path,
                skip_checks: Vec::new(),
                decompiler: true,
            })
            .collect(),
    }
}

fn trial_name(mode: Fixtures, fx: &Fixture) -> String {
    match mode {
        Fixtures::All => fx.name.clone(),
        Fixtures::Canonical => "all".to_owned(),
    }
}

/// The first name shared by two entries, if any.
fn first_duplicate(mut names: Vec<&str>) -> Option<String> {
    names.sort_unstable();
    names
        .windows(2)
        .find(|w| w[0] == w[1])
        .map(|w| w[0].to_owned())
}

/// Whether `case_name` is inapplicable to `fx`: declared in the manifest's `skip_checks`, or
/// implied for the decompiler-dependent cases by `decompiler = false`.
fn effective_skip(fx: &Fixture, case_name: &str) -> Option<String> {
    if fx.skips(case_name) {
        return Some("manifest".to_owned());
    }
    if !fx.decompiler && matches!(case_name, "decompile" | "argloc") {
        return Some("no decompiler".to_owned());
    }
    None
}

fn invoke(ida: &Ida, case: &CaseEntry) -> Result<Outcome, CallError> {
    let run = Arc::clone(&case.run);
    ida.call(move |idb| run(&*idb))
}

/// Runs every case for one fixture inside a single trial, sharing one open database.
fn run_cases(fx: Arc<Fixture>, cases: Vec<CaseEntry>) -> Result<(), Failed> {
    let _gate = KERNEL_GATE.lock().unwrap_or_else(PoisonError::into_inner);

    let working = corpus::working_copy(&fx.path).map_err(|e| Failed::from(e.to_string()))?;
    let path = working.path().to_owned();

    let outcome = Ida::run(move |ida| run_all_cases(&ida, &fx, &path, &cases));

    match outcome {
        Ok(Ok(failures)) if failures.is_empty() => Ok(()),
        Ok(Ok(failures)) => Err(Failed::from(failures.join("\n"))),
        Ok(Err(open_err)) => Err(Failed::from(open_err)),
        Err(init_err) => Err(Failed::from(init_err.to_string())),
    }
}

fn run_all_cases(
    ida: &Ida,
    fx: &Fixture,
    path: &str,
    cases: &[CaseEntry],
) -> Result<Vec<String>, String> {
    let path_owned = path.to_owned();
    match ida.call(move |idb| idb.open(&path_owned).call().map_err(|e| e.to_string())) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(e.to_string()),
    }

    let mut failures = Vec::new();
    for case in cases {
        let skip = effective_skip(fx, &case.name);
        dispatch(ida, case, skip, &mut failures);
    }

    let _ = ida.call(|idb| idb.close(false));
    Ok(failures)
}

/// Prints `<name>: start`, then runs `case` unless `skip` names a reason, printing the result
/// (or pushing a message onto `failures` for a panicked/disconnected call).
fn dispatch(ida: &Ida, case: &CaseEntry, skip: Option<String>, failures: &mut Vec<String>) {
    println!("{}: start", case.name);
    if let Some(reason) = skip {
        println!("{}: skipped ({reason})", case.name);
        return;
    }
    // Set IDAKIT_PROFILE to emit a per-check wall time on stderr, so `just profile-checks` can
    // attribute a fixture's runtime to individual checks without perturbing the normal output.
    let started = std::time::Instant::now();
    let result = invoke(ida, case);
    if std::env::var_os("IDAKIT_PROFILE").is_some() {
        eprintln!(
            "PROFILE\t{}\t{:.3}",
            case.name,
            started.elapsed().as_secs_f64()
        );
    }
    match result {
        Ok(Outcome::Passed(Some(summary))) => println!("{}: {summary}", case.name),
        Ok(Outcome::Passed(None)) => println!("{}: ok", case.name),
        Ok(Outcome::Skipped(reason)) => println!("{}: skipped ({reason})", case.name),
        Err(call_err) => failures.push(format!("{}: {call_err}", case.name)),
    }
}
