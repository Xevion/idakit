//! Shared runtime harness for the kernel-touching test binaries: [`Suite`] registers cases and
//! [`run`] fans them out across fixtures, one individually reported case per fixture and check.
//!
//! Each case is named, timed, filtered, and reported on its own. That is the point: an earlier
//! version of this harness ran every check for a fixture inside a single trial, which meant 74
//! trials stood in for 814 real cases, so a failure named only its fixture, timings were per
//! fixture, and no single check could be run alone.
//!
//! Cost is decoupled from that identity by [`idakit_runner`]. A binary using this harness has two
//! modes. Run normally it is the driver: it plans the case list and hands it to a pool of workers.
//! Run with [`WORKER_FLAG`] it is a worker: it brings the kernel up once, then opens each fixture
//! once and runs every case grouped onto that fixture before moving on. So bring-up is paid per
//! worker and `open` per fixture, while the report still has one line per case.
//!
//! The case list must be a pure function of the corpus manifest, since the driver plans in one
//! process and the workers resolve names in another.

use std::process::ExitCode;
use std::sync::Arc;

use idakit::corpus::{self, Fixture, WorkingCopy};
use idakit::prelude::{Database, Ida};
use idakit_runner::{Case, CaseResult, Outcome, Runner, Status, serve};

/// Argument that turns a harness binary into a worker instead of the driver.
pub const WORKER_FLAG: &str = "--idakit-worker";

/// Which fixtures a [`Suite`] resolves against.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Fixtures {
    /// The one manifest-designated canonical fixture ([`idakit::corpus::canonical`]).
    ///
    /// Case names carry no fixture prefix, since naming the only fixture adds nothing.
    Canonical,
    /// Every openable corpus fixture ([`idakit::corpus::fixtures`]).
    All,
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
    /// Starts a new suite named `name`, used to prefix its diagnostic cases.
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

    /// Registers a read-only case, which shares its fixture's open database with its siblings.
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

/// Runs `suite`, as the driver or as a worker depending on how this process was started.
///
/// # Panics
/// If `suite` never called [`Suite::fixtures`].
#[must_use]
pub fn run(suite: Suite) -> ExitCode {
    let Suite {
        name,
        fixtures,
        cases,
    } = suite;
    let mode = fixtures.expect("Suite::fixtures(...) must be called before harness::run");

    if std::env::args().any(|arg| arg == WORKER_FLAG) {
        work(cases, mode)
    } else {
        drive(name, &cases, mode)
    }
}

/// Plans the case list, runs it across a pool of workers, and reports every case.
fn drive(suite_name: &str, cases: &[CaseEntry], mode: Fixtures) -> ExitCode {
    // A misconfigured corpus (a manifest that is present but broken) must fail loudly rather than
    // silently collapse to zero cases and a green run.
    if let Err(reason) = corpus::validate() {
        println!("{suite_name}_manifest_is_valid ... FAILED\n  {reason}");
        return ExitCode::FAILURE;
    }

    let fixtures = resolve_fixtures(mode);
    if let Some(dup) = first_duplicate(fixtures.iter().map(|f| f.name.as_str())) {
        println!("{suite_name} fixtures collide on display name {dup:?}");
        return ExitCode::FAILURE;
    }
    if let Some(dup) = first_duplicate(cases.iter().map(|c| c.name.as_str())) {
        println!("{suite_name} cases collide on name {dup:?}");
        return ExitCode::FAILURE;
    }

    let planned = plan(cases, mode, &fixtures);
    if planned.is_empty() {
        println!("{suite_name}: no corpus configured, skipping");
        return ExitCode::SUCCESS;
    }

    let program = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            println!("{suite_name}: cannot resolve this executable: {err}");
            return ExitCode::FAILURE;
        }
    };
    let total = planned.len();
    match Runner::new(program, &[WORKER_FLAG]).run(planned) {
        Ok(results) => report(&results, total),
        Err(err) => {
            println!("{suite_name}: could not start workers: {err}");
            ExitCode::FAILURE
        }
    }
}

/// One [`Case`] per fixture and check, grouped by fixture so a worker opens each database once.
fn plan(entries: &[CaseEntry], mode: Fixtures, fixtures: &[Fixture]) -> Vec<Case> {
    let mut cases = Vec::new();
    for fixture in fixtures {
        for entry in entries {
            let name = match mode {
                Fixtures::All => format!("{}::{}", fixture.name, entry.name),
                Fixtures::Canonical => entry.name.clone(),
            };
            cases.push(Case::new(name).group(fixture.name.clone()));
        }
    }
    cases
}

/// Prints one line per case, then any failures in full, then a summary.
#[must_use]
pub fn report(results: &[CaseResult], total: usize) -> ExitCode {
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

/// Brings the kernel up once, then serves cases, holding each fixture open across its own group.
fn work(cases: Vec<CaseEntry>, mode: Fixtures) -> ExitCode {
    let fixtures = resolve_fixtures(mode);

    let outcome = Ida::run(move |ida| {
        let mut open: Option<OpenFixture> = None;
        serve(|name| {
            let (fixture_name, case_name) = split_name(mode, name);
            let Some(fixture) = fixtures.iter().find(|f| f.name == fixture_name) else {
                return Outcome::Failed(format!("no such fixture: {fixture_name}"));
            };
            let Some(entry) = cases.iter().find(|c| c.name == case_name) else {
                return Outcome::Failed(format!("no such case: {case_name}"));
            };
            if let Some(reason) = effective_skip(fixture, &entry.name) {
                return Outcome::Skipped(reason);
            }
            match ensure_open(&ida, &mut open, fixture) {
                Ok(()) => invoke(&ida, entry),
                Err(reason) => Outcome::Failed(reason),
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

/// The fixture a worker currently has open, and the disposable copy backing it.
///
/// The [`WorkingCopy`] must outlive the open database, since dropping it deletes the file.
struct OpenFixture {
    name: String,
    _working: WorkingCopy,
}

/// Opens `fixture` unless it is already the open one, closing whatever was open before.
fn ensure_open(ida: &Ida, open: &mut Option<OpenFixture>, fixture: &Fixture) -> Result<(), String> {
    if open.as_ref().is_some_and(|o| o.name == fixture.name) {
        return Ok(());
    }
    if open.is_some() {
        // Never save: a fixture on disk is read-only ground truth for every other run.
        let _ = ida.call(|idb| idb.close(false));
        *open = None;
    }

    let working = corpus::working_copy(&fixture.path).map_err(|e| e.to_string())?;
    let path = working.path().to_owned();
    ida.call(move |idb| idb.open(&path).call().map_err(|e| e.to_string()))
        .map_err(|e| e.to_string())??;
    *open = Some(OpenFixture {
        name: fixture.name.clone(),
        _working: working,
    });
    Ok(())
}

/// Runs one case on the kernel thread, turning a panic into a failed case rather than a dead
/// worker.
fn invoke(ida: &Ida, entry: &CaseEntry) -> Outcome {
    let run = Arc::clone(&entry.run);
    match ida.call(move |idb| run(&*idb)) {
        Ok(outcome) => outcome,
        Err(err) => Outcome::Failed(err.to_string()),
    }
}

/// Splits a planned case name back into its fixture and case halves.
fn split_name(mode: Fixtures, name: &str) -> (String, String) {
    match mode {
        Fixtures::All => name.split_once("::").map_or_else(
            || (String::new(), name.to_owned()),
            |(fixture, case)| (fixture.to_owned(), case.to_owned()),
        ),
        Fixtures::Canonical => ("canonical".to_owned(), name.to_owned()),
    }
}

fn resolve_fixtures(mode: Fixtures) -> Vec<Fixture> {
    match mode {
        Fixtures::All => corpus::fixtures(),
        // Wrapped so the canonical database is an ordinary one-element fixture list, sharing every
        // code path with `Fixtures::All`.
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

/// The first name shared by two entries, if any.
pub fn first_duplicate<'a>(names: impl Iterator<Item = &'a str>) -> Option<String> {
    let mut names: Vec<&str> = names.collect();
    names.sort_unstable();
    names
        .windows(2)
        .find(|w| w[0] == w[1])
        .map(|w| w[0].to_owned())
}

/// Whether `case_name` is inapplicable to `fixture`: declared in the manifest's `skip_checks`, or
/// implied for the decompiler-dependent cases by `decompiler = false`.
fn effective_skip(fixture: &Fixture, case_name: &str) -> Option<String> {
    if fixture.skips(case_name) {
        return Some("manifest".to_owned());
    }
    if !fixture.decompiler && matches!(case_name, "decompile" | "argloc") {
        return Some("no decompiler".to_owned());
    }
    None
}
