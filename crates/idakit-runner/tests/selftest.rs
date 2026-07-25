//! End-to-end proof of the runner against the `selftest-worker` fixture.
//!
//! These cover the property the crate exists for: N individually named cases produce N individual
//! results, while running inside far fewer processes. They are deliberately free of any dependency
//! on IDA, so the process, pipe, and lifetime machinery is proven on every platform the runner has
//! to support, not just the one where the kernel happens to be installed.

use std::collections::{BTreeMap, HashSet};

use assert2::{assert, check};
use idakit_runner::{Case, CaseResult, Runner, Status};

const WORKER: &str = env!("CARGO_BIN_EXE_selftest-worker");

fn run(cases: Vec<Case>, workers: usize) -> Vec<CaseResult> {
    Runner::new(WORKER, &["--worker"])
        .workers(workers)
        .run(cases)
        .expect("the runner starts")
}

fn by_name(results: &[CaseResult]) -> BTreeMap<&str, &CaseResult> {
    results
        .iter()
        .map(|r| (r.name.as_str(), r))
        .collect::<BTreeMap<_, _>>()
}

/// The `pid=N opens=M` pair the fixture reports in every passing case's summary.
fn stats_of(result: &CaseResult) -> (&str, u32) {
    let (pid, opens) = result
        .message
        .split_once(' ')
        .expect("a pass reports pid and opens");
    (
        pid.strip_prefix("pid=").expect("a pid field"),
        opens
            .strip_prefix("opens=")
            .and_then(|n| n.parse().ok())
            .expect("an opens field"),
    )
}

fn pid_of(result: &CaseResult) -> &str {
    stats_of(result).0
}

#[test]
fn every_case_reports_its_own_result() {
    let cases = vec![
        Case::new("a::pass"),
        Case::new("b::fail"),
        Case::new("c::skip"),
        Case::new("d::panic"),
    ];
    let results = run(cases, 2);
    assert!(results.len() == 4);

    let by = by_name(&results);
    check!(by["a::pass"].status == Status::Passed);
    check!(by["b::fail"].status == Status::Failed);
    check!(by["b::fail"].message == "declared failure");
    check!(by["c::skip"].status == Status::Skipped);
    check!(by["c::skip"].message == "declared skip");
    // A panicking case fails on its own, rather than taking the worker (and its siblings) down.
    check!(by["d::panic"].status == Status::Failed);
    check!(by["d::panic"].message == "deliberate panic");
}

#[test]
fn many_cases_share_few_processes() {
    // The whole point: identity is per case, cost is per worker.
    let cases: Vec<Case> = (0..40).map(|i| Case::new(format!("g{i}::pass"))).collect();
    let results = run(cases, 4);

    assert!(results.len() == 40);
    check!(results.iter().all(|r| r.status == Status::Passed));

    let pids: HashSet<&str> = results.iter().map(pid_of).collect();
    check!(
        pids.len() <= 4,
        "40 cases should run in at most 4 processes, saw {}",
        pids.len()
    );
}

#[test]
fn a_worker_never_reopens_a_group_it_finished() {
    // Grouping only pays if a worker stays put: bouncing between fixtures would make it reopen a
    // database it had already closed. A worker may legitimately serve several groups in turn, and
    // may join a busy group when the remaining work justifies the extra open, so the property
    // worth asserting is not exclusivity but that no group is ever entered twice by one worker.
    let mut cases = Vec::new();
    for group in ["alpha", "beta", "gamma"] {
        for i in 0..6 {
            cases.push(Case::new(format!("{group}::{i}::pass")).group(group));
        }
    }
    let results = run(cases, 3);
    assert!(results.len() == 18);
    check!(results.iter().all(|r| r.status == Status::Passed));

    let mut groups_per_worker: BTreeMap<&str, HashSet<&str>> = BTreeMap::new();
    let mut opens_per_worker: BTreeMap<&str, u32> = BTreeMap::new();
    for result in &results {
        let (pid, opens) = stats_of(result);
        let group = result.name.split("::").next().expect("a group prefix");
        groups_per_worker.entry(pid).or_default().insert(group);
        let seen = opens_per_worker.entry(pid).or_default();
        *seen = (*seen).max(opens);
    }

    for (pid, groups) in &groups_per_worker {
        // One open per distinct group is the floor; anything more means it went back.
        check!(
            opens_per_worker[pid] as usize == groups.len(),
            "worker {pid} opened {} times for {} groups",
            opens_per_worker[pid],
            groups.len()
        );
    }
}

#[test]
fn output_is_attributed_to_the_case_that_printed_it() {
    let cases = vec![
        Case::new("quiet_before::pass"),
        Case::new("loud::print"),
        Case::new("quiet_after::pass"),
    ];
    // One worker, so all three share a process and misattribution would actually be possible.
    let results = run(cases, 1);
    let by = by_name(&results);

    let loud = &by["loud::print"].output;
    check!(loud.iter().any(|l| l == "printed to stdout"));
    check!(loud.iter().any(|l| l == "printed to stderr"));
    check!(by["quiet_before::pass"].output.is_empty());
    check!(by["quiet_after::pass"].output.is_empty());
}

#[test]
fn a_crashing_case_does_not_strand_the_rest() {
    // The fixture exits without reporting, so the runner must notice, blame that case, and bring
    // up a replacement worker for everything still queued.
    let mut cases = vec![Case::new("boom::crash")];
    cases.extend((0..8).map(|i| Case::new(format!("after{i}::pass"))));

    let results = run(cases, 1);
    assert!(results.len() == 9);

    let by = by_name(&results);
    check!(by["boom::crash"].status == Status::Failed);
    for i in 0..8 {
        let name = format!("after{i}::pass");
        check!(by[name.as_str()].status == Status::Passed, "{name} ran");
    }
}

#[test]
fn timings_are_per_case() {
    let results = run(vec![Case::new("only::pass")], 1);
    // A trivial case should not be billed for the worker's startup, which is the whole reason
    // timing is measured around the case body rather than the process.
    check!(results[0].millis < 1_000);
}
