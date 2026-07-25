//! A fixture binary for the runner's own tests: a worker with no expensive setup.
//!
//! Each case name ends in the behaviour it should exhibit (`group::pass`, `group::panic`, and so
//! on), so one binary covers every outcome the runner has to handle.
//!
//! Every result reports the worker's process id and how many times this worker has switched group,
//! which stands in for how many times a real worker would have opened a database. Together they
//! let the tests prove both halves of the design: that many cases share few processes, and that a
//! worker never pays to reopen a group it already finished.

use idakit_runner::{Outcome, serve};

fn main() -> std::io::Result<()> {
    if std::env::args().any(|arg| arg == "--worker") {
        let pid = std::process::id();
        let mut current: Option<String> = None;
        let mut opens = 0u32;
        return serve(move |name| {
            // The group is the leading segment; the rest is the case's own identity and behaviour.
            let group = name.split_once("::").map(|(head, _)| head.to_owned());
            if group != current {
                opens += 1;
                current = group;
            }
            run(name, pid, opens)
        });
    }
    eprintln!("selftest-worker is a test fixture; the runner spawns it with --worker");
    std::process::exit(2);
}

fn run(name: &str, pid: u32, opens: u32) -> Outcome {
    let summary = format!("pid={pid} opens={opens}");
    match name.rsplit("::").next().unwrap_or(name) {
        "pass" => Outcome::Passed(Some(summary)),
        "skip" => Outcome::Skipped("declared skip".to_owned()),
        "fail" => Outcome::Failed("declared failure".to_owned()),
        "panic" => panic!("deliberate panic"),
        "print" => {
            println!("printed to stdout");
            eprintln!("printed to stderr");
            Outcome::Passed(Some(summary))
        }
        // Dies without reporting, so the runner has to notice and replace the worker.
        "crash" => std::process::exit(9),
        other => Outcome::Failed(format!("unknown behaviour {other:?}")),
    }
}
