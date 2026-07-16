//! Corpus fan-out matrix: every [`common::checks`] invariant against every corpus database.
//!
//! `harness = false` + `libtest-mimic` because the corpus is discovered at runtime, not at
//! compile time. Registration and fan-out live in [`common::harness`]; this binary only wires
//! the check axis onto a suite.

mod common;

use std::process::ExitCode;

use common::harness::{Fixtures, Suite};

fn main() -> ExitCode {
    let mut suite = Suite::new("corpus").fixtures(Fixtures::All);
    for &(name, check) in common::checks::CHECKS {
        suite = suite.case(name, check);
    }
    common::harness::run(suite)
}
