//! A test runner that decouples test identity from process count.
//!
//! Test binaries whose setup is expensive face a forced choice. One process per test keeps each
//! case individually named, filterable, timed, and reported, but pays the setup every time.
//! Batching cases into one process avoids that, but conventional runners spawn one process per
//! *listed* test, so batching means collapsing many cases into one coarse test, which hides
//! failures, blurs per-case timing, and makes filtering impossible.
//!
//! This crate refuses the choice. A [`Runner`] takes N individually named [`Case`]s, executes them
//! inside a small pool of long-lived workers that each pay setup once, and returns N individual
//! [`CaseResult`]s. Batching becomes an execution detail that nothing downstream can observe.
//!
//! # The two halves
//!
//! A binary using this crate plays both roles. Spawned normally it is the runner; spawned with a
//! worker flag it calls [`serve`] and becomes a worker, looping over the cases the runner leases
//! it. Because both roles are the same compiled binary, case names cannot drift between listing
//! and execution.
//!
//! ```no_run
//! use idakit_runner::{Case, Outcome, Runner, serve};
//!
//! # fn main() -> std::io::Result<()> {
//! if std::env::args().any(|a| a == "--worker") {
//!     // Expensive one-time setup happens here, before any case runs.
//!     return serve(|name| match name {
//!         "always_passes" => Outcome::Passed(None),
//!         other => Outcome::Failed(format!("no such case: {other}")),
//!     });
//! }
//!
//! let program = std::env::current_exe()?;
//! let results = Runner::new(program, &["--worker"])
//!     .workers(4)
//!     .run(vec![Case::new("always_passes").group("fixture-a")])?;
//! # let _ = results;
//! # Ok(())
//! # }
//! ```
//!
//! # Grouping
//!
//! A [`Case`] may carry a group, meaning "these cases can share one piece of expensive state". For
//! kernel tests the group is the fixture, so a worker opens that database once and every case
//! against it follows immediately, without any case knowing it was batched. A group in progress is
//! reserved to one worker, since a second worker joining it would just open the same database
//! again. Cases that cannot share state, anything that writes, are left ungrouped and remain
//! available to every worker.
//!
//! # Worker lifetimes
//!
//! Workers cannot outlive the runner, including when the runner is killed rather than exiting
//! cleanly. The per-platform mechanism lives in the private `lifecycle` module: a job object on
//! Windows, `PR_SET_PDEATHSIG` on Linux.
//!
//! A case that never reports is bounded by [`Runner::timeout`]: its worker is killed, that one case
//! is failed, and a replacement takes over the rest of the queue. Without it a wedged case would
//! park the runner on a blocking read forever, losing the whole run instead of one case.

mod lifecycle;
pub mod protocol;
mod runner;
mod worker;

pub use crate::protocol::Status;
pub use crate::runner::{Case, CaseResult, Runner};
pub use crate::worker::{Outcome, expecting_panic, panic_message, serve};
