//! Warm-kernel test harness: one persistent daemon brings the IDA kernel up once, then `fork`s a
//! copy-on-write child per test so bring-up is paid once instead of per test.
//!
//! A test binary built against this crate is its own runner (`harness = false`) and speaks the
//! three modes `cargo nextest` expects, dispatched by [`main`]:
//!
//! - `--daemon <db> <sock>` runs the persistent `daemon`, which opens the database once, listens
//!   on a Unix socket, and forks a warm child per request. It is started out of band (by the test
//!   recipe), never by nextest.
//! - `--list` prints the registered case names for nextest's discovery pass.
//! - `--exact <name>` is nextest's per-test invocation, a thin `proxy` that asks the daemon to run
//!   one case and mirrors the child's output and exit code back.
//!
//! Cases register through the [`register`]/[`kernel_test`] attributes, which emit an
//! `inventory::submit!` naming an niladic runner; the daemon and the list mode both read the
//! resulting [`KernelTest`] registry. Because registration is `inventory`-based rather than
//! libtest's compile-time collection, a full upstream `#[rstest]` (case expansion, fixtures) rides
//! the harness by targeting `register` with rstest's own `#[test_attr]`, so the harness gains
//! parametrization without reimplementing it.
//!
//! The daemon forks on its own main thread, the `g_main` owner, so each child is a valid single
//! owner of the moved kernel (see [`Database`](idakit::Database)'s `Send` contract). Copy-on-write
//! gives each child an isolated view: a write in one child is invisible to its siblings.

mod daemon;
mod db;
mod proxy;
mod wire;

use std::env;

pub use idakit_test_macros::{kernel_test, register};
pub use inventory;

pub use crate::db::{DbRef, db_ref};

/// One registered case: a unique name, a niladic runner (a panic is a failure), and a scheduling
/// weight.
///
/// The name is `module_path!()::fn_ident`, unique within the binary, and is what nextest lists and
/// addresses. The weight is the case's admission cost in the daemon's token pool, so a heavy case
/// reserves more of the pool and serializes against other heavy cases while light cases pack in.
pub struct KernelTest {
    /// Fully-qualified case name, unique across the binary.
    pub name: &'static str,
    /// Runs the case body against the warm kernel; a panic is a failure.
    pub run: fn(),
    /// Admission cost in daemon tokens (default 1).
    pub weight: u32,
}

inventory::collect!(KernelTest);

/// Every registered case, sorted by name for a stable listing.
///
/// The listing must be a pure function of the binary: nextest lists in one process and runs each
/// case in another, so anything that could yield a different set on the second pass would list a
/// case it can never find.
#[must_use]
pub fn all() -> Vec<&'static KernelTest> {
    let mut cases: Vec<&'static KernelTest> = inventory::iter::<KernelTest>.into_iter().collect();
    cases.sort_by_key(|case| case.name);
    cases
}

/// Entry point for a harness test binary: dispatch on argv to the daemon, list, or proxy mode.
///
/// A test binary's `main` is exactly `fn main() { idakit_test::main() }`; the mode is chosen by the
/// arguments nextest (or the test recipe) passes. `--list` returns; `--daemon` and the per-test
/// proxy never return.
///
/// # Panics
/// In `--daemon` mode if the kernel cannot be brought up or the database cannot be opened, and in
/// proxy mode if the daemon connection fails; both are unrecoverable for a test run.
pub fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if let Some(i) = args.iter().position(|a| a == "--daemon") {
        let db = args.get(i + 1).cloned();
        let sock = args.get(i + 2).expect("--daemon needs <db> <sock>");
        daemon::run(db, sock);
    }

    if args.iter().any(|a| a == "--list") {
        // nextest asks for the ignored subset in a separate pass; the harness has none.
        if !args.iter().any(|a| a == "--ignored") {
            for case in all() {
                println!("{}: test", case.name);
            }
        }
        return;
    }

    // Proxy mode: the name follows `--exact`, else it is the first non-flag argument.
    let name = args
        .iter()
        .position(|a| a == "--exact")
        .and_then(|i| args.get(i + 1))
        .or_else(|| args.iter().find(|a| !a.starts_with("--")))
        .cloned()
        .expect("no test name (expected --exact <name>)");
    proxy::run(&name);
}
