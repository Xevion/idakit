//! idalib does not hijack process signal handlers on idakit's path. RE shows the crash-handler
//! installer (`sub_2296C60`: SEGV/ILL/FPE/BUS/ABRT/INT/TERM + altstack) is reached only through
//! crash-cleanup temp-file registration, which none of idakit's operations trigger. Verified
//! across init, open, analyze, and DB creation, batch on and off. This asserts that invariant
//! per signal: its handler is identical before idakit runs and after open+analyze, so a future
//! idalib that starts stealing signals fails here instead of silently taking them. One `#[case]`
//! per signal, rather than one test looping over all of them, so a drift on any signal is its
//! own reported failure instead of being masked by whichever signal happens to be checked first.

// The whole invariant is POSIX sigaction dispositions, which have no Windows analogue.
#![cfg(unix)]

use std::ffi::c_int;

use assert2::assert;
use idakit::kernel::Ida;
use rstest::rstest;

mod common;

/// The current disposition for `n` as an opaque handle value (`SIG_DFL` = 0, `SIG_IGN` = 1).
/// libc collapses the `sa_handler`/`sa_sigaction` union into one field, so this is the value
/// regardless of `SA_SIGINFO`.
fn disposition(n: c_int) -> usize {
    // SAFETY: a null `act` makes this read-only; sigaction fills `oldact` from the
    // process-global disposition and writes nothing back. Zeroed sigaction is valid.
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::sigaction(n, std::ptr::null(), &mut sa) };
    if rc == 0 { sa.sa_sigaction } else { 0 }
}

#[rstest]
#[case::int("INT", libc::SIGINT)]
#[case::ill("ILL", libc::SIGILL)]
#[case::abrt("ABRT", libc::SIGABRT)]
#[case::bus("BUS", libc::SIGBUS)]
#[case::fpe("FPE", libc::SIGFPE)]
#[case::usr1("USR1", libc::SIGUSR1)]
#[case::segv("SEGV", libc::SIGSEGV)]
#[case::pipe("PIPE", libc::SIGPIPE)]
#[case::term("TERM", libc::SIGTERM)]
fn idalib_leaves_signal_handler_untouched(#[case] name: &str, #[case] sig: c_int) {
    let Some(db) = common::TestDb::acquire() else {
        return;
    };
    let path = db.path().to_owned();
    // Baseline before any idalib code runs; handlers are process-global, so reading here
    // captures whatever the Rust runtime installed at startup.
    let before = disposition(sig);
    let after = Ida::run(move |ida| {
        ida.call(move |idb| {
            idb.open(&path).run_auto(true).call().expect("open");
            disposition(sig)
        })
        .unwrap_or_else(|e| e.resume())
    })
    .expect("kernel init failed");

    assert!(
        before == after,
        "idalib changed the {name}({sig}) handler: {before:#x} -> {after:#x}"
    );
}
