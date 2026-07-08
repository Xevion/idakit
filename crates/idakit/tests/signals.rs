//! idalib does not hijack process signal handlers on idakit's path. RE shows the crash-handler
//! installer (`sub_2296C60`: SEGV/ILL/FPE/BUS/ABRT/INT/TERM + altstack) is reached only through
//! crash-cleanup temp-file registration, which none of idakit's operations trigger. Verified
//! across init, open, analyze, and DB creation, batch on and off. This asserts that invariant:
//! every tracked signal's handler is identical before idakit runs and after open+analyze, so a
//! future idalib that starts stealing signals fails here instead of silently taking them.

// The whole invariant is POSIX sigaction dispositions, which have no Windows analogue.
#![cfg(unix)]

use std::ffi::c_int;

use assert2::assert;
use idakit::kernel::Ida;

mod common;

const SIGS: &[(&str, c_int)] = &[
    ("INT", libc::SIGINT),
    ("ILL", libc::SIGILL),
    ("ABRT", libc::SIGABRT),
    ("BUS", libc::SIGBUS),
    ("FPE", libc::SIGFPE),
    ("USR1", libc::SIGUSR1),
    ("SEGV", libc::SIGSEGV),
    ("PIPE", libc::SIGPIPE),
    ("TERM", libc::SIGTERM),
];

// Current disposition for `n` as an opaque handle value (SIG_DFL=0, SIG_IGN=1). libc collapses
// the sa_handler/sa_sigaction union into one field, so this is the value regardless of SA_SIGINFO.
fn probe() -> Vec<usize> {
    SIGS.iter()
        .map(|&(_, n)| {
            // SAFETY: a null `act` makes this read-only; sigaction fills `oldact` from the
            // process-global disposition and writes nothing back. Zeroed sigaction is valid.
            let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::sigaction(n, std::ptr::null(), &mut sa) };
            if rc == 0 { sa.sa_sigaction } else { 0 }
        })
        .collect()
}

#[test]
fn idalib_leaves_signal_handlers_untouched() {
    let Some(db) = common::TestDb::acquire() else {
        return;
    };
    let path = db.path().to_owned();
    // Baseline before any idalib code runs; handlers are process-global, so reading here
    // captures whatever the Rust runtime installed at startup.
    let before = probe();
    let after = Ida::run(move |ida| {
        ida.call(move |idb| {
            idb.open(&path).run_auto(true).call().expect("open");
            probe()
        })
        .unwrap_or_else(|e| e.resume())
    })
    .expect("kernel init failed");

    for (i, (name, num)) in SIGS.iter().enumerate() {
        assert!(
            before[i] == after[i],
            "idalib changed the {name}({num}) handler: {:#x} -> {:#x}",
            before[i],
            after[i]
        );
    }
}
