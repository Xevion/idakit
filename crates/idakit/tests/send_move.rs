//! `Database` is `Send`: move one open database across freshly-spawned threads and prove the full
//! kernel API follows it.
//!
//! Brings the kernel up on a host thread, then hands the open database to a fresh thread (which
//! then exits), reclaims it, and hands it to another. Each hop decompiles the same function fresh
//! (the cache is cleared first, so a move that silently broke the kernel diverges here instead of
//! replaying a stale ctree). Identical output on every thread proves the runtime `g_main` re-steal
//! carries the whole API across a single-owner move, including the case the earlier probe left
//! open: the previous owner thread has *died*, not merely parked.
//!
//! `here()` inits the kernel on the calling thread, so the whole scenario runs on an 8 MiB thread
//! (nextest's test thread is too small). Skips when no corpus is configured.

mod common;

use std::thread;

use assert2::assert;
use idakit::prelude::*;

use common::TestDb;

/// idalib's native stack; library init alone overflows a smaller one.
const STACK: usize = 8 << 20;

/// A reading of the open kernel that must not change as the database moves between threads.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Fingerprint {
    funcs: usize,
    entry: u64,
    name: String,
    pseudocode: String,
}

/// Read the fingerprint, forcing a FRESH decompile: the cache is cleared first, so the pseudocode
/// is recomputed on the current thread rather than replayed from a prior owner's cached ctree.
fn fingerprint(db: &mut Database) -> Fingerprint {
    db.clear_decompilation_cache();
    let funcs = db.functions().count();
    let first = db.functions().next().expect("at least one function");
    let entry = first.address();
    let name = first.name().as_str().to_owned();
    let pseudocode = db
        .decompile(entry)
        .expect("decompile the first function")
        .pseudocode()
        .expect("pseudocode for the first function");
    Fingerprint {
        funcs,
        entry: entry.get(),
        name,
        pseudocode,
    }
}

/// Decompile the target repeatedly until two consecutive fresh reads agree, returning the settled
/// reading. Isolates the thread move from the decompiler's one-time type-inference warm-up.
fn settle(db: &mut Database) -> Fingerprint {
    let mut prev = fingerprint(db);
    for _ in 0..8 {
        let next = fingerprint(db);
        if next == prev {
            return next;
        }
        prev = next;
    }
    panic!("decompiler output never settled across 8 fresh reads");
}

/// Move `db` into a fresh thread, fingerprint it there, and hand it back; the thread then exits, so
/// the next owner reclaims a database whose previous owner is dead. That the database moves in and
/// back out is exactly what a `Send` bound compiles.
fn hop(db: Database) -> (Database, Fingerprint) {
    thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || {
            let mut db = db;
            let fp = fingerprint(&mut db);
            (db, fp)
        })
        .expect("spawn hop thread")
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e))
}

#[test]
fn database_send_survives_thread_moves() {
    let Some(db) = TestDb::acquire() else {
        println!("skipping: no corpus configured");
        return;
    };
    thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || run(&db))
        .expect("spawn host thread")
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e));
}

fn run(db: &TestDb) {
    let mut idb = Ida::new().here().expect("kernel init failed");
    idb.open(db.path()).call().expect("open failed");

    // Early decompiles of a function can refine database-level type inference (a weak symbol's
    // type settling), and that refinement persists past a cfunc-cache clear, so the first fresh
    // reads differ until the types converge. Settle on the host first, so the baseline and each
    // hop compare stable output and the thread move stays the only variable.
    let baseline = settle(&mut idb);

    // Host holds the baseline, then the database hops to B (which dies), back to the host, then C.
    let (mut idb, on_b) = hop(idb);
    let on_host_again = fingerprint(&mut idb);
    let (mut idb, on_c) = hop(idb);

    assert!(
        !baseline.pseudocode.is_empty(),
        "expected non-empty pseudocode"
    );
    assert!(
        baseline == on_b,
        "fingerprint diverged after moving to thread B"
    );
    assert!(
        baseline == on_host_again,
        "fingerprint diverged after B died and the host reclaimed the database"
    );
    assert!(
        baseline == on_c,
        "fingerprint diverged after moving to thread C"
    );

    idb.close(false);
    println!(
        "Database Send move-chain OK: {} funcs, entry {:#x}, fresh decompile stable across 3 threads",
        baseline.funcs, baseline.entry
    );
}
