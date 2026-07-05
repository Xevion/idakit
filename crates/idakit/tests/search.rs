//! Binary pattern search against a real database: exact bytes, wildcards, range bounds,
//! and parse rejection.
//!
//! A normal `#[test]` on the kernel thread `Ida::run` spawns; the nextest `serial-kernel`
//! group serializes it. Skips when no test database is present (see [`common::TestDb`]).

mod common;

use idakit::{Ea, Offset, Pattern};

#[test]
fn search() {
    let Some(db) = common::TestDb::acquire() else {
        eprintln!("skipping: no test database (set IDAKIT_TEST_DB or install IDA at $IDADIR)");
        return;
    };
    let path = db.path().to_owned();
    idakit::Ida::run(move |ida| {
        ida.call(move |idb| run(idb, &path))
            .unwrap_or_else(|e| e.resume())
    })
    .expect("kernel init failed");
}

fn run(idb: &mut idakit::Idb, db: &str) {
    idb.open(db).call().expect("open failed");

    let first = idb.functions().next().expect("a function");
    let ea = first.ea();

    // A pattern built from real bytes at the entry is guaranteed to occur at `ea`; the
    // whole-image search must list it among the hits.
    let bytes = idb.bytes(ea, 16);
    assert!(
        bytes.len() >= 8,
        "need at least 8 readable bytes at the entry"
    );
    let exact: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();

    let pat = Pattern::compile(idb, exact.join(" "))
        .call()
        .expect("exact pattern compiles");
    let hits: Vec<Ea> = idb.search(&pat).collect();
    assert!(
        hits.contains(&ea),
        "exact pattern should match its own entry {ea:#x}"
    );

    // Wildcarding a byte can only widen the match set, and must still hit `ea`.
    let mut wild = exact.clone();
    wild[1] = "?".to_owned();
    let wpat = Pattern::compile(idb, wild.join(" "))
        .call()
        .expect("wildcard pattern compiles");
    let whits: Vec<Ea> = idb.search(&wpat).collect();
    assert!(
        whits.contains(&ea),
        "wildcard pattern should still match {ea:#x}"
    );
    assert!(
        whits.len() >= hits.len(),
        "wildcard matches a superset of the exact hits"
    );

    // A range that starts just past `ea` must not report `ea` itself.
    let bounds = idb
        .address_range()
        .expect("open database has an address range");
    let after: Vec<Ea> = idb
        .search_in((ea + Offset::new(1))..bounds.end, &pat)
        .collect();
    assert!(
        !after.contains(&ea),
        "range starting after {ea:#x} should exclude it"
    );

    // An unparseable pattern is a recoverable error, never a panic across the FFI boundary.
    // Inlined so the borrowing `Result` drops at the statement, not at scope end.
    assert!(
        Pattern::compile(idb, "").call().is_err(),
        "empty pattern should error, not panic"
    );

    // Patterns hold an immutable borrow of `idb`; release them before the &mut close.
    drop(pat);
    drop(wpat);
    idb.close(false);
    println!(
        "search OK: {} exact hits, {} wildcard hits at entry {ea:#x}",
        hits.len(),
        whits.len()
    );
}
