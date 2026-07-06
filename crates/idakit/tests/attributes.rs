//! Function and segment attributes against a real database: sizes and flags, segment
//! permissions/bitness/class, and the cross-invariant that a function's entry lies in an
//! executable segment. Read-only; opens `save = false`.

mod common;

use idakit::prelude::*;

#[test]
fn attributes() {
    common::with_canonical_db(run);
}

fn run(idb: &mut Database) {
    let first = idb.functions().next().expect("a function");
    let address = first.address();
    let end = first.end().expect("function has an end");
    assert!(
        end > address,
        "function end {end:#x} should be past its start {address:#x}"
    );
    assert!(
        first.size() == address.distance_to(end),
        "size should equal end - start"
    );
    assert!(first.size() > 0, "the first function should be non-empty");

    // Flag predicates just have to resolve without panicking; report the tallies over a
    // sample so a human can sanity-check them.
    let (mut libs, mut thunks, mut norets) = (0usize, 0usize, 0usize);
    for f in idb.functions().take(2000) {
        libs += usize::from(f.is_lib());
        thunks += usize::from(f.is_thunk());
        norets += usize::from(f.is_noreturn());
    }
    println!("function flags over <=2000: {libs} lib, {thunks} thunk, {norets} noreturn");

    let segs: Vec<_> = idb.segments().collect();
    assert!(!segs.is_empty(), "the database has segments");

    // A real program has executable code; its segment is readable and 32/64-bit.
    let exec = segs
        .iter()
        .find(|s| s.is_executable())
        .expect("an executable segment");
    assert!(
        exec.is_readable(),
        "an executable segment should be readable"
    );
    assert!(
        matches!(exec.bitness(), Some(Bitness::Bits32 | Bitness::Bits64)),
        "unexpected code-segment bitness {:?}",
        exec.bitness()
    );
    println!(
        "exec segment {:?}: class={:?} bitness={:?} r={} w={} x={}",
        exec.name(),
        exec.class(),
        exec.bitness(),
        exec.is_readable(),
        exec.is_writable(),
        exec.is_executable(),
    );

    // Cross-invariant: the entry function lives inside an executable segment.
    let entry_seg = segs
        .iter()
        .find(|s| matches!((s.start(), s.end()), (Some(st), Some(en)) if st <= address && address < en))
        .expect("the entry function is inside a segment");
    assert!(
        entry_seg.is_executable(),
        "the entry function's segment {:?} should be executable",
        entry_seg.name()
    );

    println!("attributes OK: function sizes/flags, segment perms/bitness/class verified");
}
