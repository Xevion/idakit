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
    let address = check_first_function_size(idb);
    check_function_flags_sample(idb);

    let segs: Vec<_> = idb.segments().collect();
    assert!(!segs.is_empty(), "the database has segments");

    let exec = check_exec_segment(&segs);
    check_entry_segment(idb, &segs, address);
    check_segments_non_overlapping(&segs);

    let (segment_checked, bitness_checked) = check_function_segment_sample(idb, &segs);
    let func_span_count = check_function_spans_non_overlapping(idb);
    println!(
        "cross-invariants OK: {} segments non-overlapping, {segment_checked} functions \
         single-segment, {bitness_checked} bitness pairs agree, {func_span_count} function \
         spans non-overlapping",
        segs.len(),
    );

    check_segment_type_codes(&segs);
    check_segment_flag_predicates(&segs);
    print_exec_segment_scalars(&exec);

    println!("attributes OK: function sizes/flags, segment perms/bitness/class verified");
}

/// The first function's `[address, end)` span is non-empty and `size()` agrees with it.
fn check_first_function_size(idb: &Database) -> Address {
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
    address
}

/// Flag predicates just have to resolve without panicking; report the tallies over a sample so
/// a human can sanity-check them.
fn check_function_flags_sample(idb: &Database) {
    let (mut libs, mut thunks, mut norets) = (0usize, 0usize, 0usize);
    for f in idb.functions().take(2000) {
        libs += usize::from(f.is_lib());
        thunks += usize::from(f.is_thunk());
        norets += usize::from(f.is_noreturn());
    }
    println!("function flags over <=2000: {libs} lib, {thunks} thunk, {norets} noreturn");
}

/// A real program has executable code; its segment is readable and 32/64-bit.
fn check_exec_segment<'db>(segs: &[Segment<'db>]) -> Segment<'db> {
    let exec = *segs
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
    exec
}

/// Cross-invariant: the entry function lives inside an executable segment, and `segment_at`
/// resolves its address back to that same segment.
fn check_entry_segment(idb: &Database, segs: &[Segment<'_>], address: Address) {
    let entry_seg = segs
        .iter()
        .find(|s| matches!((s.start(), s.end()), (Some(st), Some(en)) if st <= address && address < en))
        .expect("the entry function is inside a segment");
    assert!(
        entry_seg.is_executable(),
        "the entry function's segment {:?} should be executable",
        entry_seg.name()
    );

    let looked_up = idb
        .segment_at(address)
        .expect("segment_at resolves the entry function's address");
    assert!(
        looked_up.index() == entry_seg.index(),
        "segment_at should resolve to the entry segment"
    );
}

/// Segments never overlap: sorted by start, each one ends at or before the next begins.
fn check_segments_non_overlapping(segs: &[Segment<'_>]) {
    let mut seg_spans: Vec<(Address, Address)> = segs
        .iter()
        .filter_map(|s| Some((s.start()?, s.end()?)))
        .collect();
    seg_spans.sort_by_key(|&(start, _)| start);
    for pair in seg_spans.windows(2) {
        let (_, prev_end) = pair[0];
        let (next_start, _) = pair[1];
        assert!(
            prev_end <= next_start,
            "segments overlap: one ends at {prev_end:#x}, the next starts at {next_start:#x}"
        );
    }
}

/// Cross-invariant, over a sample rather than just the entry: every function lies inside exactly
/// one segment, `segment_at` agrees with the linear scan, and `Function::bitness` matches the
/// containing segment's (both derive from the same processor-mode state). Returns
/// `(segment_checked, bitness_checked)` counts for the caller's summary.
fn check_function_segment_sample(idb: &Database, segs: &[Segment<'_>]) -> (usize, usize) {
    let mut segment_checked = 0usize;
    let mut bitness_checked = 0usize;
    for f in idb.functions().take(2000) {
        let fea = f.address();
        let containing: Vec<_> = segs
            .iter()
            .filter(
                |s| matches!((s.start(), s.end()), (Some(st), Some(en)) if st <= fea && fea < en),
            )
            .collect();
        assert!(
            containing.len() == 1,
            "function {:#x} lies in {} segments, expected exactly one",
            fea.get(),
            containing.len()
        );
        let seg_here = idb
            .segment_at(fea)
            .expect("segment_at resolves a function's address");
        assert!(
            seg_here.index() == containing[0].index(),
            "segment_at disagrees with the linear scan for function {:#x}",
            fea.get()
        );
        segment_checked += 1;

        if let (Some(fb), Some(sb)) = (f.bitness(), containing[0].bitness()) {
            assert!(
                fb == sb,
                "function {:#x} bitness {fb:?} disagrees with its segment's bitness {sb:?}",
                fea.get()
            );
            bitness_checked += 1;
        }
    }
    assert!(
        segment_checked > 0,
        "no function sampled for segment containment"
    );
    assert!(
        bitness_checked > 0,
        "no function/segment bitness pair sampled"
    );
    (segment_checked, bitness_checked)
}

/// Function entry spans `[start, end)` never overlap across the whole database: two distinct
/// functions never claim the same bytes as their entry chunk. Returns the span count for the
/// caller's summary.
fn check_function_spans_non_overlapping(idb: &Database) -> usize {
    let mut func_spans: Vec<(Address, Address)> = idb
        .functions()
        .filter_map(|f| Some((f.address(), f.end()?)))
        .collect();
    func_spans.sort_by_key(|&(start, _)| start);
    for pair in func_spans.windows(2) {
        let (_, prev_end) = pair[0];
        let (next_start, _) = pair[1];
        assert!(
            prev_end <= next_start,
            "function entry chunks overlap: one ends at {prev_end:#x}, the next starts at {next_start:#x}"
        );
    }
    func_spans.len()
}

/// A segment's `type`/`align`/`comb` codes are loader-dependent, so no single segment is
/// guaranteed to report one; a real database is expected to have at least one that does.
fn check_segment_type_codes(segs: &[Segment<'_>]) {
    assert!(
        segs.iter().any(|s| s.kind().is_some()),
        "at least one segment should report a recognized type code"
    );
    assert!(
        segs.iter().any(|s| s.alignment().is_some()),
        "at least one segment should report a recognized alignment code"
    );
    assert!(
        segs.iter().any(|s| s.combination().is_some()),
        "at least one segment should report a recognized combination code"
    );
}

/// Every `is_*` predicate is exactly its corresponding bit in `flags()`.
fn check_segment_flag_predicates(segs: &[Segment<'_>]) {
    for seg in segs {
        let flags = seg.flags();
        assert!(seg.is_visible() != flags.contains(SegmentFlags::HIDDEN));
        assert!(seg.is_debugger() == flags.contains(SegmentFlags::DEBUG));
        assert!(seg.is_loader() == flags.contains(SegmentFlags::LOADER));
        assert!(seg.is_type_hidden() == flags.contains(SegmentFlags::HIDETYPE));
        assert!(seg.is_header() == flags.contains(SegmentFlags::HEADER));
    }
}

/// Best-effort: exercise the remaining scalar accessors on the executable segment found earlier.
fn print_exec_segment_scalars(exec: &Segment<'_>) {
    let _ = exec.comment(false);
    let _ = exec.comment(true);
    println!(
        "exec segment scalars: sel={:#x} type={:?} color={:?} align={:?} comb={:?} \
         visible={} debugger={} loader={} type_hidden={} header={}",
        exec.selector(),
        exec.kind(),
        exec.color(),
        exec.alignment(),
        exec.combination(),
        exec.is_visible(),
        exec.is_debugger(),
        exec.is_loader(),
        exec.is_type_hidden(),
        exec.is_header(),
    );
}
