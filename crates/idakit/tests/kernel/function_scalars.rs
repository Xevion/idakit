//! Function-level scalar accessors against a real database: `total_size`, `comment`,
//! `does_return`, `bitness`, and the [`FunctionEntry`] read. Read-only; opens `save = false`.
//! Skips when no test database is present.

use assert2::assert;
use idakit::prelude::*;
use idakit_runner_macros::kernel_test;

#[kernel_test(read_only)]
fn function_scalar_accessors_hold_across_the_corpus() {
    crate::common::with_canonical_db(run);
}

// total_size must never undercount the entry chunk alone; bitness must resolve for every real
// function (the regression guard for the bitness facade bug); does_return/comment are exercised
// end to end, cross-checked against is_noreturn and comment(true) where possible.
fn run(idb: &mut Database) {
    let mut checked = 0usize;
    let mut commented = 0usize;
    for f in idb.functions() {
        assert!(
            f.total_size() >= f.size(),
            "function {:#x}: total_size {} < entry size {}",
            f.address().get(),
            f.total_size(),
            f.size()
        );

        let bitness = f.bitness();
        assert!(
            matches!(
                bitness,
                Some(Bitness::Bits16 | Bitness::Bits32 | Bitness::Bits64)
            ),
            "function {:#x}: expected a recognized bitness, got {bitness:?}",
            f.address().get()
        );

        if !f.is_noreturn() {
            assert!(
                f.does_return(),
                "function {:#x}: not flagged noreturn but does_return() is false",
                f.address().get()
            );
        }

        if let Some(text) = f.comment(false) {
            assert!(!text.is_empty(), "a Some comment should be non-empty");
            commented += 1;
        }
        let _ = f.comment(true);

        checked += 1;
    }
    assert!(checked > 0, "expected at least one function");

    println!("function scalar accessors OK: {checked} funcs checked, {commented} commented");
}

#[kernel_test(read_only)]
fn entry_info_agrees_with_the_per_field_accessors() {
    crate::common::with_canonical_db(run_entry);
}

// The entry read and the one-field-at-a-time accessors are independent paths to the same kernel
// facts, so they must agree. The string gating is checked in both directions: an unrequested field
// stays None even where the function does have that text, which is the half a fixed GFI_ALL would
// silently pass.
fn run_entry(idb: &mut Database) {
    let mut checked = 0usize;
    let mut named = 0usize;
    let mut framed = 0usize;
    for f in idb.functions() {
        let address = f.address().get();
        let bare = f.entry().unwrap_or_else(|e| panic!("{address:#x}: {e}"));

        assert!(bare.address == f.address(), "{address:#x}: entry address");
        assert!(bare.end == f.end().unwrap(), "{address:#x}: entry end");
        assert!(
            bare.flags.contains(FuncFlags::NORET) == f.is_noreturn(),
            "{address:#x}: NORET disagrees with is_noreturn()"
        );
        assert!(
            bare.flags.contains(FuncFlags::THUNK) == f.is_thunk(),
            "{address:#x}: THUNK disagrees with is_thunk()"
        );
        assert!(
            bare.name.is_none() && bare.comment.is_none() && bare.repeatable_comment.is_none(),
            "{address:#x}: unrequested strings should be absent, got {bare:?}"
        );

        let full = f
            .entry_with()
            .name(true)
            .comments(true)
            .call()
            .unwrap_or_else(|e| panic!("{address:#x}: {e}"));
        assert!(
            full.name.as_deref() == Some(f.name().as_str()),
            "{address:#x}: entry name disagrees with name()"
        );
        assert!(
            full.comment == f.comment(false),
            "{address:#x}: entry comment disagrees with comment(false)"
        );
        assert!(
            full.repeatable_comment == f.comment(true),
            "{address:#x}: entry repeatable comment disagrees with comment(true)"
        );
        named += usize::from(full.name.is_some());

        // The frame's parts are components of the total the stack surface reports.
        if let Ok(Some(frame)) = f.frame() {
            assert!(
                bare.locals_size + u64::from(bare.saved_regs_size) <= frame.size(),
                "{address:#x}: locals {} + saved regs {} exceed frame size {}",
                bare.locals_size,
                bare.saved_regs_size,
                frame.size()
            );
            framed += 1;
        }
        checked += 1;
    }
    assert!(checked > 0, "expected at least one function");

    println!("entry info OK: {checked} funcs, {named} named, {framed} with a frame");
}
