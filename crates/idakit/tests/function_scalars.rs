//! Function-level scalar accessors against a real database: `total_size`, `comment`,
//! `does_return`, and `bitness`. Read-only; opens `save = false`. Skips when no test database is
//! present.

mod common;

use assert2::assert;
use idakit::prelude::*;

#[test]
fn function_scalar_accessors_hold_across_the_corpus() {
    common::with_canonical_db(run);
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
