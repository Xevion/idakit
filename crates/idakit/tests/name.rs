//! Name lookups against a real database: [`Database::visible_name`]/[`Database::short_name`]/
//! [`Database::long_name`] resolve wherever [`Database::name`] does, and the list holds at least
//! one public name. Read-only; opens `save = false`. Skips when no test database is present.

mod common;

use assert2::assert;
use idakit::prelude::*;

#[test]
fn name_flags_and_linkage() {
    common::with_canonical_db(run);
}

fn run(idb: &mut Database) {
    let mut checked = 0usize;
    let mut named = 0usize;
    let mut public = 0usize;
    let mut weak = 0usize;

    let mut prev = None;

    // The whole list, not a leading window: a stripped library sorts its import thunks and local
    // symbols below its exported ones, so any fixed sample of the front can hold no public name
    // at all (libstdc++'s first is entry 6262 of 14479).
    for entry in idb.names() {
        checked += 1;

        // The list is address-ascending; a cursor that fails to advance repeats an address here
        // rather than running the loop forever.
        assert!(
            prev.is_none_or(|p| p < entry.address),
            "name list is not strictly increasing at {:#x}",
            entry.address.get()
        );
        prev = Some(entry.address);

        // GN_VISIBLE substitutes forbidden characters, so `name_with`/`name` need not agree
        // exactly; the real invariant is that a named address resolves under both, and that
        // short_name/long_name resolve wherever visible_name does.
        if idb.name(entry.address).is_some() {
            named += 1;
            assert!(
                idb.visible_name(entry.address).is_some(),
                "visible_name found nothing at {:#x}, but name() did",
                entry.address.get()
            );
            assert!(
                idb.short_name(entry.address).is_some(),
                "short_name found nothing at {:#x}, but visible_name did",
                entry.address.get()
            );
            assert!(
                idb.long_name(entry.address).is_some(),
                "long_name found nothing at {:#x}, but visible_name did",
                entry.address.get()
            );
        }

        public += usize::from(idb.is_public_name(entry.address));
        weak += usize::from(idb.is_weak_name(entry.address));
    }

    assert!(checked > 0, "expected at least one named address");
    assert!(named > 0, "no listed address resolved a name");
    assert!(public > 0, "expected at least one public name in the list");

    println!("name flags OK: {checked} names checked, {named} named, {public} public, {weak} weak");
}
