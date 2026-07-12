//! Hex-Rays decompilation-cache invalidation against a real database.
//!
//! Mirrors the `roundtrip` test's harness: an ordinary `#[test]` that brings the kernel
//! up on the thread `Ida::run` spawns and does its work through `ida.call`, closing `save = false`
//! so the fixture never changes on disk. Each test gates on its preconditions (a decompilable
//! function, a caller/callee pair) and skips cleanly when the corpus can't supply them.

mod common;

use assert2::{assert, check};
use idakit::prelude::*;

#[test]
fn invalidate_roundtrip() {
    common::with_canonical_db(invalidate_roundtrip_body);
}

fn invalidate_roundtrip_body(idb: &mut idakit::Database) {
    let Some(entry) = first_decompilable(idb) else {
        println!("skipping: no decompilable function in the corpus fixture");
        return;
    };
    let ea = entry.get();

    idb.decompile(entry)
        .expect("decompile the located function");
    assert!(
        idb.is_decompilation_cached(entry),
        "decompiling should cache the function"
    );
    assert!(
        idb.invalidate_decompilation(entry),
        "invalidating a cached function reports the eviction"
    );
    assert!(
        !idb.is_decompilation_cached(entry),
        "invalidation should evict the cache entry"
    );

    // Re-cache, then the broad clear also empties it.
    idb.decompile(entry).expect("re-decompile the function");
    assert!(idb.is_decompilation_cached(entry));
    idb.clear_decompilation_cache();
    assert!(
        !idb.is_decompilation_cached(entry),
        "clear_decompilation_cache empties the cache"
    );
    println!("invalidate roundtrip OK at {ea:#x}");
}

#[test]
fn set_type_auto_invalidates_callers() {
    common::with_canonical_db(set_type_auto_invalidates_callers_body);
}

fn set_type_auto_invalidates_callers_body(idb: &mut idakit::Database) {
    // A parseable prototype that applies on any target; a callee that rejects it is skipped.
    let proto = "__int64 f(__int64 a)";
    let entries: Vec<Address> = idb.functions().map(|f| f.address()).collect();

    for &callee in &entries {
        // Every code-xref source targeting this callee's entry, snapshotted before the &mut below.
        let sources: Vec<Address> = idb
            .xrefs_to(callee)
            .filter(|x| x.is_code())
            .map(|x| x.from)
            .collect();

        for src in sources {
            // Normalize the call site to its containing function's entry (the caller).
            let Some(caller) = idb.function_at(src).map(|f| f.address()) else {
                continue;
            };
            if caller == callee {
                continue;
            }
            if idb.decompile(caller).is_err() || idb.decompile(callee).is_err() {
                continue;
            }

            // Auto-invalidation ON: a prototype change on the callee must evict the caller too,
            // since the caller's cached pseudocode renders the callee's call site.
            assert!(idb.is_decompilation_cached(caller));
            assert!(idb.is_decompilation_cached(callee));
            if idb
                .function_mut(callee)
                .expect("callee is a function")
                .set_type(proto)
                .is_err()
            {
                continue; // this callee won't take the prototype; try another pair
            }
            check!(
                !idb.is_decompilation_cached(caller),
                "auto-invalidation should evict the caller's cached decompilation"
            );
            check!(
                !idb.is_decompilation_cached(callee),
                "the prototype write should evict the callee's own cached decompilation"
            );

            // Opt-out: re-cache the caller, then a set_type with auto_invalidate(false) leaves it.
            idb.decompile(caller).expect("re-decompile the caller");
            assert!(idb.is_decompilation_cached(caller));
            idb.function_mut(callee)
                .expect("callee is a function")
                .auto_invalidate(false)
                .set_type(proto)
                .expect("set_type with auto-invalidation off");
            check!(
                idb.is_decompilation_cached(caller),
                "auto_invalidate(false) should leave the caller's cache intact"
            );

            println!(
                "set_type auto-invalidation OK: callee {:#x} evicts caller {:#x}, opt-out preserves it",
                callee.get(),
                caller.get()
            );
            return;
        }
    }

    println!("skipping: no decompilable caller/callee pair found in the corpus fixture");
}

#[test]
fn set_type_auto_invalidates_pointer_referrers() {
    common::with_canonical_db(set_type_auto_invalidates_pointer_referrers_body);
}

fn set_type_auto_invalidates_pointer_referrers_body(idb: &mut idakit::Database) {
    let proto = "__int64 f(__int64 a)";
    let entries: Vec<Address> = idb.functions().map(|f| f.address()).collect();

    for &target in &entries {
        // A non-code reference to the target: its address taken into a pointer or vtable, not a
        // call. The referrer's pseudocode still prints the target's name, so retyping the target
        // must evict the referrer even though no call/jump xref connects them.
        let sources: Vec<Address> = idb
            .xrefs_to(target)
            .filter(|x| !x.is_code())
            .map(|x| x.from)
            .collect();

        for src in sources {
            let Some(referrer) = idb.function_mut(src).map(|c| c.address()) else {
                continue;
            };
            if referrer == target {
                continue;
            }
            if idb.decompile(referrer).is_err() || idb.decompile(target).is_err() {
                continue;
            }

            assert!(idb.is_decompilation_cached(referrer));
            if idb
                .function_mut(target)
                .expect("target is a function")
                .set_type(proto)
                .is_err()
            {
                continue; // this target won't take the prototype; try another pair
            }
            check!(
                !idb.is_decompilation_cached(referrer),
                "a data-reference (function-pointer) referrer must be evicted too"
            );
            println!(
                "pointer-referrer invalidation OK: target {:#x} evicts referrer {:#x}",
                target.get(),
                referrer.get()
            );
            return;
        }
    }

    println!("skipping: no function-pointer referrer pair found in the corpus fixture");
}

/// The first function (scanning a bounded prefix) that Hex-Rays decompiles, or `None` if none do.
fn first_decompilable(idb: &idakit::Database) -> Option<Address> {
    idb.functions()
        .take(2000)
        .map(|f| f.address())
        .find(|&ea| idb.decompile(ea).is_ok())
}
