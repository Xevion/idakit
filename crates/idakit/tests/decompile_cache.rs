//! Hex-Rays decompilation-cache invalidation against a real database.
//!
//! Mirrors the `roundtrip` test's harness: an ordinary `#[test]` that brings the kernel
//! up on the thread `Ida::run` spawns and does its work through `ida.call`, closing `save = false`
//! so the fixture never changes on disk. Each test gates on its preconditions (a decompilable
//! function, a caller/callee pair) and skips cleanly when the corpus can't supply them.

mod common;

use std::collections::HashSet;

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

#[test]
fn at_mut_rename_invalidates_referrers() {
    common::with_canonical_db(at_mut_rename_invalidates_referrers_body);
}

/// The raw address cursor drives dependent invalidation, not just `function_mut`: a rename through
/// `at_mut` evicts every function that renders the address. A function entry is the convenient
/// referenced address here; a data symbol travels the identical dependents path.
fn at_mut_rename_invalidates_referrers_body(idb: &mut idakit::Database) {
    let entries: Vec<Address> = idb.functions().map(|f| f.address()).collect();

    for &target in &entries {
        let sources: Vec<Address> = idb.xrefs_to(target).map(|x| x.from).collect();

        for src in sources {
            let Some(referrer) = idb.function_at(src).map(|f| f.address()) else {
                continue;
            };
            if referrer == target || idb.decompile(referrer).is_err() {
                continue;
            }
            assert!(idb.is_decompilation_cached(referrer));

            // Rename through the raw LocationMut cursor; its Drop coalesces the eviction.
            idb.at_mut(target)
                .rename("idakit_atmut_probe")
                .expect("rename through at_mut");
            check!(
                !idb.is_decompilation_cached(referrer),
                "a rename through at_mut must evict every function that renders the address"
            );

            // Opt-out: re-cache, rename again with invalidation off, the referrer stays cached.
            idb.decompile(referrer).expect("re-decompile the referrer");
            assert!(idb.is_decompilation_cached(referrer));
            idb.at_mut(target)
                .auto_invalidate(false)
                .rename("idakit_atmut_probe2")
                .expect("rename with auto-invalidation off");
            check!(
                idb.is_decompilation_cached(referrer),
                "auto_invalidate(false) on at_mut must leave the referrer's cache intact"
            );

            println!(
                "at_mut rename invalidation OK: target {:#x} evicts referrer {:#x}, opt-out preserves it",
                target.get(),
                referrer.get()
            );
            return;
        }
    }

    println!("skipping: no decompilable referrer found in the corpus fixture");
}

#[test]
fn refresh_text_reflects_rename() {
    common::with_canonical_db(refresh_text_reflects_rename_body);
}

/// A held [`DecompiledFunction`] re-prints a callee rename through `refresh_text` with no
/// re-decompile: the cached ctext is stale, but re-walking the ctree resolves the new name.
fn refresh_text_reflects_rename_body(idb: &mut idakit::Database) {
    let entries: Vec<Address> = idb.functions().map(|f| f.address()).collect();

    for &callee in &entries {
        let sources: Vec<Address> = idb
            .xrefs_to(callee)
            .filter(|x| x.is_code())
            .map(|x| x.from)
            .collect();

        for src in sources {
            let Some(caller) = idb.function_at(src).map(|f| f.address()) else {
                continue;
            };
            if caller == callee {
                continue;
            }

            // The caller's pseudocode must actually name the callee for the refresh to prove
            // anything, so establish the baseline before mutating.
            let old_name = String::from(
                idb.function_at(callee)
                    .expect("callee is a function")
                    .name(),
            );
            let baseline = {
                let Ok(cf) = idb.decompile(caller) else {
                    continue;
                };
                cf.pseudocode()
            };
            let Some(baseline) = baseline else { continue };
            if old_name.is_empty() || !baseline.contains(&old_name) {
                continue; // this caller does not render the callee's name; try another pair
            }

            // Rename the callee, opting out so the caller's cache survives.
            idb.at_mut(callee)
                .auto_invalidate(false)
                .rename("idakit_refreshed_callee")
                .expect("rename the callee");
            assert!(
                idb.is_decompilation_cached(caller),
                "auto_invalidate(false) should leave the caller cached"
            );

            // The cached ctext still shows the old name; refresh re-prints from the ctree.
            let cf = idb.decompile(caller).expect("re-decompile hits the cache");
            let refreshed = cf
                .refresh_text()
                .expect("refresh_text renders the pseudocode");
            check!(
                refreshed.contains("idakit_refreshed_callee"),
                "refresh_text should reflect the callee's new name"
            );
            check!(
                refreshed != baseline,
                "refresh_text should change the rendered pseudocode"
            );

            println!(
                "refresh_text OK: caller {:#x} re-prints callee {:#x} rename without re-decompile",
                caller.get(),
                callee.get()
            );
            return;
        }
    }

    println!("skipping: no caller naming a decompilable callee in the corpus fixture");
}

#[test]
fn data_symbol_rename_invalidates_readers() {
    common::with_canonical_db(data_symbol_rename_invalidates_readers_body);
}

/// Renaming a genuine data symbol (a named address that is not a function entry) through `at_mut`
/// evicts every function that reads it, exercising the `LocationMut` consumer on a data address.
fn data_symbol_rename_invalidates_readers_body(idb: &mut idakit::Database) {
    let functions: HashSet<Address> = idb.functions().map(|f| f.address()).collect();
    let symbols: Vec<Address> = idb
        .names()
        .map(|n| n.address)
        .filter(|a| !functions.contains(a))
        .collect();

    'symbols: for symbol in symbols {
        let sources: Vec<Address> = idb.xrefs_to(symbol).map(|x| x.from).collect();

        for src in sources {
            let Some(reader) = idb.function_at(src).map(|f| f.address()) else {
                continue;
            };
            if idb.decompile(reader).is_err() {
                continue;
            }
            assert!(idb.is_decompilation_cached(reader));

            if idb.at_mut(symbol).rename("idakit_data_probe").is_err() {
                continue 'symbols; // this symbol will not take a rename; try another
            }
            check!(
                !idb.is_decompilation_cached(reader),
                "renaming a data symbol must evict every function that reads it"
            );
            println!(
                "data-symbol rename invalidation OK: symbol {:#x} evicts reader {:#x}",
                symbol.get(),
                reader.get()
            );
            return;
        }
    }

    println!("skipping: no data symbol with a decompilable reader in the corpus fixture");
}

#[test]
fn patch_self_evicts_containing_function() {
    common::with_canonical_db(patch_self_evicts_containing_function_body);
}

/// A byte patch self-evicts the containing function's cached decompilation through the kernel's
/// byte-patched hook, so `patch` queues no invalidation of its own. Guards that ground truth.
fn patch_self_evicts_containing_function_body(idb: &mut idakit::Database) {
    let Some(entry) = first_decompilable(idb) else {
        println!("skipping: no decompilable function in the corpus fixture");
        return;
    };

    idb.decompile(entry)
        .expect("decompile the located function");
    assert!(idb.is_decompilation_cached(entry));

    // Flip one byte at the entry so the patch record changes the image and fires the hook.
    let original = idb.at(entry).bytes(1);
    assert!(original.len() == 1, "need a readable byte at the entry");
    idb.at_mut(entry)
        .patch(&[!original[0]])
        .expect("patch one byte");
    check!(
        !idb.is_decompilation_cached(entry),
        "a byte patch must self-evict the containing function's cached decompilation"
    );

    // Restore the byte; the database closes save = false regardless.
    idb.at_mut(entry)
        .patch(&original)
        .expect("restore the byte");
    println!("patch self-eviction OK at {:#x}", entry.get());
}

/// The first function (scanning a bounded prefix) that Hex-Rays decompiles, or `None` if none do.
fn first_decompilable(idb: &idakit::Database) -> Option<Address> {
    idb.functions()
        .take(2000)
        .map(|f| f.address())
        .find(|&ea| idb.decompile(ea).is_ok())
}
