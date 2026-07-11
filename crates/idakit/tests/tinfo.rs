//! Live `tinfo_t` handles built through [`TypeInfo`] against a real database: leaf and composite
//! construction, named/parsed resolution, the error paths (`NoType`, `ParseFailed`,
//! `ApplyRejected`), `&self` handle reuse, and apply through both write cursors. Verified by
//! `is_ok` parity against the [`TypeExpr`] twin, since a code entry may or may not accept a data
//! type and both build surfaces bottom out in the same kernel apply. Closes with `save = false`,
//! so the `.i64` on disk is never touched.

mod common;

use assert2::assert;
use idakit::prelude::*;

#[test]
fn tinfo() {
    common::with_canonical_db(run);
}

fn run(idb: &mut idakit::Database) {
    let entry = idb.functions().next().expect("a function").address();

    leaf_handles_apply(idb, entry);
    composite_handles_apply(idb, entry);
    named_ref_resolves_and_applies(idb, entry);
    named_ref_missing_is_no_type(idb);
    parse_type_roundtrips(idb, entry);
    parse_type_rejects_garbage(idb);
    parse_type_resolves_local_til(idb);
    handle_reuse(idb, entry);
    apply_unresolved_pointer_is_rejected(idb, entry);
    apply_through_both_cursors(idb, entry);

    println!(
        "tinfo OK: leaf apply, composite apply, named ref, missing ref, parse roundtrip, parse \
         reject, local-til parse, handle reuse, unresolved-pointer reject, both cursors"
    );
}

/// Every leaf width builds a live handle, and applying the int32 handle agrees with the
/// [`TypeExpr`] int32 recipe at the same address.
fn leaf_handles_apply(idb: &mut idakit::Database, entry: Address) {
    use idakit::types::expr;

    // Construct the whole leaf surface: void, bool, every int width, and both floats.
    let _ = idb.type_void();
    let _ = idb.type_bool();
    for bytes in [1u32, 2, 4, 8, 16] {
        let _ = idb.type_int(bytes, true);
        let _ = idb.type_int(bytes, false);
    }
    let _ = idb.type_float(4);
    let _ = idb.type_float(8);

    let handle = idb.type_int(4, true);
    let built = idb.at_mut(entry).apply_type(&handle);
    let recipe = idb.at_mut(entry).set_type(expr::int32());
    assert!(
        built.is_ok() == recipe.is_ok(),
        "the int32 handle should agree with its recipe twin: built={built:?} recipe={recipe:?}"
    );
}

/// Each composite (pointer, array, const, volatile) over int32 applies in parity with its
/// [`TypeExpr`] twin.
fn composite_handles_apply(idb: &mut idakit::Database, entry: Address) {
    use idakit::types::expr;

    fn parity(idb: &mut idakit::Database, entry: Address, built: &TypeInfo, recipe: TypeExpr) {
        let b = idb.at_mut(entry).apply_type(built);
        let r = idb.at_mut(entry).set_type(recipe);
        assert!(
            b.is_ok() == r.is_ok(),
            "a composite handle should agree with its recipe twin: built={b:?} recipe={r:?}"
        );
    }

    let base = idb.type_int(4, true);
    parity(idb, entry, &base.pointer(), expr::int32().pointer());
    parity(idb, entry, &base.array(8), expr::int32().array(8));
    parity(idb, entry, &base.const_(), expr::int32().const_());
    parity(idb, entry, &base.volatile_(), expr::int32().volatile_());
}

/// A defined struct resolves through [`type_ref`](idakit::Database::type_ref), and a pointer to it
/// applies in parity with the named-recipe twin.
fn named_ref_resolves_and_applies(idb: &mut idakit::Database, entry: Address) {
    use idakit::types::expr;

    idb.types_mut()
        .define("struct idakit_h_pt { int x; int y; };")
        .expect("define a struct to reference");

    let handle = idb
        .type_ref("idakit_h_pt")
        .expect("resolve the defined struct");
    let built = idb.at_mut(entry).apply_type(&handle.pointer());
    let recipe = idb
        .at_mut(entry)
        .set_type(expr::named("idakit_h_pt").pointer());
    assert!(
        built.is_ok() == recipe.is_ok(),
        "a pointer to the named struct should agree with its recipe twin: built={built:?} recipe={recipe:?}"
    );
}

/// An unknown name is a clean [`TypeWriteError::NoType`], never a panic.
fn named_ref_missing_is_no_type(idb: &mut idakit::Database) {
    let r = idb.type_ref("idakit_no_such_zzz");
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::NoType { .. }
        }) = r
    );
}

/// A parsed declaration builds a handle that applies in parity with the `decl` recipe twin.
fn parse_type_roundtrips(idb: &mut idakit::Database, entry: Address) {
    use idakit::types::expr;

    let handle = idb
        .parse_type("int *")
        .expect("parse a pointer declaration");
    let built = idb.at_mut(entry).apply_type(&handle);
    let recipe = idb.at_mut(entry).set_type(expr::decl("int *"));
    assert!(
        built.is_ok() == recipe.is_ok(),
        "a parsed handle should agree with its decl twin: built={built:?} recipe={recipe:?}"
    );
}

/// Garbage text is a [`TypeWriteError::ParseFailed`] carrying IDA's reason; print it so a run
/// shows whether the capture landed.
fn parse_type_rejects_garbage(idb: &mut idakit::Database) {
    match idb.parse_type("%%% not a type %%%") {
        Err(Error::TypeWrite {
            source: TypeWriteError::ParseFailed { reason, .. },
        }) => {
            println!("parse_type reject reason: {reason:?}");
        }
        other => panic!("garbage declaration should be ParseFailed, got {other:?}"),
    }
}

/// A declaration referencing the freshly defined struct parses, proving `parse_type` resolves
/// against the local til (not just built-in types).
fn parse_type_resolves_local_til(idb: &mut idakit::Database) {
    let r = idb.parse_type("idakit_h_pt *");
    assert!(
        !matches!(
            r,
            Err(Error::TypeWrite {
                source: TypeWriteError::ParseFailed { .. }
            })
        ),
        "a declaration over a defined local type must not fail parsing, got {r:?}"
    );
}

/// A base handle seeds two derivations from one `&self`, proving the composites copy rather than
/// consume: both the pointer and the array apply.
fn handle_reuse(idb: &mut idakit::Database, entry: Address) {
    let base = idb.type_int(4, true);
    let ptr = base.pointer();
    let arr = base.array(4);
    // `base` is still usable here; if `pointer` had consumed it, this line would not compile.
    let _ = base.const_();

    let p = idb.at_mut(entry).apply_type(&ptr);
    let a = idb.at_mut(entry).apply_type(&arr);
    assert!(
        p.is_ok() == a.is_ok(),
        "both derivations of one base should reach the same apply outcome: ptr={p:?} arr={a:?}"
    );
}

/// A pointer to an unresolved name is rejected. Depending on the parser it may fail at parse time
/// (an unknown name never resolves) or build and then fail at apply; only the apply-reject case is
/// asserted, the parse-reject case is noted and skipped.
fn apply_unresolved_pointer_is_rejected(idb: &mut idakit::Database, entry: Address) {
    match idb.parse_type("idakit_no_such_built *") {
        Ok(handle) => {
            let r = idb.at_mut(entry).apply_type(&handle);
            assert!(
                let Err(Error::TypeWrite {
                    source: TypeWriteError::ApplyRejected { .. }
                }) = r
            );
        }
        Err(Error::TypeWrite {
            source: TypeWriteError::ParseFailed { .. },
        }) => {
            println!(
                "skipping unresolved-pointer apply: the parser rejected the name at parse time"
            );
        }
        other => panic!("an unresolved pointer should parse-fail or apply-reject, got {other:?}"),
    }
}

/// One handle applies through both write cursors: a function-typed handle sets the prototype via
/// [`FunctionEdit::apply_type`], and an int handle routes through [`LocationMut::apply_type`], both
/// reaching the shared result mapping.
fn apply_through_both_cursors(idb: &mut idakit::Database, entry: Address) {
    let proto = idb
        .parse_type("int idakit_h_proto(int a, int b)")
        .expect("parse a function prototype");
    idb.function_mut(entry)
        .expect("a function at the entry")
        .apply_type(&proto)
        .expect("apply a prototype via FunctionEdit");
    assert!(
        idb.function(entry).prototype().is_some(),
        "a prototype should be set after applying a function-typed handle"
    );

    let int32 = idb.type_int(4, true);
    // The location cursor reaches the same helper; its outcome at a code entry is not asserted.
    let _ = idb.at_mut(entry).apply_type(&int32);
}
