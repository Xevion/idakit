//! Write path against a real database: comment round-trip (set then read back on both
//! channels) and byte patching (patch then read back), plus the unmapped-address
//! rejection. Closes with `save = false`, so the `.i64` on disk is never touched.

mod common;

use idakit::prelude::*;

#[test]
fn write() {
    common::with_canonical_db(run);
}

fn run(idb: &mut idakit::Database) {
    let address = idb.functions().next().expect("a function").address();

    comment_round_trips(idb, address);
    patch_round_trips(idb, address);
    patch_rejects_unmapped(idb);
    type_apply(idb, address);
    type_define(idb);
    type_build(idb, address);

    println!(
        "write OK: comment round-trip, patch round-trip, unmapped patch rejected, type apply + define + build"
    );
}

/// A regular and a repeatable comment set on `address` read back verbatim on their own channels,
/// read through the same write cursor (the cursor is read-capable).
fn comment_round_trips(idb: &mut idakit::Database, address: Address) {
    let mut loc = idb.at_mut(address);
    loc.set_comment("idakit regular", false)
        .expect("set regular comment");
    loc.set_comment("idakit repeatable", true)
        .expect("set repeatable comment");

    assert!(loc.comment().as_deref() == Some("idakit regular"));
    assert!(loc.repeatable_comment().as_deref() == Some("idakit repeatable"));
    // The two channels are independent -- reading one never returns the other.
    assert!(
        loc.comment() != loc.repeatable_comment(),
        "regular and repeatable channels should be distinct"
    );
}

/// Patching bytes is visible to a read-back on the same cursor, and restoring returns the originals.
fn patch_round_trips(idb: &mut idakit::Database, address: Address) {
    let original = idb.at(address).bytes(4);
    assert!(original.len() == 4, "need 4 readable bytes at the entry");

    // Bitwise-not is guaranteed to differ from the original in every byte.
    let flipped: Vec<u8> = original.iter().map(|b| !b).collect();
    let mut loc = idb.at_mut(address);
    loc.patch(&flipped).expect("patch failed");
    assert!(
        loc.bytes(4) == flipped,
        "read-back should show patched bytes"
    );

    loc.patch(&original).expect("restore failed");
    assert!(
        loc.bytes(4) == original,
        "restore should return the originals"
    );
}

/// A patch targeting an unmapped address is rejected whole, as a typed `WriteRejected`.
fn patch_rejects_unmapped(idb: &mut idakit::Database) {
    let nowhere = Address::new_const(0xffff_ffff_f000);
    let r = idb.at_mut(nowhere).patch(&[0x90, 0x90]);
    assert!(
        matches!(r, Err(Error::WriteRejected { op: "patch", .. })),
        "unmapped patch should be WriteRejected, got {r:?}"
    );
}

/// Applying a well-formed prototype sets it; a bad name or declaration surfaces the typed error.
fn type_apply(idb: &mut idakit::Database, address: Address) {
    // A well-formed prototype applies through the function cursor and shows up as a prototype.
    idb.function_mut(address)
        .expect("a function at the entry")
        .set_type("int idakit_probe(int a, int b)")
        .expect("apply function prototype");
    assert!(
        idb.function(address).prototype().is_some(),
        "a prototype should be set after apply"
    );

    // A bare, nonexistent name routes to the by-name path -- a clean TypeNotFound.
    let r = idb.at_mut(address).set_type("idakit_no_such_type_zzz");
    assert!(
        matches!(r, Err(Error::TypeNotFound { .. })),
        "unknown named type should be TypeNotFound, got {r:?}"
    );

    // A garbage declaration -- TypeParseFailed carrying IDA's reason (captured off the msg channel,
    // or the fallback when IDA left none). Print it so a run shows whether the capture landed.
    match idb
        .at_mut(address)
        .set_type(idakit::types::expr::decl("%%% not a type %%%"))
    {
        Err(Error::TypeParseFailed { reason, .. }) => {
            println!("type-apply parse-error reason: {reason:?}");
        }
        other => panic!("garbage decl should be TypeParseFailed, got {other:?}"),
    }
}

/// Defining a struct adds it to the type library so a later apply can reference it by name; a
/// malformed declaration surfaces the typed error.
fn type_define(idb: &mut idakit::Database) {
    idb.types_mut()
        .define("struct idakit_pt { int x; int y; };")
        .expect("define struct");
    let names: Vec<String> = idb.named_types().map(|t| t.name()).collect();
    assert!(
        names.iter().any(|n| n == "idakit_pt"),
        "the defined struct should appear in named types"
    );

    // A defined function typedef applies cleanly by bare name (the by-name OK path), routed
    // through the scoped-closure cursor. A function type at a function entry sets its prototype.
    let entry = idb.functions().next().expect("a function").address();
    idb.types_mut()
        .define("typedef int idakit_fn_t(int arg);")
        .expect("define function typedef");
    idb.with_function_mut(entry, |f| f.set_type("idakit_fn_t"))
        .expect("a function at the entry")
        .expect("apply named function type");
    assert!(
        idb.function(entry).prototype().is_some(),
        "a prototype should be set after applying a named function type"
    );

    // A declaration referencing the freshly defined struct must parse -- proving parse_decl
    // resolves against the local til -- whether or not the kernel reshapes a code address to it.
    // Routed through the scoped-closure location cursor.
    let r = idb.with_location_mut(entry, |loc| {
        loc.set_type(idakit::types::expr::decl("idakit_pt *"))
    });
    assert!(
        !matches!(r, Err(Error::TypeParseFailed { .. })),
        "a decl referencing a defined local type must not fail parsing, got {r:?}"
    );

    // A malformed declaration -- TypeDefineFailed.
    let r = idb
        .types_mut()
        .define("struct idakit_broken { this is not valid");
    assert!(
        matches!(r, Err(Error::TypeDefineFailed { .. })),
        "malformed define should be TypeDefineFailed, got {r:?}"
    );
}

/// A built recipe, a scalar leaf or a pointer/array composite, lowers through the
/// serialize-and-build path: the encoder emits postfix bytecode, the facade interpreter rebuilds
/// the `tinfo` bottom-up and applies it. A composite agrees with its text declaration, and one over
/// an unknown named type surfaces the typed error instead of panicking.
fn type_build(idb: &mut idakit::Database, address: Address) {
    use idakit::types::expr;

    idb.types_mut()
        .define("struct idakit_built_pt { int x; int y; };")
        .expect("define struct for the build path");

    // The built composite reaches apply_tinfo with the type its text declaration parses to, so the
    // two agree at any address (a code entry may or may not accept a data type; both paths match).
    let built = idb
        .at_mut(address)
        .set_type(expr::named("idakit_built_pt").pointer());
    let text = idb
        .at_mut(address)
        .set_type(expr::decl("idakit_built_pt *"));
    assert!(
        built.is_ok() == text.is_ok(),
        "a built composite should agree with its text declaration: built={built:?} text={text:?}"
    );
    println!("type-build composite applied: {}", built.is_ok());

    // A composite over an unknown named type fails at build time as a typed TypeApplyFailed, not a
    // panic or a silent success. Deterministic regardless of the address.
    let r = idb
        .at_mut(address)
        .set_type(expr::named("idakit_no_such_built").pointer());
    assert!(
        matches!(r, Err(Error::TypeApplyFailed { .. })),
        "a composite over an unknown named type should be TypeApplyFailed, got {r:?}"
    );
}
