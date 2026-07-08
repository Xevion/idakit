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
    type_function_build(idb, address);
    type_surgery(idb, address);
    type_clear(idb, address);
    type_member_edit(idb);
    type_enum_member_edit(idb);
    type_member_ref(idb);

    println!(
        "write OK: comment round-trip, patch round-trip, unmapped patch rejected, type apply + define + build + function-build + surgery + clear + member-edit + enum-member-edit + member-ref"
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

/// The from-scratch function-prototype builder lowers through the recipe path: build
/// `int f(int, unsigned int)` and a variadic twin, apply each as the entry's prototype, and read
/// the stored prototype back structurally (arch-independent) to confirm its return, arity, and
/// varargs flag.
fn type_function_build(idb: &mut idakit::Database, entry: Address) {
    use idakit::types::{TypeShape, expr};

    idb.function_mut(entry)
        .expect("a function at the entry")
        .set_type(
            expr::function(expr::int32())
                .arg(expr::int32())
                .arg(expr::decl("unsigned int")),
        )
        .expect("apply a built prototype");
    let proto = idb
        .function(entry)
        .prototype_type()
        .expect("walk the built prototype")
        .expect("a prototype is set after the built apply");
    let TypeShape::Function {
        ret,
        params,
        varargs,
    } = proto.shape()
    else {
        panic!(
            "the built prototype should be a function, got {:?}",
            proto.shape()
        );
    };
    assert!(!*varargs, "the fixed prototype is not variadic");
    assert!(params.len() == 2, "two parameters, got {}", params.len());
    assert!(
        proto.get(*ret).shape
            == TypeShape::Int {
                bytes: 4,
                signed: true,
            },
        "the return type should be a signed 32-bit int"
    );

    idb.function_mut(entry)
        .expect("a function at the entry")
        .set_type(expr::function(expr::void()).arg(expr::int32()).variadic())
        .expect("apply a variadic prototype");
    let proto = idb
        .function(entry)
        .prototype_type()
        .expect("walk the variadic prototype")
        .expect("a prototype is set after the variadic apply");
    assert!(
        matches!(proto.shape(), TypeShape::Function { varargs: true, .. }),
        "the built prototype should be variadic, got {:?}",
        proto.shape()
    );
}

/// Prototype surgery edits one field at a time: seed a known prototype, swap the return type,
/// retype and rename a parameter, prepend an implicit `this`, and set a calling convention,
/// confirming each through a structural or textual read; the out-of-range and no-prototype paths
/// surface the typed `SignatureError`.
fn type_surgery(idb: &mut idakit::Database, entry: Address) {
    use idakit::types::{TypeShape, expr};

    idb.function_mut(entry)
        .expect("a function at the entry")
        .set_type("int idakit_surgery_probe(int a, int b)")
        .expect("seed a prototype to edit");

    // Swap the return (int -> char *), retype arg 0 (-> unsigned int), rename arg 1.
    idb.function_mut(entry)
        .expect("a function at the entry")
        .set_return_type(expr::char_().pointer())
        .expect("set the return type");
    idb.function_mut(entry)
        .expect("a function at the entry")
        .set_arg_type(0, expr::decl("unsigned int"))
        .expect("retype arg 0");
    idb.function_mut(entry)
        .expect("a function at the entry")
        .rename_arg(1, "idakit_count")
        .expect("rename arg 1");

    let proto = idb
        .function(entry)
        .prototype_type()
        .expect("walk the edited prototype")
        .expect("a prototype is set");
    let TypeShape::Function { ret, params, .. } = proto.shape() else {
        panic!("expected a function, got {:?}", proto.shape());
    };
    assert!(
        matches!(proto.get(*ret).shape, TypeShape::Ptr(_)),
        "the return type should now be a pointer"
    );
    assert!(params.len() == 2, "still two params, got {}", params.len());
    assert!(
        matches!(
            proto.get(params[0]).shape,
            TypeShape::Int { signed: false, .. }
        ),
        "arg 0 should now be unsigned"
    );
    // Param names are not in the structural walk; they render in the prototype text.
    let text = idb.function(entry).prototype().expect("prototype text");
    assert!(
        text.contains("idakit_count"),
        "the renamed arg should render: {text:?}"
    );

    // An out-of-range index is a typed SignatureError, without mutating.
    let r = idb
        .function_mut(entry)
        .expect("a function at the entry")
        .set_arg_type(9, expr::int32());
    assert!(
        matches!(
            r,
            Err(Error::Signature {
                source: SignatureError::ArgIndexOutOfRange {
                    index: 9,
                    arity: 2,
                    ..
                }
            })
        ),
        "an out-of-range arg index should be ArgIndexOutOfRange, got {r:?}"
    );

    // prepend_this inserts a leading implicit this-pointer, shifting the params.
    idb.function_mut(entry)
        .expect("a function at the entry")
        .prepend_this(expr::void().pointer())
        .expect("prepend a this-pointer");
    let proto = idb
        .function(entry)
        .prototype_type()
        .expect("walk after prepend_this")
        .expect("a prototype is set");
    let TypeShape::Function { params, .. } = proto.shape() else {
        panic!("expected a function, got {:?}", proto.shape());
    };
    assert!(
        params.len() == 3,
        "the this-pointer should be prepended, got {}",
        params.len()
    );
    let text = idb.function(entry).prototype().expect("prototype text");
    assert!(
        text.contains("this"),
        "the this arg should render: {text:?}"
    );

    // Setting a convention is accepted; its rendering is arch-dependent, so no string check.
    idb.function_mut(entry)
        .expect("a function at the entry")
        .set_calling_convention(CallingConvention::Cdecl)
        .expect("set the calling convention");

    // A function whose type was cleared has no prototype to edit.
    idb.at_mut(entry).clear_type().expect("clear the prototype");
    let r = idb
        .function_mut(entry)
        .expect("a function at the entry")
        .set_return_type(expr::int32());
    assert!(
        matches!(
            r,
            Err(Error::Signature {
                source: SignatureError::NoPrototype { .. }
            })
        ),
        "editing a cleared prototype should be NoPrototype, got {r:?}"
    );
}

/// Clearing a type is the inverse of applying one: set a prototype, confirm it, clear it, confirm
/// it is gone, and confirm a second clear is an idempotent success.
fn type_clear(idb: &mut idakit::Database, entry: Address) {
    idb.function_mut(entry)
        .expect("a function at the entry")
        .set_type("int idakit_clear_probe(int a)")
        .expect("apply a prototype to clear");
    assert!(
        idb.function(entry).prototype().is_some(),
        "a prototype should be set before the clear"
    );

    idb.at_mut(entry).clear_type().expect("clear the type");
    assert!(
        idb.function(entry).prototype().is_none(),
        "the prototype should be gone after clear"
    );

    idb.at_mut(entry)
        .clear_type()
        .expect("a second clear is an idempotent success");
}

/// Struct-member surgery on a freshly defined type: append a member, rename one by bit offset,
/// retype another by name, then delete one. Each edit reads back structurally through `type_named`,
/// and the typed failures (duplicate name, missing member, missing type) surface without mutating.
fn type_member_edit(idb: &mut idakit::Database) {
    use idakit::types::{TypeEditCode, TypeEditError, expr};

    fn member_names(idb: &idakit::Database, ty: &str) -> Vec<String> {
        let t = idb.type_named(ty).expect("resolve the type");
        t.members()
            .expect("a struct has members")
            .iter()
            .map(|m| m.name.clone())
            .collect()
    }

    idb.types_mut()
        .define("struct idakit_member_probe { int a; int b; };")
        .expect("define a struct to edit");

    // Append a third member; the all-int layout keeps a@0, b@32, c@64 bits with no repacking.
    idb.types_mut()
        .edit("idakit_member_probe")
        .add_member("c", expr::int32())
        .expect("append member c");
    assert!(
        member_names(idb, "idakit_member_probe") == ["a", "b", "c"],
        "c should be appended after a and b"
    );

    // Offset keying on the stable layout: the member at bit 32 is b (a rename does not shift
    // offsets, so this stays unambiguous).
    idb.types_mut()
        .edit("idakit_member_probe")
        .member_at(32)
        .rename("beta")
        .expect("rename the member at bit 32 by offset");
    assert!(
        member_names(idb, "idakit_member_probe") == ["a", "beta", "c"],
        "the middle member should be renamed by offset"
    );

    // Delete the last member by name on the clean all-int layout (deleting the tail leaves no
    // gap member behind, unlike deleting a middle member).
    idb.types_mut()
        .edit("idakit_member_probe")
        .member("c")
        .delete()
        .expect("delete c by name");
    assert!(
        member_names(idb, "idakit_member_probe") == ["a", "beta"],
        "c should be gone, leaving a and beta"
    );

    // Renaming onto an existing name is a typed rejection carrying the structured code.
    let dup = idb
        .types_mut()
        .edit("idakit_member_probe")
        .member("beta")
        .rename("a");
    assert!(
        matches!(
            dup,
            Err(Error::TypeEdit {
                source: TypeEditError::Rejected {
                    code: TypeEditCode::DupName,
                    ..
                }
            })
        ),
        "renaming onto an existing name should be Rejected(DupName), got {dup:?}"
    );

    // A member that does not resolve is NoMember; an unknown type is NoType.
    let ghost = idb
        .types_mut()
        .edit("idakit_member_probe")
        .member("ghost")
        .set_type(expr::int32());
    assert!(
        matches!(
            ghost,
            Err(Error::TypeEdit {
                source: TypeEditError::NoMember { .. }
            })
        ),
        "editing a missing member should be NoMember, got {ghost:?}"
    );
    let no_type = idb
        .types_mut()
        .edit("idakit_no_such_struct")
        .add_member("x", expr::int32());
    assert!(
        matches!(
            no_type,
            Err(Error::TypeEdit {
                source: TypeEditError::NoType { .. }
            })
        ),
        "editing a missing type should be NoType, got {no_type:?}"
    );

    // Name keying with a size change: retype a to a one-byte char and confirm its width. Checked
    // last and by size (not by the member list, which a shrink can pad with a gap member).
    idb.types_mut()
        .edit("idakit_member_probe")
        .member("a")
        .set_type(expr::char_())
        .expect("retype member a to char");
    let probe = idb
        .type_named("idakit_member_probe")
        .expect("resolve probe");
    let a = probe
        .members()
        .expect("a struct has members")
        .iter()
        .find(|m| m.name == "a")
        .expect("member a");
    assert!(
        probe.get(a.ty).size == Some(1),
        "member a should now be a one-byte char"
    );
}

/// Enum-constant surgery on a freshly defined enum: add a constant, change a value, rename one,
/// delete one, each read back through `type_named`, and the typed failures (missing constant,
/// missing type, duplicate name) surface without mutating.
fn type_enum_member_edit(idb: &mut idakit::Database) {
    use idakit::types::{TypeEditError, TypeShape};

    fn constants(idb: &idakit::Database, ty: &str) -> Vec<(String, u64)> {
        let t = idb.type_named(ty).expect("resolve the enum");
        match t.shape() {
            TypeShape::Enum { members, .. } => {
                members.iter().map(|m| (m.name.clone(), m.value)).collect()
            }
            other => panic!("expected an enum, got {other:?}"),
        }
    }

    idb.types_mut()
        .define("enum idakit_enum_probe { PROBE_A = 1, PROBE_B = 2 };")
        .expect("define an enum to edit");

    idb.types_mut()
        .edit("idakit_enum_probe")
        .add_constant("PROBE_C", 3)
        .expect("add a constant");
    assert!(
        constants(idb, "idakit_enum_probe").contains(&("PROBE_C".to_owned(), 3)),
        "PROBE_C = 3 should be added"
    );

    idb.types_mut()
        .edit("idakit_enum_probe")
        .constant("PROBE_A")
        .set_value(10)
        .expect("change a constant value");
    assert!(
        constants(idb, "idakit_enum_probe").contains(&("PROBE_A".to_owned(), 10)),
        "PROBE_A should now be 10"
    );

    idb.types_mut()
        .edit("idakit_enum_probe")
        .constant("PROBE_B")
        .rename("PROBE_BETA")
        .expect("rename a constant");
    let names: Vec<String> = constants(idb, "idakit_enum_probe")
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert!(
        names.iter().any(|n| n == "PROBE_BETA") && !names.iter().any(|n| n == "PROBE_B"),
        "PROBE_B should be renamed to PROBE_BETA, got {names:?}"
    );

    idb.types_mut()
        .edit("idakit_enum_probe")
        .constant("PROBE_C")
        .delete()
        .expect("delete a constant");
    assert!(
        !constants(idb, "idakit_enum_probe")
            .iter()
            .any(|(n, _)| n == "PROBE_C"),
        "PROBE_C should be gone"
    );

    // A constant that does not resolve is NoMember; an unknown enum is NoType.
    let ghost = idb
        .types_mut()
        .edit("idakit_enum_probe")
        .constant("PROBE_GHOST")
        .set_value(9);
    assert!(
        matches!(
            ghost,
            Err(Error::TypeEdit {
                source: TypeEditError::NoMember { .. }
            })
        ),
        "editing a missing constant should be NoMember, got {ghost:?}"
    );
    let no_type = idb
        .types_mut()
        .edit("idakit_no_such_enum")
        .add_constant("X", 1);
    assert!(
        matches!(
            no_type,
            Err(Error::TypeEdit {
                source: TypeEditError::NoType { .. }
            })
        ),
        "editing a missing enum should be NoType, got {no_type:?}"
    );

    // Renaming onto an existing constant name is a typed rejection.
    let dup = idb
        .types_mut()
        .edit("idakit_enum_probe")
        .constant("PROBE_A")
        .rename("PROBE_BETA");
    assert!(
        matches!(
            dup,
            Err(Error::TypeEdit {
                source: TypeEditError::Rejected { .. }
            })
        ),
        "renaming onto an existing constant name should be Rejected, got {dup:?}"
    );
}

/// A durable MemberRef is a stable index handle guarded by a structural fingerprint: it survives a
/// rename of another member, edits through it, but goes stale once the layout changes (an append).
/// An out-of-range mint is a typed error.
fn type_member_ref(idb: &mut idakit::Database) {
    use idakit::types::{TypeEditError, expr};

    fn names(idb: &idakit::Database, ty: &str) -> Vec<String> {
        idb.type_named(ty)
            .expect("resolve the type")
            .members()
            .expect("a struct has members")
            .iter()
            .map(|m| m.name.clone())
            .collect()
    }

    idb.types_mut()
        .define("struct idakit_ref_probe { int a; int b; int c; };")
        .expect("define a struct for the ref");

    // Mint a ref to the middle member (index 1 = b).
    let r = idb
        .types_mut()
        .edit("idakit_ref_probe")
        .member_ref(1)
        .expect("mint a member ref");

    // Renaming another member leaves offsets unchanged, so the ref stays valid; edit through it.
    idb.types_mut()
        .edit("idakit_ref_probe")
        .member("a")
        .rename("alpha")
        .expect("rename a");
    idb.types_mut()
        .edit("idakit_ref_probe")
        .member_by_ref(&r)
        .expect("the ref survives an unrelated rename")
        .rename("beta")
        .expect("rename b through the ref");
    assert!(
        names(idb, "idakit_ref_probe") == ["alpha", "beta", "c"],
        "the ref should have renamed the middle member"
    );

    // A structural edit (append) changes the fingerprint, staling the ref.
    idb.types_mut()
        .edit("idakit_ref_probe")
        .add_member("d", expr::int32())
        .expect("append d");
    let stale = matches!(
        idb.types_mut().edit("idakit_ref_probe").member_by_ref(&r),
        Err(Error::TypeEdit {
            source: TypeEditError::StaleMemberRef { .. }
        })
    );
    assert!(stale, "an appended member should stale the ref");

    // Minting past the last member is a typed range error.
    let oob = idb.types_mut().edit("idakit_ref_probe").member_ref(99);
    assert!(
        matches!(
            oob,
            Err(Error::TypeEdit {
                source: TypeEditError::MemberIndexOutOfRange { index: 99, .. }
            })
        ),
        "an out-of-range index should be MemberIndexOutOfRange, got {oob:?}"
    );
}
