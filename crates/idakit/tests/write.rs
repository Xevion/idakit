//! Write path against a real database: comment round-trip (set then read back on both
//! channels) and byte patching (patch then read back), plus the unmapped-address
//! rejection. Closes with `save = false`, so the `.i64` on disk is never touched.

mod common;

use assert2::assert;
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
    type_member_comment_edit(idb);
    type_member_bitfield(idb);
    type_member_repr_edit(idb);
    type_enum_member_edit(idb);
    type_enum_bitmask_edit(idb);
    type_enum_repr_edit(idb);
    type_enum_width_edit(idb);
    type_member_ref(idb);
    type_member_add_at_offset(idb);
    type_member_offset_edit(idb);
    type_function_edit_direct(idb, address);
    type_named_arg_renders(idb, address);
    type_build_failed(idb, address);
    type_member_set_type_compatible(idb);
    type_enum_forcename(idb);

    println!(
        "write OK: comment round-trip, patch round-trip, unmapped patch rejected, type apply + define + build + function-build + surgery + clear + member-edit + member-comment-edit + member-bitfield + member-repr-edit + enum-member-edit + enum-bitmask-edit + enum-repr-edit + enum-width-edit + member-ref + offset-insert + offset-edit + direct function-edit + named-arg render + build-failed + member-set-type-compatible + enum-forcename"
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
    // The two channels are independent, so reading one never returns the other.
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
    assert!(let Err(Error::WriteRejected { op: "patch", .. }) = r);
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

    // A bare, nonexistent name routes to the by-name path, a clean NoType.
    let r = idb.at_mut(address).set_type("idakit_no_such_type_zzz");
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::NoType { .. }
        }) = r
    );

    // A garbage declaration: ParseFailed carrying IDA's reason (captured off the msg channel,
    // or the fallback when IDA left none). Print it so a run shows whether the capture landed.
    match idb
        .at_mut(address)
        .set_type(idakit::types::expr::decl("%%% not a type %%%"))
    {
        Err(Error::TypeWrite {
            source: TypeWriteError::ParseFailed { reason, .. },
        }) => {
            println!("type-apply parse-error reason: {reason:?}");
        }
        other => panic!("garbage decl should be ParseFailed, got {other:?}"),
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

    // A declaration referencing the freshly defined struct must parse, proving parse_decl
    // resolves against the local til, whether or not the kernel reshapes a code address to it.
    // Routed through the scoped-closure location cursor.
    let r = idb.with_location_mut(entry, |loc| {
        loc.set_type(idakit::types::expr::decl("idakit_pt *"))
    });
    assert!(
        !matches!(
            r,
            Err(Error::TypeWrite {
                source: TypeWriteError::ParseFailed { .. }
            })
        ),
        "a decl referencing a defined local type must not fail parsing, got {r:?}"
    );

    // A malformed declaration: TypeDefineFailed.
    let r = idb
        .types_mut()
        .define("struct idakit_broken { this is not valid");
    assert!(let Err(Error::TypeDefineFailed { .. }) = r);
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

    // A composite over an unknown named type BUILDS fine (an unresolved named leaf is accepted
    // into the tinfo), but the kernel refuses to APPLY it because the pointee is unresolved, a
    // deterministic ApplyRejected, regardless of the address.
    let r = idb
        .at_mut(address)
        .set_type(expr::named("idakit_no_such_built").pointer());
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::ApplyRejected { .. }
        }) = r
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
    assert!(let TypeShape::Function { varargs: true, .. } = proto.shape());

    // A builder-supplied calling convention applies. Its rendering is arch-dependent, so no string
    // check, matching type_surgery's cc note.
    idb.function_mut(entry)
        .expect("a function at the entry")
        .set_type(
            expr::function(expr::int32())
                .arg(expr::int32())
                .calling_convention(CallingConvention::Cdecl),
        )
        .expect("apply a prototype with a calling convention");
    assert!(
        idb.function(entry).prototype().is_some(),
        "a prototype should be set after applying a cc-carrying builder"
    );
}

/// Prototype surgery edits one field at a time: seed a known prototype, swap the return type,
/// retype and rename a parameter, prepend an implicit `this`, and set a calling convention,
/// confirming each through a structural or textual read; the out-of-range and no-prototype paths
/// surface the typed `TypeWriteError`.
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
    assert!(let TypeShape::Ptr(_) = &proto.get(*ret).shape);
    assert!(params.len() == 2, "still two params, got {}", params.len());
    assert!(let TypeShape::Int { signed: false, .. } = &proto.get(params[0]).shape);
    // Param names are not in the structural walk; they render in the prototype text.
    let text = idb.function(entry).prototype().expect("prototype text");
    assert!(
        text.contains("idakit_count"),
        "the renamed arg should render: {text:?}"
    );

    // An out-of-range index is a typed TypeWriteError, without mutating.
    let r = idb
        .function_mut(entry)
        .expect("a function at the entry")
        .set_arg_type(9, expr::int32());
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::ArgIndexOutOfRange {
                index: 9,
                arity: 2,
                ..
            }
        }) = r
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
        let Err(Error::TypeWrite {
            source: TypeWriteError::NoPrototype { .. }
        }) = r
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
    use idakit::types::{TypeEditCode, TypeWriteError, expr};

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
        let Err(Error::TypeWrite {
            source: TypeWriteError::Rejected {
                code: TypeEditCode::DupName,
                ..
            }
        }) = dup
    );

    // A member that does not resolve is NoMember; an unknown type is NoType.
    let ghost = idb
        .types_mut()
        .edit("idakit_member_probe")
        .member("ghost")
        .set_type(expr::int32());
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::NoMember { .. }
        }) = ghost
    );
    let no_type = idb
        .types_mut()
        .edit("idakit_no_such_struct")
        .add_member("x", expr::int32());
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::NoType { .. }
        }) = no_type
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

/// `MemberEdit::comment` sets a member's comment. `TypeMember` does not yet surface a comment on
/// the read side, so this asserts the write succeeds and a re-comment is stable, rather than
/// reading the comment back; an unresolved member is still the same typed `NoMember` other member
/// edits give it.
fn type_member_comment_edit(idb: &mut idakit::Database) {
    use idakit::types::TypeWriteError;

    idb.types_mut()
        .define("struct idakit_comment_probe { int hp; };")
        .expect("define a struct to comment");

    idb.types_mut()
        .edit("idakit_comment_probe")
        .member("hp")
        .comment("current health")
        .expect("set the member comment");

    idb.types_mut()
        .edit("idakit_comment_probe")
        .member("hp")
        .comment("current health, again")
        .expect("re-set the member comment");

    let ghost = idb
        .types_mut()
        .edit("idakit_comment_probe")
        .member("ghost")
        .comment("nope");
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::NoMember { .. }
        }) = ghost
    );
}

/// `expr::bitfield` builds a bitfield member through both `add_member` and `MemberEdit::set_type`;
/// `TypeMember::bitfield_width` already reads it back. A bitfield in a union is rejected by the
/// kernel (`TERR_UNION_BF`), flowing through the existing `TypeEditCode` decode with no special
/// handling.
fn type_member_bitfield(idb: &mut idakit::Database) {
    use idakit::types::{TypeEditCode, TypeWriteError, expr};

    fn bitfield_width(idb: &idakit::Database, ty: &str, member: &str) -> Option<u32> {
        idb.type_named(ty)
            .expect("resolve the type")
            .members()
            .expect("a struct has members")
            .iter()
            .find(|m| m.name == member)
            .expect("the member")
            .bitfield_width
    }

    idb.types_mut()
        .define("struct idakit_bitfield_probe { int pad; };")
        .expect("define a struct to add a bitfield to");

    idb.types_mut()
        .edit("idakit_bitfield_probe")
        .add_member("flag", expr::bitfield(4, 3, false))
        .expect("add a bitfield member");
    assert!(
        bitfield_width(idb, "idakit_bitfield_probe", "flag") == Some(3),
        "flag should be a 3-bit bitfield"
    );

    // Retyping an ordinary member to a bitfield goes through the same recipe leaf.
    idb.types_mut()
        .edit("idakit_bitfield_probe")
        .add_member("plain", expr::int32())
        .expect("append an ordinary member");
    idb.types_mut()
        .edit("idakit_bitfield_probe")
        .member("plain")
        .set_type(expr::bitfield(2, 5, true))
        .expect("retype plain to a bitfield");
    assert!(
        bitfield_width(idb, "idakit_bitfield_probe", "plain") == Some(5),
        "plain should now be a 5-bit bitfield"
    );

    idb.types_mut()
        .define("union idakit_bitfield_union_probe { int pad; };")
        .expect("define a union to reject a bitfield");
    let rejected = idb
        .types_mut()
        .edit("idakit_bitfield_union_probe")
        .add_member("flag", expr::bitfield(4, 3, false));
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::Rejected {
                code: TypeEditCode::UnionBitfield,
                ..
            }
        }) = rejected
    );
}

/// `MemberEdit::set_repr` builds a `value_repr_t` for the numeric subset (radix/char, forced
/// sign, leading zeros); `TypeMember::repr` reads it back. An unresolved member still surfaces as
/// `TypeWriteError::NoMember`, mirroring the comment/bitfield tests.
fn type_member_repr_edit(idb: &mut idakit::Database) {
    use idakit::types::{NumberFormat, TypeWriteError, ValueRepr};

    fn repr(idb: &idakit::Database, ty: &str, member: &str) -> Option<ValueRepr> {
        idb.type_named(ty)
            .expect("resolve the type")
            .members()
            .expect("a struct has members")
            .iter()
            .find(|m| m.name == member)
            .expect("the member")
            .repr
    }

    idb.types_mut()
        .define("struct idakit_repr_probe { int hex_field; int dec_field; };")
        .expect("define a struct to set repr on");

    let hex_repr = ValueRepr {
        format: NumberFormat::Hexadecimal,
        signed: true,
        leading_zeros: false,
    };
    idb.types_mut()
        .edit("idakit_repr_probe")
        .member("hex_field")
        .set_repr(hex_repr)
        .expect("set hex_field's repr");
    assert!(repr(idb, "idakit_repr_probe", "hex_field") == Some(hex_repr));

    let dec_repr = ValueRepr {
        format: NumberFormat::Decimal,
        signed: false,
        leading_zeros: true,
    };
    idb.types_mut()
        .edit("idakit_repr_probe")
        .member("dec_field")
        .set_repr(dec_repr)
        .expect("set dec_field's repr");
    assert!(repr(idb, "idakit_repr_probe", "dec_field") == Some(dec_repr));

    let ghost = idb
        .types_mut()
        .edit("idakit_repr_probe")
        .member("ghost")
        .set_repr(hex_repr);
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::NoMember { .. }
        }) = ghost
    );
}

/// Enum-constant surgery on a freshly defined enum: add a constant, change a value, rename one,
/// delete one, each read back through `type_named`, and the typed failures (missing constant,
/// missing type, duplicate name) surface without mutating.
fn type_enum_member_edit(idb: &mut idakit::Database) {
    use idakit::types::{TypeShape, TypeWriteError};

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
        let Err(Error::TypeWrite {
            source: TypeWriteError::NoMember { .. }
        }) = ghost
    );
    let no_type = idb
        .types_mut()
        .edit("idakit_no_such_enum")
        .add_constant("X", 1);
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::NoType { .. }
        }) = no_type
    );

    // Renaming onto an existing constant name is a typed rejection.
    let dup = idb
        .types_mut()
        .edit("idakit_enum_probe")
        .constant("PROBE_A")
        .rename("PROBE_BETA");
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::Rejected { .. }
        }) = dup
    );
}

/// `set_bitmask` flips `TypeShape::Enum::is_bitmask` and back, and `add_flag`'s explicit group
/// mask lands the same way `add_constant`'s implicit one does.
fn type_enum_bitmask_edit(idb: &mut idakit::Database) {
    use idakit::types::TypeShape;

    fn shape(idb: &idakit::Database, ty: &str) -> (bool, Vec<(String, u64)>) {
        let t = idb.type_named(ty).expect("resolve the enum");
        match t.shape() {
            TypeShape::Enum {
                is_bitmask,
                members,
                ..
            } => (
                *is_bitmask,
                members.iter().map(|m| (m.name.clone(), m.value)).collect(),
            ),
            other => panic!("expected an enum, got {other:?}"),
        }
    }

    idb.types_mut()
        .define("enum idakit_flags_probe { PROBE_RESERVED = 8 };")
        .expect("define an enum to edit");
    assert!(
        !shape(idb, "idakit_flags_probe").0,
        "starts as an ordinary enum"
    );

    idb.types_mut()
        .edit("idakit_flags_probe")
        .set_bitmask(true)
        .expect("mark as a bitmask enum");
    assert!(
        shape(idb, "idakit_flags_probe").0,
        "should now be a bitmask enum"
    );

    idb.types_mut()
        .edit("idakit_flags_probe")
        .add_flag("PROBE_READ", 1, 1)
        .expect("add a masked flag");
    idb.types_mut()
        .edit("idakit_flags_probe")
        .add_flag("PROBE_WRITE", 2, 2)
        .expect("add a second masked flag");
    let (_, members) = shape(idb, "idakit_flags_probe");
    assert!(members.contains(&("PROBE_READ".to_owned(), 1)));
    assert!(members.contains(&("PROBE_WRITE".to_owned(), 2)));

    idb.types_mut()
        .edit("idakit_flags_probe")
        .set_bitmask(false)
        .expect("clear the bitmask marking");
    assert!(
        !shape(idb, "idakit_flags_probe").0,
        "should be an ordinary enum again"
    );
}

/// `TypeEdit::set_repr` builds the same `value_repr_t` as `MemberEdit::set_repr`, but at the
/// whole-enum level (`tinfo_t::set_enum_repr`); `TypeShape::Enum::repr` reads it back.
fn type_enum_repr_edit(idb: &mut idakit::Database) {
    use idakit::types::{NumberFormat, TypeShape, ValueRepr};

    fn repr(idb: &idakit::Database, ty: &str) -> Option<ValueRepr> {
        let t = idb.type_named(ty).expect("resolve the enum");
        match t.shape() {
            TypeShape::Enum { repr, .. } => *repr,
            other => panic!("expected an enum, got {other:?}"),
        }
    }

    idb.types_mut()
        .define("enum idakit_enum_repr_probe { PROBE_A = 1 };")
        .expect("define an enum to set repr on");

    let hex_repr = ValueRepr {
        format: NumberFormat::Hexadecimal,
        signed: true,
        leading_zeros: false,
    };
    idb.types_mut()
        .edit("idakit_enum_repr_probe")
        .set_repr(hex_repr)
        .expect("set the enum's repr");
    assert!(repr(idb, "idakit_enum_repr_probe") == Some(hex_repr));

    let dec_repr = ValueRepr {
        format: NumberFormat::Decimal,
        signed: false,
        leading_zeros: true,
    };
    idb.types_mut()
        .edit("idakit_enum_repr_probe")
        .set_repr(dec_repr)
        .expect("change the enum's repr");
    assert!(repr(idb, "idakit_enum_repr_probe") == Some(dec_repr));
}

/// `TypeEdit::set_enum_width` sets the enum's storage width (`tinfo_t::set_enum_width`); the new
/// width shows through the resolved `Type`'s own byte size.
fn type_enum_width_edit(idb: &mut idakit::Database) {
    idb.types_mut()
        .define("enum idakit_enum_width_probe { PROBE_A = 1 };")
        .expect("define an enum to resize");

    idb.types_mut()
        .edit("idakit_enum_width_probe")
        .set_enum_width(8)
        .expect("widen the enum to 8 bytes");
    let widened = idb
        .type_named("idakit_enum_width_probe")
        .expect("resolve the widened enum");
    assert!(
        widened.size() == Some(8),
        "the enum's size should reflect the new width, got {:?}",
        widened.size()
    );

    idb.types_mut()
        .edit("idakit_enum_width_probe")
        .set_enum_width(1)
        .expect("narrow the enum to 1 byte");
    let narrowed = idb
        .type_named("idakit_enum_width_probe")
        .expect("resolve the narrowed enum");
    assert!(
        narrowed.size() == Some(1),
        "the enum's size should reflect the narrower width, got {:?}",
        narrowed.size()
    );
}

/// A durable MemberRef is a stable index handle guarded by a structural fingerprint: it survives a
/// rename of another member, edits through it, but goes stale once the layout changes (an append).
/// An out-of-range mint is a typed error.
fn type_member_ref(idb: &mut idakit::Database) {
    use idakit::types::{TypeWriteError, expr};

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
    assert!(r.index() == 1);
    assert!(r.type_name() == "idakit_ref_probe");

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
    let mut types = idb.types_mut();
    let mut edit = types.edit("idakit_ref_probe");
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::StaleMemberRef { .. }
        }) = edit.member_by_ref(&r)
    );

    // Minting past the last member is a typed range error.
    let oob = idb.types_mut().edit("idakit_ref_probe").member_ref(99);
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::MemberIndexOutOfRange { index: 99, .. }
        }) = oob
    );

    // Deleting a non-tail member leaves a same-offset gap (IDA does not repack), so the fingerprint
    // must catch the retype and stale a ref into the deleted slot.
    idb.types_mut()
        .define("struct idakit_gap_ref { int p; int q; int r; };")
        .expect("define a struct for the gap case");
    let gref = idb
        .types_mut()
        .edit("idakit_gap_ref")
        .member_ref(1)
        .expect("mint a ref to q");
    idb.types_mut()
        .edit("idakit_gap_ref")
        .member("q")
        .delete()
        .expect("delete the middle member");
    let mut types = idb.types_mut();
    let mut edit = types.edit("idakit_gap_ref");
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::StaleMemberRef { .. }
        }) = edit.member_by_ref(&gref)
    );
}

/// `add_member_at` inserts a new member at an explicit bit offset, distinct from `member_at`
/// (which only selects an existing one). A char followed by an int leaves an alignment gap in
/// most tils; insert into that gap and confirm the new member lands there. Skips if this
/// database's til packs the two fields with no gap to insert into.
fn type_member_add_at_offset(idb: &mut idakit::Database) {
    use idakit::types::expr;

    idb.types_mut()
        .define("struct idakit_insert_probe { char a; int c; };")
        .expect("define a struct with alignment padding after a");

    let gap_start = {
        let probe = idb
            .type_named("idakit_insert_probe")
            .expect("resolve the type");
        let members = probe.members().expect("a struct has members");
        let a = members.iter().find(|m| m.name == "a").expect("member a");
        let c = members.iter().find(|m| m.name == "c").expect("member c");
        let after_a = a.bit_offset + 8;
        if c.bit_offset <= after_a {
            None
        } else {
            Some(after_a)
        }
    };
    let Some(gap_start) = gap_start else {
        println!("skipping add_member_at: this til leaves no alignment gap after a char");
        return;
    };

    idb.types_mut()
        .edit("idakit_insert_probe")
        .add_member_at(gap_start, "b", expr::char_())
        .expect("insert b into the alignment gap");

    let probe = idb
        .type_named("idakit_insert_probe")
        .expect("resolve after insert");
    let landed = probe
        .members()
        .expect("a struct has members")
        .iter()
        .any(|m| m.name == "b" && m.bit_offset == gap_start);
    assert!(landed, "b should be inserted at bit offset {gap_start}");
}

/// Offset-keyed selection also retypes and deletes, not just renames (the rename case is
/// already covered in `type_member_edit`).
fn type_member_offset_edit(idb: &mut idakit::Database) {
    use idakit::types::{TypeShape, expr};

    idb.types_mut()
        .define("struct idakit_offset_probe { int a; int b; int c; };")
        .expect("define a struct to edit by offset");

    // Retype the member at bit 32 (b) to unsigned, keyed by offset rather than name.
    idb.types_mut()
        .edit("idakit_offset_probe")
        .member_at(32)
        .set_type(expr::decl("unsigned int"))
        .expect("retype the member at bit 32");
    let probe = idb
        .type_named("idakit_offset_probe")
        .expect("resolve the type");
    let b = probe
        .members()
        .expect("a struct has members")
        .iter()
        .find(|m| m.name == "b")
        .expect("member b");
    assert!(let TypeShape::Int { signed: false, .. } = &probe.get(b.ty).shape);

    // Delete the member at bit 64 (c), keyed by offset rather than name.
    idb.types_mut()
        .edit("idakit_offset_probe")
        .member_at(64)
        .delete()
        .expect("delete the member at bit 64");
    let probe = idb
        .type_named("idakit_offset_probe")
        .expect("resolve after offset delete");
    let names: Vec<String> = probe
        .members()
        .expect("a struct has members")
        .iter()
        .map(|m| m.name.clone())
        .collect();
    assert!(
        !names.iter().any(|n| n == "c"),
        "c should be gone after offset delete, got {names:?}"
    );
}

/// `clear_type` and `rename` invoked directly on the function cursor from `function_mut`
/// (previously only exercised through the location cursor's `at_mut`).
fn type_function_edit_direct(idb: &mut idakit::Database, entry: Address) {
    idb.function_mut(entry)
        .expect("a function at the entry")
        .set_type("int idakit_direct_probe(int a)")
        .expect("seed a prototype to clear");
    idb.function_mut(entry)
        .expect("a function at the entry")
        .clear_type()
        .expect("clear_type via FunctionEdit");
    assert!(
        idb.function(entry).prototype().is_none(),
        "the prototype should be gone after FunctionEdit::clear_type"
    );

    let original = idb.function(entry).name();
    idb.function_mut(entry)
        .expect("a function at the entry")
        .rename("idakit_direct_rename_probe")
        .expect("rename via FunctionEdit");
    assert!(idb.function(entry).name().as_str() == "idakit_direct_rename_probe");

    idb.function_mut(entry)
        .expect("a function at the entry")
        .rename(original.as_str())
        .expect("restore the original name");
    assert!(idb.function(entry).name().as_str() == original.as_str());
}

/// A builder-supplied parameter name renders in the applied prototype's text.
fn type_named_arg_renders(idb: &mut idakit::Database, entry: Address) {
    use idakit::types::expr;

    idb.function_mut(entry)
        .expect("a function at the entry")
        .set_type(expr::function(expr::int32()).named_arg("myparam", expr::int32()))
        .expect("apply a prototype with a named arg");
    let text = idb.function(entry).prototype().expect("prototype text");
    assert!(
        text.contains("myparam"),
        "the builder-supplied param name should render: {text:?}"
    );
}

/// A composite recipe whose embedded declaration fails to parse fails at build time
/// (`BuildFailed`), distinct from a bare top-level `decl()`, which fails at parse time
/// (`ParseFailed`, see `type_apply`): wrapping the same garbage text in `.pointer()` routes it
/// through the recipe-build path instead of the direct-decl path.
fn type_build_failed(idb: &mut idakit::Database, address: Address) {
    use idakit::types::expr;

    let r = idb
        .at_mut(address)
        .set_type(expr::decl("%%% not a type %%%").pointer());
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::BuildFailed { .. }
        }) = r
    );
}

/// `MemberEdit::set_type_compatible` (`ETF_COMPATIBLE`) is SDK-documented (`typeinf.hpp`) to
/// reject a replacement the kernel's own compatibility check refuses, as
/// `TypeEditCode::NotCompatible`. This crate's genuine attempts to trigger that rejection all
/// succeeded instead: same-size and mismatched-size scalar<->scalar retypes (int<->char,
/// int<->unsigned int), scalar<->same-size aggregate, scalar<->pointer and pointer<->scalar, a
/// bitfield width change, a bitfield sign flip, a bitfield grown from a plain scalar, an enum
/// retype, a solo union member grown past its old size, an existing numeric `set_repr` left in
/// place across a retype to an aggregate, and shrinking a non-tail struct member (which leaves an
/// unlabeled gap rather than moving the following member or converting to an array). None
/// reproduced `NotCompatible`, so this test proves the flag threads through and takes structural
/// effect instead of asserting the rejection.
fn type_member_set_type_compatible(idb: &mut idakit::Database) {
    use idakit::types::{TypeShape, expr};

    idb.types_mut()
        .define("struct idakit_etf_compat_probe { int a; };")
        .expect("define a struct to retype");

    idb.types_mut()
        .edit("idakit_etf_compat_probe")
        .member("a")
        .set_type_compatible(expr::decl("unsigned int"))
        .expect("a compatible retype should succeed under ETF_COMPATIBLE");

    let probe = idb
        .type_named("idakit_etf_compat_probe")
        .expect("resolve the retyped struct");
    let a = probe
        .members()
        .expect("a struct has members")
        .iter()
        .find(|m| m.name == "a")
        .expect("member a");
    assert!(let TypeShape::Int { signed: false, .. } = &probe.get(a.ty).shape);
}

/// `TypeEdit::add_constant_forced`/`ConstantEdit::rename_forced` (`ETF_FORCENAME`) force an enum
/// constant name through the alien-name collision (`TERR_ALIEN_NAME`) that the plain add/rename
/// paths reject when the name is already used by another enum.
fn type_enum_forcename(idb: &mut idakit::Database) {
    use idakit::types::{TypeEditCode, TypeWriteError};

    idb.types_mut()
        .define("enum idakit_forcename_owner { IDAKIT_FORCENAME_TAKEN = 1 };")
        .expect("define the enum that owns the name");
    idb.types_mut()
        .define("enum idakit_forcename_add { IDAKIT_FORCENAME_OTHER = 1 };")
        .expect("define a second enum to add a colliding constant to");
    idb.types_mut()
        .define("enum idakit_forcename_rename { IDAKIT_FORCENAME_MINE = 1 };")
        .expect("define a third enum to rename a constant into a collision");

    // Plain add rejects the cross-enum name collision.
    let rejected = idb
        .types_mut()
        .edit("idakit_forcename_add")
        .add_constant("IDAKIT_FORCENAME_TAKEN", 2);
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::Rejected {
                code: TypeEditCode::AlienName,
                ..
            }
        }) = rejected
    );

    // add_constant_forced forces the same name through.
    idb.types_mut()
        .edit("idakit_forcename_add")
        .add_constant_forced("IDAKIT_FORCENAME_TAKEN", 2)
        .expect("add_constant_forced should force the name through the collision");

    // Plain rename rejects the same collision.
    let rejected = idb
        .types_mut()
        .edit("idakit_forcename_rename")
        .constant("IDAKIT_FORCENAME_MINE")
        .rename("IDAKIT_FORCENAME_TAKEN");
    assert!(
        let Err(Error::TypeWrite {
            source: TypeWriteError::Rejected {
                code: TypeEditCode::AlienName,
                ..
            }
        }) = rejected
    );

    // rename_forced forces it through.
    idb.types_mut()
        .edit("idakit_forcename_rename")
        .constant("IDAKIT_FORCENAME_MINE")
        .rename_forced("IDAKIT_FORCENAME_TAKEN")
        .expect("rename_forced should force the name through the collision");
}
