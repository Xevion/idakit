//! Struct-member surgery: append/rename/retype/delete, comments, bitfields, numeric repr,
//! durable member refs, offset-keyed insertion and editing, and the `ETF_COMPATIBLE` retype flag.

use assert2::assert;
use idakit::prelude::*;

use crate::common::assert_type_write_err;

/// Struct-member surgery on a freshly defined type: append a member, rename one by bit offset,
/// retype another by name, then delete one. Each edit reads back structurally through `type_named`,
/// and the typed failures (duplicate name, missing member, missing type) surface without mutating.
#[test]
fn type_member_edit() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::{TypeEditCode, TypeWriteError, expr};

        fn member_names(idb: &Database, ty: &str) -> Vec<String> {
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
        assert_type_write_err!(
            dup,
            TypeWriteError::Rejected {
                code: TypeEditCode::DupName,
                ..
            }
        );

        // A member that does not resolve is NoMember; an unknown type is NoType.
        let ghost = idb
            .types_mut()
            .edit("idakit_member_probe")
            .member("ghost")
            .set_type(expr::int32());
        assert_type_write_err!(ghost, TypeWriteError::NoMember { .. });
        let no_type = idb
            .types_mut()
            .edit("idakit_no_such_struct")
            .add_member("x", expr::int32());
        assert_type_write_err!(no_type, TypeWriteError::NoType { .. });

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
    });
}

/// `MemberEdit::comment` sets a member's comment. `TypeMember` does not yet surface a comment on
/// the read side, so this asserts the write succeeds and a re-comment is stable, rather than
/// reading the comment back; an unresolved member is still the same typed `NoMember` other member
/// edits give it.
#[test]
fn type_member_comment_edit() {
    crate::common::with_canonical_db(|idb| {
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
        assert_type_write_err!(ghost, TypeWriteError::NoMember { .. });
    });
}

/// `expr::bitfield` builds a bitfield member through both `add_member` and `MemberEdit::set_type`;
/// `TypeMember::bitfield_width` already reads it back. A bitfield in a union is rejected by the
/// kernel (`TERR_UNION_BF`), flowing through the existing `TypeEditCode` decode with no special
/// handling.
#[test]
fn type_member_bitfield() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::{TypeEditCode, TypeWriteError, expr};

        fn bitfield_width(idb: &Database, ty: &str, member: &str) -> Option<u32> {
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
        assert_type_write_err!(
            rejected,
            TypeWriteError::Rejected {
                code: TypeEditCode::UnionBitfield,
                ..
            }
        );
    });
}

/// `MemberEdit::set_repr` builds a `value_repr_t` for the numeric subset (radix/char, forced
/// sign, leading zeros); `TypeMember::repr` reads it back. An unresolved member still surfaces as
/// `TypeWriteError::NoMember`, mirroring the comment/bitfield tests.
#[test]
fn type_member_repr_edit() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::{NumberFormat, TypeWriteError, ValueRepr};

        fn repr(idb: &Database, ty: &str, member: &str) -> Option<ValueRepr> {
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
        assert_type_write_err!(ghost, TypeWriteError::NoMember { .. });
    });
}

/// A durable MemberRef is a stable index handle guarded by a structural fingerprint: it survives a
/// rename of another member, edits through it, but goes stale once the layout changes (an append).
/// An out-of-range mint is a typed error.
#[test]
fn type_member_ref() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::{TypeWriteError, expr};

        fn names(idb: &Database, ty: &str) -> Vec<String> {
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
        assert_type_write_err!(
            edit.member_by_ref(&r),
            TypeWriteError::StaleMemberRef { .. }
        );

        // Minting past the last member is a typed range error.
        let oob = idb.types_mut().edit("idakit_ref_probe").member_ref(99);
        assert_type_write_err!(oob, TypeWriteError::MemberIndexOutOfRange { index: 99, .. });

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
        assert_type_write_err!(
            edit.member_by_ref(&gref),
            TypeWriteError::StaleMemberRef { .. }
        );
    });
}

/// `add_member_at` inserts a new member at an explicit bit offset, distinct from `member_at`
/// (which only selects an existing one). A char followed by an int leaves an alignment gap in
/// most tils; insert into that gap and confirm the new member lands there. Skips if this
/// database's til packs the two fields with no gap to insert into.
#[test]
fn type_member_add_at_offset() {
    crate::common::with_canonical_db(|idb| {
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
    });
}

/// Offset-keyed selection also retypes and deletes, not just renames (the rename case is
/// already covered in `type_member_edit`).
#[test]
fn type_member_offset_edit() {
    crate::common::with_canonical_db(|idb| {
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
    });
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
#[test]
fn type_member_set_type_compatible() {
    crate::common::with_canonical_db(|idb| {
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
    });
}
