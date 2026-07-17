//! Enum surgery: constant add/rename/retype/delete, the bitmask flag, whole-enum numeric repr,
//! storage width, forced-name collisions, and delete-by-value.

use assert2::assert;
use idakit::prelude::*;

use crate::common::assert_type_write_err;

/// Enum-constant surgery on a freshly defined enum: add a constant, change a value, rename one,
/// delete one, each read back through `type_named`, and the typed failures (missing constant,
/// missing type, duplicate name) surface without mutating.
#[test]
fn type_enum_member_edit() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::{TypeShape, TypeWriteError};

        fn constants(idb: &Database, ty: &str) -> Vec<(String, u64)> {
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
        assert_type_write_err!(ghost, TypeWriteError::NoMember { .. });
        let no_type = idb
            .types_mut()
            .edit("idakit_no_such_enum")
            .add_constant("X", 1);
        assert_type_write_err!(no_type, TypeWriteError::NoType { .. });

        // Renaming onto an existing constant name is a typed rejection.
        let dup = idb
            .types_mut()
            .edit("idakit_enum_probe")
            .constant("PROBE_A")
            .rename("PROBE_BETA");
        assert_type_write_err!(dup, TypeWriteError::Rejected { .. });
    });
}

/// `set_bitmask` flips `TypeShape::Enum::is_bitmask` and back, and `add_flag`'s explicit group
/// mask lands the same way `add_constant`'s implicit one does.
#[test]
fn type_enum_bitmask_edit() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::TypeShape;

        fn shape(idb: &Database, ty: &str) -> (bool, Vec<(String, u64)>) {
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
    });
}

/// `TypeEdit::set_repr` builds the same `value_repr_t` as `MemberEdit::set_repr`, but at the
/// whole-enum level (`tinfo_t::set_enum_repr`); `TypeShape::Enum::repr` reads it back.
#[test]
fn type_enum_repr_edit() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::{NumberFormat, TypeShape, ValueRepr};

        fn repr(idb: &Database, ty: &str) -> Option<ValueRepr> {
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
    });
}

/// `TypeEdit::set_enum_width` sets the enum's storage width (`tinfo_t::set_enum_width`); the new
/// width shows through the resolved `Type`'s own byte size.
#[test]
fn type_enum_width_edit() {
    crate::common::with_canonical_db(|idb| {
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
    });
}

/// `TypeEdit::add_constant_forced`/`ConstantEdit::rename_forced` (`ETF_FORCENAME`) force an enum
/// constant name through the alien-name collision (`TERR_ALIEN_NAME`) that the plain add/rename
/// paths reject when the name is already used by another enum.
#[test]
fn type_enum_forcename() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::{TypeEditCode, TypeShape, TypeWriteError};

        fn constants(idb: &Database, ty: &str) -> Vec<(String, u64)> {
            let t = idb.type_named(ty).expect("resolve the enum");
            match t.shape() {
                TypeShape::Enum { members, .. } => {
                    members.iter().map(|m| (m.name.clone(), m.value)).collect()
                }
                other => panic!("expected an enum, got {other:?}"),
            }
        }

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
        assert_type_write_err!(
            rejected,
            TypeWriteError::Rejected {
                code: TypeEditCode::AlienName,
                ..
            }
        );

        // add_constant_forced forces the same name through, and the constant actually lands.
        idb.types_mut()
            .edit("idakit_forcename_add")
            .add_constant_forced("IDAKIT_FORCENAME_TAKEN", 2)
            .expect("add_constant_forced should force the name through the collision");
        assert!(
            constants(idb, "idakit_forcename_add")
                .contains(&("IDAKIT_FORCENAME_TAKEN".to_owned(), 2)),
            "the forced constant should be present, got {:?}",
            constants(idb, "idakit_forcename_add")
        );

        // Plain rename rejects the same collision.
        let rejected = idb
            .types_mut()
            .edit("idakit_forcename_rename")
            .constant("IDAKIT_FORCENAME_MINE")
            .rename("IDAKIT_FORCENAME_TAKEN");
        assert_type_write_err!(
            rejected,
            TypeWriteError::Rejected {
                code: TypeEditCode::AlienName,
                ..
            }
        );

        // rename_forced forces it through, and the constant actually takes the new name.
        idb.types_mut()
            .edit("idakit_forcename_rename")
            .constant("IDAKIT_FORCENAME_MINE")
            .rename_forced("IDAKIT_FORCENAME_TAKEN")
            .expect("rename_forced should force the name through the collision");
        let names: Vec<String> = constants(idb, "idakit_forcename_rename")
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(
            names.iter().any(|n| n == "IDAKIT_FORCENAME_TAKEN")
                && !names.iter().any(|n| n == "IDAKIT_FORCENAME_MINE"),
            "the constant should be renamed through the collision, got {names:?}"
        );
    });
}

/// `TypeEdit::add_flag_forced` (`ETF_FORCENAME`) forces a masked flag's name through the alien-name
/// collision (`TERR_ALIEN_NAME`) that plain `add_flag` rejects, and the flag lands on the enum.
#[test]
fn type_enum_flag_forcename() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::{TypeEditCode, TypeShape, TypeWriteError};

        fn constants(idb: &Database, ty: &str) -> Vec<(String, u64)> {
            let t = idb.type_named(ty).expect("resolve the enum");
            match t.shape() {
                TypeShape::Enum { members, .. } => {
                    members.iter().map(|m| (m.name.clone(), m.value)).collect()
                }
                other => panic!("expected an enum, got {other:?}"),
            }
        }

        idb.types_mut()
            .define("enum idakit_flagforce_owner { IDAKIT_FLAGFORCE_TAKEN = 1 };")
            .expect("define the enum that owns the name");
        idb.types_mut()
            .define("enum idakit_flagforce_bits { IDAKIT_FLAGFORCE_RESERVED = 8 };")
            .expect("define a bitmask enum to add a colliding flag to");
        idb.types_mut()
            .edit("idakit_flagforce_bits")
            .set_bitmask(true)
            .expect("mark as a bitmask enum");

        // Plain add_flag rejects the cross-enum name collision.
        let rejected =
            idb.types_mut()
                .edit("idakit_flagforce_bits")
                .add_flag("IDAKIT_FLAGFORCE_TAKEN", 1, 1);
        assert_type_write_err!(
            rejected,
            TypeWriteError::Rejected {
                code: TypeEditCode::AlienName,
                ..
            }
        );

        // add_flag_forced forces the same name through, and the flag actually lands.
        idb.types_mut()
            .edit("idakit_flagforce_bits")
            .add_flag_forced("IDAKIT_FLAGFORCE_TAKEN", 1, 1)
            .expect("add_flag_forced should force the name through the collision");
        assert!(
            constants(idb, "idakit_flagforce_bits")
                .contains(&("IDAKIT_FLAGFORCE_TAKEN".to_owned(), 1)),
            "the forced flag should be present, got {:?}",
            constants(idb, "idakit_flagforce_bits")
        );
    });
}

/// `TypeEdit::delete_constant_by_value` deletes an enum constant keyed by its value rather than
/// its name; deleting a value no constant carries surfaces the typed `TypeEditCode::NotFound`.
#[test]
fn type_enum_delete_by_value() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::{TypeEditCode, TypeShape, TypeWriteError};

        fn constants(idb: &Database, ty: &str) -> Vec<(String, u64)> {
            let t = idb.type_named(ty).expect("resolve the enum");
            match t.shape() {
                TypeShape::Enum { members, .. } => {
                    members.iter().map(|m| (m.name.clone(), m.value)).collect()
                }
                other => panic!("expected an enum, got {other:?}"),
            }
        }

        idb.types_mut()
            .define("enum idakit_del_value_probe { PROBE_A = 1, PROBE_B = 2 };")
            .expect("define an enum to delete by value");

        idb.types_mut()
            .edit("idakit_del_value_probe")
            .delete_constant_by_value(1)
            .expect("delete the constant carrying value 1");
        let remaining = constants(idb, "idakit_del_value_probe");
        assert!(
            !remaining.iter().any(|(n, _)| n == "PROBE_A"),
            "PROBE_A should be gone, got {remaining:?}"
        );
        assert!(
            remaining.iter().any(|(n, v)| n == "PROBE_B" && *v == 2),
            "PROBE_B should remain, got {remaining:?}"
        );

        // A value no constant carries is a typed NotFound rejection, not a silent no-op.
        let ghost = idb
            .types_mut()
            .edit("idakit_del_value_probe")
            .delete_constant_by_value(999);
        assert_type_write_err!(
            ghost,
            TypeWriteError::Rejected {
                code: TypeEditCode::NotFound,
                ..
            }
        );
    });
}

/// Two constants sharing the same value stay distinct: duplicate *values* are legal C (only names
/// must be unique), so both read back with their own name and the shared value, never merged or
/// deduped away.
#[test]
fn type_enum_duplicate_values() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::TypeShape;

        idb.types_mut()
            .define("enum idakit_pcase_dup { PROBE_ONE = 1 };")
            .expect("define the enum");
        idb.types_mut()
            .edit("idakit_pcase_dup")
            .add_constant("PROBE_ALSO_ONE", 1)
            .expect("a duplicate value should be accepted");

        let ty = idb
            .type_named("idakit_pcase_dup")
            .expect("resolve the enum");
        assert!(let TypeShape::Enum { members, .. } = ty.shape());
        assert!(
            members
                .iter()
                .any(|m| m.name == "PROBE_ONE" && m.value == 1)
        );
        assert!(
            members
                .iter()
                .any(|m| m.name == "PROBE_ALSO_ONE" && m.value == 1)
        );
        assert!(
            members.len() == 2,
            "both constants should be kept distinct, not merged, got {members:?}"
        );
    });
}

/// The full `u64` range round-trips through a constant, including the two's-complement bit
/// pattern a negative signed value takes (`u64::MAX` is `-1i64`) and a near-max magnitude, going
/// straight through `add_constant`'s raw `u64` rather than a signed-literal declaration (whose
/// parser support for negative enumerators is not something this crate asserts on).
#[test]
fn type_enum_extreme_values() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::TypeShape;

        idb.types_mut()
            .define("enum idakit_pcase_extreme { PROBE_ZERO = 0 };")
            .expect("define the enum");
        idb.types_mut()
            .edit("idakit_pcase_extreme")
            .set_enum_width(8)
            .expect("widen to 8 bytes so the full u64 range is representable");
        idb.types_mut()
            .edit("idakit_pcase_extreme")
            .add_constant("PROBE_NEG_ONE", u64::MAX)
            .expect("the all-ones bit pattern should be accepted");
        idb.types_mut()
            .edit("idakit_pcase_extreme")
            .add_constant("PROBE_HUGE", u64::MAX - 1)
            .expect("a near-max value should be accepted");

        let ty = idb
            .type_named("idakit_pcase_extreme")
            .expect("resolve the enum");
        assert!(let TypeShape::Enum { members, .. } = ty.shape());
        assert!(
            members
                .iter()
                .any(|m| m.name == "PROBE_NEG_ONE" && m.value == u64::MAX)
        );
        assert!(
            members
                .iter()
                .any(|m| m.name == "PROBE_HUGE" && m.value == u64::MAX - 1)
        );
    });
}
