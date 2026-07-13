//! Type-write result codes and recipe opcodes shared with the generated type-build bridge.
//!
//! [`SigWriteCode`] and [`TypeApplyCode`] pin idakit's decode of the generated bridge's
//! `TypeWriteResult.code`/`SigWriteResult.code` to the values the generated C++
//! (`gen_type_build.cc`) emits; the two sides are kept aligned by hand. Each is a facade sentinel,
//! not a raw SDK value, and each call site validates with `TryFrom` rather than matching a bare
//! `c_int`, so a drifted or unmodelled code is a typed rejection instead of a silent fallthrough.

use std::ffi::c_int;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::VariantArray;

/// The outcome of a signature-surgery call (`func_set_rettype`, `func_set_argtype`,
/// `func_rename_arg`, `func_set_cc`, `func_prepend_this`).
///
/// The complete closed set those calls return: `rebuild_and_apply` and the pre-failure checks
/// ahead of it never leak a raw `tinfo_code_t`, unlike the til member-edit codes (see
/// [`IDAKIT_TEDIT_NO_TYPE`]).
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Debug, TryFromPrimitive, IntoPrimitive, VariantArray,
)]
#[repr(i32)]
#[doc(alias(
    "IDAKIT_SIG_OK",
    "IDAKIT_SIG_NO_PROTOTYPE",
    "IDAKIT_SIG_ARG_RANGE",
    "IDAKIT_SIG_BUILD",
    "IDAKIT_SIG_APPLY"
))]
pub enum SigWriteCode {
    /// A prototype-surgery edit succeeded (`IDAKIT_SIG_OK`).
    Ok = 0,
    /// The address carries no function type to edit (`IDAKIT_SIG_NO_PROTOTYPE`).
    NoPrototype = 1,
    /// A parameter index was past the last parameter (`IDAKIT_SIG_ARG_RANGE`).
    ArgRange = 2,
    /// A replacement-type recipe did not build (`IDAKIT_SIG_BUILD`).
    Build = 3,
    /// `create_func` or `apply_tinfo` rejected the rebuilt signature (`IDAKIT_SIG_APPLY`).
    Apply = 4,
}

/// Member-edit pre-failure: no such named type in the local til. A positive sentinel; a successful
/// edit is 0 and a kernel rejection is a negative `tinfo_code_t`.
///
/// `IDAKIT_TEDIT_NO_TYPE`/`NO_MEMBER`/`BUILD` stay plain consts rather than an enum: the codes a
/// til member/constant edit returns are these three sentinels *or* any raw `tinfo_code_t`
/// (mirrored in full by `idakit::types::TypeEditCode`), so no standalone closed set exists to
/// model in isolation here.
pub const IDAKIT_TEDIT_NO_TYPE: c_int = 1;
/// Member-edit pre-failure: the member (by name or bit offset) did not resolve.
pub const IDAKIT_TEDIT_NO_MEMBER: c_int = 2;
/// Member-edit pre-failure: a member-type recipe did not build.
pub const IDAKIT_TEDIT_BUILD: c_int = 3;
/// `member_bit` value that appends a new member at the end rather than a fixed offset.
pub const IDAKIT_MEMBER_APPEND: u64 = u64::MAX;

/// The outcome of a whole-item type apply (`apply_type_decl`, `apply_named_type`, `clear_type`,
/// `apply_type_recipe`, `tinfo_apply`).
///
/// The complete closed set those calls return: none of them ever forward a raw `tinfo_code_t`.
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Debug, TryFromPrimitive, IntoPrimitive, VariantArray,
)]
#[repr(i32)]
#[doc(alias("IDAKIT_TYPE_OK", "IDAKIT_TYPE_ERR_INPUT", "IDAKIT_TYPE_ERR_APPLY"))]
pub enum TypeApplyCode {
    /// Result of a successful type apply (`IDAKIT_TYPE_OK`).
    Ok = 0,
    /// A bad input to a type apply: an unparseable declaration, a named type that does not exist,
    /// or a malformed recipe (`IDAKIT_TYPE_ERR_INPUT`).
    ErrInput = 1,
    /// `apply_tinfo` rejected the parsed/resolved/built type at the address
    /// (`IDAKIT_TYPE_ERR_APPLY`).
    ErrApply = 2,
}

/// Recipe opcode: push the `void` type. Kept in lockstep with `idakit_facade.h` by hand.
pub const IDAKIT_RECIPE_VOID: u8 = 0;
/// Recipe opcode: push the boolean type.
pub const IDAKIT_RECIPE_BOOL: u8 = 1;
/// Recipe opcode: push an integer, followed by a `u8` width in bytes and a `u8` signedness flag.
pub const IDAKIT_RECIPE_INT: u8 = 2;
/// Recipe opcode: push a float, followed by a `u8` width in bytes.
pub const IDAKIT_RECIPE_FLOAT: u8 = 3;
/// Recipe opcode: push a named-type reference, followed by a `u32` length and that many name bytes.
pub const IDAKIT_RECIPE_NAMED: u8 = 4;
/// Recipe opcode: push a parsed declaration, followed by a `u32` length and that many decl bytes.
pub const IDAKIT_RECIPE_DECL: u8 = 5;
/// Recipe opcode: pop one type, push a pointer to it.
pub const IDAKIT_RECIPE_PTR: u8 = 6;
/// Recipe opcode: pop one type, push an array of it, followed by a `u64` element count.
pub const IDAKIT_RECIPE_ARRAY: u8 = 7;
/// Recipe opcode: pop one type, push its `const`-qualified form.
pub const IDAKIT_RECIPE_CONST: u8 = 8;
/// Recipe opcode: pop one type, push its `volatile`-qualified form.
pub const IDAKIT_RECIPE_VOLATILE: u8 = 9;
/// Recipe opcode: build a function type.
///
/// Followed by a `u32` parameter count, a `u8` varargs flag, a `u16` calling convention (0 =
/// default), then that many `u32`-length-prefixed parameter names; pops the parameter types then
/// the return type (return pushed first) and pushes the function.
pub const IDAKIT_RECIPE_FUNCTION: u8 = 10;
/// Recipe opcode: build a bitfield member type.
///
/// Followed by a `u8` container width in bytes, a `u8` field width in bits, and a `u8`
/// signedness flag. Valid only as a struct member; the kernel rejects a bitfield in a union.
pub const IDAKIT_RECIPE_BITFIELD: u8 = 11;

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    /// Every `SigWriteCode` variant round-trips its raw `IDAKIT_SIG_*` value, so a drifted
    /// discriminant fails here rather than silently misreading the facade.
    #[test]
    fn sig_write_code_round_trips() {
        for &code in SigWriteCode::VARIANTS {
            assert!(SigWriteCode::try_from(i32::from(code)) == Ok(code));
        }
        assert!(SigWriteCode::try_from(5).is_err());
    }

    #[rstest]
    #[case(SigWriteCode::Ok, 0)]
    #[case(SigWriteCode::NoPrototype, 1)]
    #[case(SigWriteCode::ArgRange, 2)]
    #[case(SigWriteCode::Build, 3)]
    #[case(SigWriteCode::Apply, 4)]
    fn sig_write_code_pins_the_facade_value(#[case] code: SigWriteCode, #[case] raw: i32) {
        assert!(i32::from(code) == raw);
    }

    /// Every `TypeApplyCode` variant round-trips its raw `IDAKIT_TYPE_*` value.
    #[test]
    fn type_apply_code_round_trips() {
        for &code in TypeApplyCode::VARIANTS {
            assert!(TypeApplyCode::try_from(i32::from(code)) == Ok(code));
        }
        assert!(TypeApplyCode::try_from(3).is_err());
    }

    #[rstest]
    #[case(TypeApplyCode::Ok, 0)]
    #[case(TypeApplyCode::ErrInput, 1)]
    #[case(TypeApplyCode::ErrApply, 2)]
    fn type_apply_code_pins_the_facade_value(#[case] code: TypeApplyCode, #[case] raw: i32) {
        assert!(i32::from(code) == raw);
    }
}
