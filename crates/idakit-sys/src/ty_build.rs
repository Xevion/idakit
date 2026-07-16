//! Type-write result codes shared with the generated type-build bridge.
//!
//! [`SigWriteCode`] and [`TypeApplyCode`] pin idakit's decode of the generated bridge's
//! `TypeWriteResult.code`/`SigWriteResult.code` to the values `idakit-sys-codegen`'s `type_build`
//! domain spec generates (`crate::SIG_*`/`crate::TYPE_*`). Each is a facade sentinel, not a raw SDK
//! value, and each call site validates with `TryFrom` rather than matching a bare `c_int`, so a
//! drifted or unmodelled code is a typed rejection instead of a silent fallthrough. The member-edit
//! pre-failure sentinels (`TEDIT_*`) and the recipe opcodes (`RECIPE_*`) are generated consts too;
//! see `crate::TEDIT_NO_TYPE` and `crate::RECIPE_VOID` and siblings.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::VariantArray;

/// The outcome of a signature-surgery call (`func_set_rettype`, `func_set_argtype`,
/// `func_rename_arg`, `func_set_cc`, `func_prepend_this`).
///
/// The complete closed set those calls return: `rebuild_and_apply` and the pre-failure checks
/// ahead of it never leak a raw `tinfo_code_t`, unlike the til member-edit codes (see
/// [`crate::TEDIT_NO_TYPE`]).
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Debug, TryFromPrimitive, IntoPrimitive, VariantArray,
)]
#[repr(i32)]
pub enum SigWriteCode {
    /// A prototype-surgery edit succeeded.
    Ok = 0,
    /// The address carries no function type to edit.
    NoPrototype = 1,
    /// A parameter index was past the last parameter.
    ArgRange = 2,
    /// A replacement-type recipe did not build.
    Build = 3,
    /// `create_func` or `apply_tinfo` rejected the rebuilt signature.
    Apply = 4,
}

/// The outcome of a whole-item type apply (`apply_type_decl`, `apply_named_type`, `clear_type`,
/// `apply_type_recipe`, `tinfo_apply`).
///
/// The complete closed set those calls return: none of them ever forward a raw `tinfo_code_t`.
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Debug, TryFromPrimitive, IntoPrimitive, VariantArray,
)]
#[repr(i32)]
pub enum TypeApplyCode {
    /// Result of a successful type apply.
    Ok = 0,
    /// A bad input to a type apply: an unparseable declaration, a named type that does not exist,
    /// or a malformed recipe.
    ErrInput = 1,
    /// `apply_tinfo` rejected the parsed/resolved/built type at the address.
    ErrApply = 2,
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    /// Every `SigWriteCode` variant round-trips its raw value, so a drifted discriminant fails
    /// here rather than silently misreading the facade.
    #[test]
    fn sig_write_code_round_trips() {
        for &code in SigWriteCode::VARIANTS {
            assert!(SigWriteCode::try_from(i32::from(code)) == Ok(code));
        }
    }

    /// A code past the last modelled `SigWriteCode` variant is rejected, not absorbed.
    #[rstest]
    #[case::just_past_the_set(5)]
    #[case::far_past_the_set(100)]
    #[case::negative(-1)]
    #[case::i32_min(i32::MIN)]
    #[case::i32_max(i32::MAX)]
    fn sig_write_code_rejects_values_outside_the_set(#[case] raw: i32) {
        assert!(SigWriteCode::try_from(raw).is_err());
    }

    /// Each variant's discriminant matches the generated `crate::SIG_*` const, a real drift check
    /// between the hand-written enum and the single-sourced facade value.
    #[rstest]
    #[case::ok(SigWriteCode::Ok, crate::SIG_OK)]
    #[case::no_prototype(SigWriteCode::NoPrototype, crate::SIG_NO_PROTOTYPE)]
    #[case::arg_range(SigWriteCode::ArgRange, crate::SIG_ARG_RANGE)]
    #[case::build(SigWriteCode::Build, crate::SIG_BUILD)]
    #[case::apply(SigWriteCode::Apply, crate::SIG_APPLY)]
    fn sig_write_code_pins_the_generated_facade_values(
        #[case] code: SigWriteCode,
        #[case] raw: i32,
    ) {
        assert!(i32::from(code) == raw);
    }

    /// Every `TypeApplyCode` variant round-trips its raw value.
    #[test]
    fn type_apply_code_round_trips() {
        for &code in TypeApplyCode::VARIANTS {
            assert!(TypeApplyCode::try_from(i32::from(code)) == Ok(code));
        }
    }

    /// A code past the last modelled `TypeApplyCode` variant is rejected, not absorbed.
    #[rstest]
    #[case::just_past_the_set(3)]
    #[case::far_past_the_set(100)]
    #[case::negative(-1)]
    #[case::i32_min(i32::MIN)]
    #[case::i32_max(i32::MAX)]
    fn type_apply_code_rejects_values_outside_the_set(#[case] raw: i32) {
        assert!(TypeApplyCode::try_from(raw).is_err());
    }

    /// Each variant's discriminant matches the generated `crate::TYPE_*` const.
    #[rstest]
    #[case::ok(TypeApplyCode::Ok, crate::TYPE_OK)]
    #[case::err_input(TypeApplyCode::ErrInput, crate::TYPE_ERR_INPUT)]
    #[case::err_apply(TypeApplyCode::ErrApply, crate::TYPE_ERR_APPLY)]
    fn type_apply_code_pins_the_generated_facade_values(
        #[case] code: TypeApplyCode,
        #[case] raw: i32,
    ) {
        assert!(i32::from(code) == raw);
    }
}
