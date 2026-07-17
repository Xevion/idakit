//! Operator kinds for expression nodes, grouped from the decompiler's raw operator tags.
//!
//! Following `syn`'s `BinaryOp`/`UnaryOp` split, the ctree carries the operator as data on
//! a few structural node variants (`Binary`/`Unary`/`Assign`) rather than exploding
//! the ~50 arithmetic/logic ops into separate node kinds.
//!
//! Discriminants are the raw operator-tag values IDA's decompiler assigns, so the
//! `IntoPrimitive`/`TryFromPrimitive` derives are the single source of truth for the
//! mapping, where `u16::from(op)` is a free cast and `Op::try_from(raw)` lowers to a jump
//! table. An operator outside the set rejects rather than folding into a catch-all; a new
//! tag in a later IDA version is a deliberate, breaking widening, since idakit pins to one
//! minor. Signed/unsigned/float variants are kept distinct because in decompiled code the
//! operator is what reveals operand signedness and domain (`Sdiv` vs `Udiv` vs `Fdiv`).

use std::fmt;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use strum::VariantArray;

/// A binary value operator, `x OP y`.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    IntoPrimitive,
    TryFromPrimitive,
    VariantArray,
    Serialize,
    Deserialize,
)]
#[repr(u16)]
#[doc(alias("ctype_t"))]
pub enum BinaryOp {
    /// `x, y`
    Comma = 1,
    /// `x || y`
    LogOr = 17,
    /// `x && y`
    LogAnd = 18,
    /// `x | y`
    BitOr = 19,
    /// `x ^ y`
    BitXor = 20,
    /// `x & y`
    BitAnd = 21,
    /// `x == y`
    Eq = 22,
    /// `x != y`
    Ne = 23,
    /// `x >= y` signed
    Sge = 24,
    /// `x >= y` unsigned
    Uge = 25,
    /// `x <= y` signed
    Sle = 26,
    /// `x <= y` unsigned
    Ule = 27,
    /// `x > y` signed
    Sgt = 28,
    /// `x > y` unsigned
    Ugt = 29,
    /// `x < y` signed
    Slt = 30,
    /// `x < y` unsigned
    Ult = 31,
    /// `x >> y` signed
    Sshr = 32,
    /// `x >> y` unsigned
    Ushr = 33,
    /// `x << y`
    Shl = 34,
    /// `x + y`
    Add = 35,
    /// `x - y`
    Sub = 36,
    /// `x * y`
    Mul = 37,
    /// `x / y` signed
    Sdiv = 38,
    /// `x / y` unsigned
    Udiv = 39,
    /// `x % y` signed
    Smod = 40,
    /// `x % y` unsigned
    Umod = 41,
    /// `x + y` floating-point
    Fadd = 42,
    /// `x - y` floating-point
    Fsub = 43,
    /// `x * y` floating-point
    Fmul = 44,
    /// `x / y` floating-point
    Fdiv = 45,
}

/// A compound-assignment operator, `x OP= y`. Plain `=` is [`AssignmentOp::Assign`].
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    IntoPrimitive,
    TryFromPrimitive,
    VariantArray,
    Serialize,
    Deserialize,
)]
#[repr(u16)]
#[doc(alias("ctype_t"))]
pub enum AssignmentOp {
    /// `x = y`
    Assign = 2,
    /// `x |= y`
    BitOrAssign = 3,
    /// `x ^= y`
    BitXorAssign = 4,
    /// `x &= y`
    BitAndAssign = 5,
    /// `x += y`
    AddAssign = 6,
    /// `x -= y`
    SubAssign = 7,
    /// `x *= y`
    MulAssign = 8,
    /// `x >>= y` signed
    SshrAssign = 9,
    /// `x >>= y` unsigned
    UshrAssign = 10,
    /// `x <<= y`
    ShlAssign = 11,
    /// `x /= y` signed
    SdivAssign = 12,
    /// `x /= y` unsigned
    UdivAssign = 13,
    /// `x %= y` signed
    SmodAssign = 14,
    /// `x %= y` unsigned
    UmodAssign = 15,
}

/// A unary operator, `OP x` (or `x OP` for post-inc/dec).
///
/// `(type)x`, `*x`, and `&x`-as-member are modeled as their own expression variants because they
/// carry a type, an access size, or a member offset; the operators here carry nothing extra.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    IntoPrimitive,
    TryFromPrimitive,
    VariantArray,
    Serialize,
    Deserialize,
)]
#[repr(u16)]
#[doc(alias("ctype_t"))]
pub enum UnaryOp {
    /// `-x` floating-point
    FNeg = 46,
    /// `-x`
    Neg = 47,
    /// `!x`
    LogNot = 49,
    /// `~x`
    BitNot = 50,
    /// `&x`
    Ref = 52,
    /// `x++`
    PostInc = 53,
    /// `x--`
    PostDec = 54,
    /// `++x`
    PreInc = 55,
    /// `--x`
    PreDec = 56,
}

impl BinaryOp {
    /// The C source spelling of this operator (`+`, `<<`, `&&`, ...). Signed/unsigned and
    /// integer/float variants that print the same collapse here (`Sdiv`/`Udiv`/`Fdiv` ->
    /// `/`); the distinction lives in the variant, not the glyph.
    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Comma => ",",
            Self::LogOr => "||",
            Self::LogAnd => "&&",
            Self::BitOr => "|",
            Self::BitXor => "^",
            Self::BitAnd => "&",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Sge | Self::Uge => ">=",
            Self::Sle | Self::Ule => "<=",
            Self::Sgt | Self::Ugt => ">",
            Self::Slt | Self::Ult => "<",
            Self::Sshr | Self::Ushr => ">>",
            Self::Shl => "<<",
            Self::Add | Self::Fadd => "+",
            Self::Sub | Self::Fsub => "-",
            Self::Mul | Self::Fmul => "*",
            Self::Sdiv | Self::Udiv | Self::Fdiv => "/",
            Self::Smod | Self::Umod => "%",
        }
    }
}

impl fmt::Display for BinaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.symbol())
    }
}

impl AssignmentOp {
    /// The C source spelling of this assignment (`=`, `+=`, `>>=`, ...).
    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Assign => "=",
            Self::BitOrAssign => "|=",
            Self::BitXorAssign => "^=",
            Self::BitAndAssign => "&=",
            Self::AddAssign => "+=",
            Self::SubAssign => "-=",
            Self::MulAssign => "*=",
            Self::SshrAssign | Self::UshrAssign => ">>=",
            Self::ShlAssign => "<<=",
            Self::SdivAssign | Self::UdivAssign => "/=",
            Self::SmodAssign | Self::UmodAssign => "%=",
        }
    }
}

impl fmt::Display for AssignmentOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.symbol())
    }
}

impl UnaryOp {
    /// The C source spelling of this operator (`-`, `!`, `~`, `&`, `++`, `--`). Pre- and
    /// post-increment share a glyph; position is the caller's concern, not this method's.
    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            Self::FNeg | Self::Neg => "-",
            Self::LogNot => "!",
            Self::BitNot => "~",
            Self::Ref => "&",
            Self::PreInc | Self::PostInc => "++",
            Self::PreDec | Self::PostDec => "--",
        }
    }
}

impl fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.symbol())
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use idakit_sys as sys;
    use rstest::rstest;

    use super::*;

    /// Spot-check raw discriminants against the decompiler's `ctype_t` values: the oracle
    /// the `IntoPrimitive` derive is supposed to reproduce.
    #[rstest]
    #[case(BinaryOp::Comma, 1)]
    #[case(BinaryOp::Add, 35)]
    #[case(BinaryOp::Sdiv, 38)]
    #[case(BinaryOp::Fdiv, 45)]
    fn binop_raw_matches_ctype(#[case] op: BinaryOp, #[case] raw: u16) {
        assert!(u16::from(op) == raw);
        // `From`/`TryFrom` round-trip within the group.
        assert!(BinaryOp::try_from(raw).ok() == Some(op));
    }

    #[rstest]
    #[case(AssignmentOp::Assign, 2)]
    #[case(AssignmentOp::UmodAssign, 15)]
    fn assignop_raw_matches_ctype(#[case] op: AssignmentOp, #[case] raw: u16) {
        assert!(u16::from(op) == raw);
        assert!(AssignmentOp::try_from(raw).ok() == Some(op));
    }

    #[rstest]
    #[case(UnaryOp::Neg, 47)]
    #[case(UnaryOp::PreDec, 56)]
    fn unop_raw_matches_ctype(#[case] op: UnaryOp, #[case] raw: u16) {
        assert!(u16::from(op) == raw);
        assert!(UnaryOp::try_from(raw).ok() == Some(op));
    }

    /// `try_from` is group-exclusive: a discriminant from another `ctype_t` group (or a
    /// non-operator) is rejected, never silently coerced.
    #[rstest]
    // 2 is the assignment tag, not a plain binary operator; 0 is the empty-expression tag.
    #[case::asg_is_not_binary(2)]
    #[case::empty_is_not_binary(0)]
    fn binop_rejects_non_binary(#[case] v: u16) {
        assert!(BinaryOp::try_from(v).is_err());
    }

    #[test]
    fn try_from_rejects_cross_group_discriminants() {
        // 35 is the add tag (binary), not an assignment.
        assert!(AssignmentOp::try_from(35).is_err());
        // 48 and 51 are the cast and pointer-deref tags, their own expression variants, not
        // bare unaries.
        assert!(UnaryOp::try_from(48).is_err());
        assert!(UnaryOp::try_from(51).is_err());
    }

    /// A few canonical glyphs, and the signed/unsigned/float collapse.
    #[rstest]
    #[case(BinaryOp::Add, "+")]
    #[case(BinaryOp::Fadd, "+")]
    #[case(BinaryOp::LogAnd, "&&")]
    #[case(BinaryOp::Shl, "<<")]
    #[case(BinaryOp::Sdiv, "/")]
    #[case(BinaryOp::Udiv, "/")]
    #[case(BinaryOp::Fdiv, "/")]
    fn binop_symbol(#[case] op: BinaryOp, #[case] sym: &str) {
        assert!(op.symbol() == sym);
    }

    #[rstest]
    #[case(AssignmentOp::Assign, "=")]
    #[case(AssignmentOp::SshrAssign, ">>=")]
    #[case(AssignmentOp::UshrAssign, ">>=")]
    fn assignop_symbol(#[case] op: AssignmentOp, #[case] sym: &str) {
        assert!(op.symbol() == sym);
    }

    #[rstest]
    #[case(UnaryOp::Neg, "-")]
    #[case(UnaryOp::FNeg, "-")]
    #[case(UnaryOp::PreInc, "++")]
    #[case(UnaryOp::PostInc, "++")]
    fn unop_symbol(#[case] op: UnaryOp, #[case] sym: &str) {
        assert!(op.symbol() == sym);
    }

    /// Completeness: every operator variant has a non-empty glyph. `VariantArray` makes
    /// the enum self-enumerating, so a new variant that forgets `symbol()` fails here
    /// rather than panicking on the `match`'s unreachable arm at runtime.
    #[test]
    fn every_variant_has_a_symbol() {
        for op in BinaryOp::VARIANTS {
            assert!(!op.symbol().is_empty());
        }
        for op in AssignmentOp::VARIANTS {
            assert!(!op.symbol().is_empty());
        }
        for op in UnaryOp::VARIANTS {
            assert!(!op.symbol().is_empty());
        }
    }

    /// `Display` renders the same glyph as `symbol()`, one representative case per group.
    #[test]
    fn display_matches_symbol() {
        assert!(BinaryOp::Add.to_string() == BinaryOp::Add.symbol());
        assert!(AssignmentOp::Assign.to_string() == AssignmentOp::Assign.symbol());
        assert!(UnaryOp::PreInc.to_string() == UnaryOp::PreInc.symbol());
    }

    /// Each operator group round-trips through JSON.
    #[test]
    fn serde_round_trips() {
        let json = serde_json::to_string(&BinaryOp::Sdiv).unwrap();
        assert!(serde_json::from_str::<BinaryOp>(&json).unwrap() == BinaryOp::Sdiv);

        let json = serde_json::to_string(&AssignmentOp::AddAssign).unwrap();
        assert!(serde_json::from_str::<AssignmentOp>(&json).unwrap() == AssignmentOp::AddAssign);

        let json = serde_json::to_string(&UnaryOp::LogNot).unwrap();
        assert!(serde_json::from_str::<UnaryOp>(&json).unwrap() == UnaryOp::LogNot);
    }

    /// Pin each group to the facade's reported `ctype_t` values: the facade lists each group in
    /// its enum's discriminant order, so a header renumbering (or a mistyped discriminant)
    /// mismatches, and a variant added without a facade entry trips the length check. Unlike
    /// [`every_variant_round_trips_through_its_discriminant`], which the `num_enum` derives
    /// satisfy by construction, this compares against the SDK itself. Pure constant source, no
    /// kernel, so it runs as a unit test.
    #[test]
    fn ctype_ids_align_with_the_facade() {
        fn check<T: Copy + fmt::Debug + Into<u16>>(name: &str, variants: &[T], ids: &[u32]) {
            assert!(
                ids.len() == variants.len(),
                "{name}: facade lists {} ids for {} variants",
                ids.len(),
                variants.len()
            );
            for (i, &op) in variants.iter().enumerate() {
                let raw = u32::from(op.into());
                assert!(
                    ids[i] == raw,
                    "{name} {op:?}: facade ctype_t {} != discriminant {raw}",
                    ids[i]
                );
            }
        }

        check("BinaryOp", BinaryOp::VARIANTS, &sys::binop_ctype_ids());
        check(
            "AssignmentOp",
            AssignmentOp::VARIANTS,
            &sys::assignop_ctype_ids(),
        );
        check("UnaryOp", UnaryOp::VARIANTS, &sys::unop_ctype_ids());
    }

    /// Completeness: every variant of every group round-trips through its own raw discriminant,
    /// so a `TryFrom` that stops agreeing with `Into` fails here. Both derives read one
    /// discriminant list, so this says nothing about whether that list matches the SDK;
    /// [`ctype_ids_align_with_the_facade`] is what pins it.
    #[test]
    fn every_variant_round_trips_through_its_discriminant() {
        for &op in BinaryOp::VARIANTS {
            assert!(BinaryOp::try_from(u16::from(op)).ok() == Some(op));
        }
        for &op in AssignmentOp::VARIANTS {
            assert!(AssignmentOp::try_from(u16::from(op)).ok() == Some(op));
        }
        for &op in UnaryOp::VARIANTS {
            assert!(UnaryOp::try_from(u16::from(op)).ok() == Some(op));
        }
    }

    mod proptests {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            /// The three operator groups partition disjoint slices of the raw `ctype_t` space:
            /// no raw value should ever parse as more than one group's operator.
            #[test]
            fn discriminant_groups_are_mutually_exclusive(raw in any::<u16>()) {
                let matches = [
                    BinaryOp::try_from(raw).is_ok(),
                    AssignmentOp::try_from(raw).is_ok(),
                    UnaryOp::try_from(raw).is_ok(),
                ]
                .into_iter()
                .filter(|&m| m)
                .count();
                prop_assert!(matches <= 1, "raw {raw} matched {matches} operator groups");
            }

            /// Any raw value that does parse round-trips back to itself through `u16::from`.
            #[test]
            fn successful_round_trip_preserves_the_raw_value(raw in any::<u16>()) {
                if let Ok(op) = BinaryOp::try_from(raw) {
                    prop_assert_eq!(u16::from(op), raw);
                }
                if let Ok(op) = AssignmentOp::try_from(raw) {
                    prop_assert_eq!(u16::from(op), raw);
                }
                if let Ok(op) = UnaryOp::try_from(raw) {
                    prop_assert_eq!(u16::from(op), raw);
                }
            }
        }
    }
}
