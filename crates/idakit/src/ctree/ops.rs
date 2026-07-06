//! Operator kinds for expression nodes, grouped from `ctype_t`.
//!
//! Following `syn`'s `BinOp`/`UnOp` split, the ctree carries the operator as data on
//! a few structural node variants (`Binary`/`Unary`/`Assign`) rather than exploding
//! the ~50 arithmetic/logic ops into separate node kinds.
//!
//! Discriminants are the raw `ctype_t` values from `hexrays.hpp` (IDA 9.3), so the
//! `IntoPrimitive`/`TryFromPrimitive` derives are the single source of truth for the
//! SDK mapping: `raw()` is a free cast and `from_raw()` lowers to a jump table. An operator
//! outside the set rejects rather than folding into a catch-all; a new `ctype_t` in a later
//! IDA is a deliberate, breaking widening, since idakit pins to one minor. Signed / unsigned
//! / float variants are kept distinct because in decompiled code the operator is what reveals
//! operand signedness and domain (`Sdiv` vs `Udiv` vs `Fdiv`).

use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::VariantArray;

/// A binary value operator: `x OP y`.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive, VariantArray,
)]
#[repr(u16)]
pub enum BinOp {
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

/// A compound-assignment operator: `x OP= y`. Plain `=` is [`AssignOp::Assign`].
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive, VariantArray,
)]
#[repr(u16)]
pub enum AssignOp {
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

/// A unary operator: `OP x` (or `x OP` for post-inc/dec). `(type)x`, `*x`, and
/// `&x`-as-member are modeled as their own expression variants because they carry a
/// type, an access size, or a member offset; the operators here carry nothing extra.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive, VariantArray,
)]
#[repr(u16)]
pub enum UnOp {
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

/// Wraps the derived `From<Self> for u16` / `TryFrom<u16>` in the crate's `raw()` /
/// `from_raw()` naming (cf. [`Reference::from_raw`](crate::Reference)). The `$reject` text names
/// what falls outside this group so each `from_raw` doc explains its own gaps.
macro_rules! ctype_op {
    ($ty:ident, $reject:literal) => {
        impl $ty {
            /// The raw `ctype_t` discriminant.
            #[inline]
            #[must_use]
            pub fn raw(self) -> u16 {
                self.into()
            }

            // Single-line `concat!` keeps rustfmt idempotent -- it re-indents a
            // multi-line `concat!` in a macro body deeper on every run.
            #[doc = concat!("The operator for a raw `ctype_t`, or `None` if it is not ", $reject, ".")]
            #[must_use]
            pub fn from_raw(v: u16) -> Option<Self> {
                Self::try_from(v).ok()
            }
        }
    };
}

ctype_op!(BinOp, "a binary operator");
ctype_op!(AssignOp, "an assignment");
ctype_op!(
    UnOp,
    "one of the bare unary operators (cast, deref, and member-of are their own \
     expression variants)"
);

impl BinOp {
    /// The C source spelling of this operator (`+`, `<<`, `&&`, ...). Signed/unsigned and
    /// integer/float variants that print the same collapse here (`Sdiv`/`Udiv`/`Fdiv` ->
    /// `/`); the distinction lives in the variant, not the glyph.
    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            BinOp::Comma => ",",
            BinOp::LogOr => "||",
            BinOp::LogAnd => "&&",
            BinOp::BitOr => "|",
            BinOp::BitXor => "^",
            BinOp::BitAnd => "&",
            BinOp::Eq => "==",
            BinOp::Ne => "!=",
            BinOp::Sge | BinOp::Uge => ">=",
            BinOp::Sle | BinOp::Ule => "<=",
            BinOp::Sgt | BinOp::Ugt => ">",
            BinOp::Slt | BinOp::Ult => "<",
            BinOp::Sshr | BinOp::Ushr => ">>",
            BinOp::Shl => "<<",
            BinOp::Add | BinOp::Fadd => "+",
            BinOp::Sub | BinOp::Fsub => "-",
            BinOp::Mul | BinOp::Fmul => "*",
            BinOp::Sdiv | BinOp::Udiv | BinOp::Fdiv => "/",
            BinOp::Smod | BinOp::Umod => "%",
        }
    }
}

impl AssignOp {
    /// The C source spelling of this assignment (`=`, `+=`, `>>=`, ...).
    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            AssignOp::Assign => "=",
            AssignOp::BitOrAssign => "|=",
            AssignOp::BitXorAssign => "^=",
            AssignOp::BitAndAssign => "&=",
            AssignOp::AddAssign => "+=",
            AssignOp::SubAssign => "-=",
            AssignOp::MulAssign => "*=",
            AssignOp::SshrAssign | AssignOp::UshrAssign => ">>=",
            AssignOp::ShlAssign => "<<=",
            AssignOp::SdivAssign | AssignOp::UdivAssign => "/=",
            AssignOp::SmodAssign | AssignOp::UmodAssign => "%=",
        }
    }
}

impl UnOp {
    /// The C source spelling of this operator (`-`, `!`, `~`, `&`, `++`, `--`). Pre- and
    /// post-increment share a glyph; position is the caller's concern, not this method's.
    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            UnOp::FNeg | UnOp::Neg => "-",
            UnOp::LogNot => "!",
            UnOp::BitNot => "~",
            UnOp::Ref => "&",
            UnOp::PreInc | UnOp::PostInc => "++",
            UnOp::PreDec | UnOp::PostDec => "--",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::assert;
    use rstest::rstest;

    /// Spot-check raw discriminants against `hexrays.hpp` (IDA 9.3) values -- the oracle
    /// the `IntoPrimitive` derive is supposed to reproduce.
    #[rstest]
    #[case(BinOp::Comma, 1)]
    #[case(BinOp::Add, 35)]
    #[case(BinOp::Sdiv, 38)]
    #[case(BinOp::Fdiv, 45)]
    fn binop_raw_matches_ctype(#[case] op: BinOp, #[case] raw: u16) {
        assert!(op.raw() == raw);
        // `raw`/`from_raw` round-trip within the group.
        assert!(BinOp::from_raw(raw) == Some(op));
    }

    #[rstest]
    #[case(AssignOp::Assign, 2)]
    #[case(AssignOp::UmodAssign, 15)]
    fn assignop_raw_matches_ctype(#[case] op: AssignOp, #[case] raw: u16) {
        assert!(op.raw() == raw);
        assert!(AssignOp::from_raw(raw) == Some(op));
    }

    #[rstest]
    #[case(UnOp::Neg, 47)]
    #[case(UnOp::PreDec, 56)]
    fn unop_raw_matches_ctype(#[case] op: UnOp, #[case] raw: u16) {
        assert!(op.raw() == raw);
        assert!(UnOp::from_raw(raw) == Some(op));
    }

    /// `from_raw` is group-exclusive: a discriminant from another `ctype_t` group (or a
    /// non-operator) is rejected, never silently coerced.
    #[rstest]
    // 2 = cot_asg (assignment), not a plain binary operator; 0 = cot_empty.
    #[case::asg_is_not_binary(2)]
    #[case::empty_is_not_binary(0)]
    fn binop_from_raw_rejects_non_binary(#[case] v: u16) {
        assert!(let None = BinOp::from_raw(v));
    }

    #[test]
    fn from_raw_rejects_cross_group_discriminants() {
        // 35 = cot_add (binary), not an assignment.
        assert!(let None = AssignOp::from_raw(35));
        // 48 = cot_cast, 51 = cot_ptr -- their own expression variants, not bare unaries.
        assert!(let None = UnOp::from_raw(48));
        assert!(let None = UnOp::from_raw(51));
    }

    /// A few canonical glyphs, and the signed/unsigned/float collapse.
    #[rstest]
    #[case(BinOp::Add, "+")]
    #[case(BinOp::Fadd, "+")]
    #[case(BinOp::LogAnd, "&&")]
    #[case(BinOp::Shl, "<<")]
    #[case(BinOp::Sdiv, "/")]
    #[case(BinOp::Udiv, "/")]
    #[case(BinOp::Fdiv, "/")]
    fn binop_symbol(#[case] op: BinOp, #[case] sym: &str) {
        assert!(op.symbol() == sym);
    }

    #[rstest]
    #[case(AssignOp::Assign, "=")]
    #[case(AssignOp::SshrAssign, ">>=")]
    #[case(AssignOp::UshrAssign, ">>=")]
    fn assignop_symbol(#[case] op: AssignOp, #[case] sym: &str) {
        assert!(op.symbol() == sym);
    }

    #[rstest]
    #[case(UnOp::Neg, "-")]
    #[case(UnOp::FNeg, "-")]
    #[case(UnOp::PreInc, "++")]
    #[case(UnOp::PostInc, "++")]
    fn unop_symbol(#[case] op: UnOp, #[case] sym: &str) {
        assert!(op.symbol() == sym);
    }

    /// Completeness: every operator variant has a non-empty glyph. `VariantArray` makes
    /// the enum self-enumerating, so a new variant that forgets `symbol()` fails here
    /// rather than panicking on the `match`'s unreachable arm at runtime.
    #[test]
    fn every_variant_has_a_symbol() {
        for op in BinOp::VARIANTS {
            assert!(!op.symbol().is_empty());
        }
        for op in AssignOp::VARIANTS {
            assert!(!op.symbol().is_empty());
        }
        for op in UnOp::VARIANTS {
            assert!(!op.symbol().is_empty());
        }
    }
}
