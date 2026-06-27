//! Operator kinds for expression nodes, grouped from `ctype_t`.
//!
//! Following `syn`'s `BinOp`/`UnOp` split, the ctree carries the operator as data on
//! a few structural node variants (`Binary`/`Unary`/`Assign`) rather than exploding
//! the ~50 arithmetic/logic ops into separate node kinds. Each enum is
//! `#[non_exhaustive]`: a future IDA SDK that adds an operator should widen these, not
//! break every downstream `match` (cf. the clang crate's `EntityKind`, which broke
//! across LLVM releases for exactly this reason).
//!
//! Discriminants are the raw `ctype_t` values from `hexrays.hpp` (IDA 9.3), so the
//! `IntoPrimitive`/`TryFromPrimitive` derives are the single source of truth for the
//! SDK mapping: `raw()` is a free cast and `from_raw()` lowers to a jump table. Signed
//! / unsigned / float variants are kept distinct because in decompiled code the
//! operator is what reveals operand signedness and domain (`Sdiv` vs `Udiv` vs `Fdiv`).

use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::VariantArray;

/// A binary value operator: `x OP y`.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive, VariantArray,
)]
#[repr(u16)]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
/// `from_raw()` naming (cf. [`Xref::from_raw`](crate::Xref)). The `$reject` text names
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

            // Single-line `concat!` keeps rustfmt idempotent — it re-indents a
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_matches_ctype_discriminants() {
        // Spot-check against hexrays.hpp values; these are the oracle.
        assert_eq!(BinOp::Add.raw(), 35);
        assert_eq!(BinOp::Sdiv.raw(), 38);
        assert_eq!(BinOp::Comma.raw(), 1);
        assert_eq!(BinOp::Fdiv.raw(), 45);
        assert_eq!(AssignOp::Assign.raw(), 2);
        assert_eq!(AssignOp::UmodAssign.raw(), 15);
        assert_eq!(UnOp::Neg.raw(), 47);
        assert_eq!(UnOp::PreDec.raw(), 56);
    }

    #[test]
    fn from_raw_rejects_other_groups() {
        // 2 = cot_asg (assignment), not a plain binary operator.
        assert_eq!(BinOp::from_raw(2), None);
        // 35 = cot_add (binary), not an assignment.
        assert_eq!(AssignOp::from_raw(35), None);
        // 48 = cot_cast, 51 = cot_ptr — excluded from the bare unary operators.
        assert_eq!(UnOp::from_raw(48), None);
        assert_eq!(UnOp::from_raw(51), None);
        // 0 = cot_empty is never an operator.
        assert_eq!(BinOp::from_raw(0), None);
    }
}
