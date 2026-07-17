//! [`ValueRepr`], a struct/union member's or enum's value representation.
//!
//! An invented, closed subset of IDA's `value_repr_t` (`typeinf.hpp`): the bit-packed struct
//! carries a value-type nibble (`FRB_*`) plus flag bits, and several of its value types (enum-
//! linked, offset, string-literal, struct-offset, custom, float, segment) need extra union
//! payload `value_repr_t` carries alongside the nibble. [`NumberFormat`] models only the
//! non-info-carrying subset (binary/octal/hexadecimal/decimal/char); a member or enum using one
//! of the unmodeled forms reads back as `None` from `TypeMember::repr`/`TypeShape::Enum::repr`
//! rather than a mislabeled variant.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use strum::VariantArray;

/// How a struct/union member's numeric value displays.
///
/// The non-info-carrying subset of `value_repr_t`'s value-type nibble (`FRB_*`, `typeinf.hpp`).
/// The nibble never crosses the public API; it is folded into
/// [`MemberEdit::set_repr`](crate::types::MemberEdit::set_repr) and read back from
/// `TypeMember::repr` (`crate::types::TypeMember::repr`). A nibble outside this subset is
/// rejected by [`TryFrom`], not absorbed into a catch-all.
// raw FRB_* values from typeinf.hpp (IDA 9.3)
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    IntoPrimitive,
    TryFromPrimitive,
    VariantArray,
)]
#[repr(u32)]
pub enum NumberFormat {
    /// Binary.
    Binary = 0x1,
    /// Octal.
    Octal = 0x2,
    /// Hexadecimal.
    Hexadecimal = 0x3,
    /// Decimal.
    Decimal = 0x4,
    /// Char.
    Char = 0x6,
}

/// A struct/union member's or enum's value representation: radix or char format, forced sign,
/// and leading zeros.
///
/// Read from `TypeMember::repr` (`crate::types::TypeMember::repr`) or `TypeShape::Enum::repr`
/// (`crate::types::TypeShape::Enum`), and written through
/// [`MemberEdit::set_repr`](crate::types::MemberEdit::set_repr) or
/// [`TypeEdit::set_repr`](crate::types::TypeEdit::set_repr). Models only the numeric subset of
/// `value_repr_t`; the info-carrying forms are out of scope. See the module docs.
///
/// ```
/// use idakit::types::{NumberFormat, ValueRepr};
///
/// let repr = ValueRepr {
///     format: NumberFormat::Hexadecimal,
///     signed: true,
///     leading_zeros: false,
/// };
/// assert_eq!(repr.format, NumberFormat::Hexadecimal);
/// assert!(repr.signed);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[doc(alias("value_repr_t"))]
pub struct ValueRepr {
    /// The display format.
    pub format: NumberFormat,
    /// Force a signed display (`FRB_SIGNED`).
    pub signed: bool,
    /// Show leading zeros (`FRB_LZERO`).
    pub leading_zeros: bool,
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    /// Every variant round-trips through its FRB nibble, and the nibble is pinned to the SDK's
    /// literal `FRB_*` value (`typeinf.hpp`).
    #[rstest]
    #[case(NumberFormat::Binary, 0x1)]
    #[case(NumberFormat::Octal, 0x2)]
    #[case(NumberFormat::Hexadecimal, 0x3)]
    #[case(NumberFormat::Decimal, 0x4)]
    #[case(NumberFormat::Char, 0x6)]
    fn number_format_round_trips_and_pins_frb(#[case] format: NumberFormat, #[case] frb: u32) {
        assert!(u32::from(format) == frb);
        assert!(NumberFormat::try_from(frb) == Ok(format));
    }

    /// Completeness: every variant round-trips through its nibble, so a drifted discriminant
    /// fails here rather than silently writing the wrong `value_repr_t`.
    #[test]
    fn every_variant_round_trips() {
        for &format in NumberFormat::VARIANTS {
            assert!(NumberFormat::try_from(u32::from(format)) == Ok(format));
        }
    }

    /// A nibble outside the modeled numeric subset (unknown, or an info-carrying/float/segment
    /// form) is rejected, not absorbed.
    #[rstest]
    #[case::unk(0x0)]
    #[case::float(0x5)]
    #[case::seg(0x7)]
    #[case::enum_linked(0x8)]
    #[case::out_of_range(0xff)]
    fn try_from_rejects_unmodeled(#[case] vtype: u32) {
        assert!(NumberFormat::try_from(vtype).is_err());
    }
}
