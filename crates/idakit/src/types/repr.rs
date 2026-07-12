//! [`MemberRepr`], a struct/union member's value representation.
//!
//! An invented, closed subset of IDA's `value_repr_t` (`typeinf.hpp`): the bit-packed struct
//! carries a value-type nibble (`FRB_*`) plus flag bits, and several of its value types (enum-
//! linked, offset, string-literal, struct-offset, custom, float, segment) need extra union
//! payload `value_repr_t` carries alongside the nibble. [`NumberFormat`] models only the
//! non-info-carrying subset (binary/octal/hexadecimal/decimal/char); a member using one of the
//! unmodeled forms reads back as `None` from `TypeMember::repr` rather than a mislabeled variant.

/// How a struct/union member's numeric value displays.
///
/// The non-info-carrying subset of `value_repr_t`'s value-type nibble (`FRB_*`, `typeinf.hpp`).
/// The nibble never crosses the public API; it is folded into
/// [`MemberEdit::set_repr`](crate::types::MemberEdit::set_repr) and read back from
/// `TypeMember::repr` (`crate::types::TypeMember::repr`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NumberFormat {
    /// Binary.
    Binary,
    /// Octal.
    Octal,
    /// Hexadecimal.
    Hexadecimal,
    /// Decimal.
    Decimal,
    /// Char.
    Char,
}

/// Raw `value_repr_t::FRB_*` value-type nibbles (typeinf.hpp, IDA 9.3). Crate-private: the facade
/// boundary is the only place a nibble crosses, and [`NumberFormat`] never exposes it publicly.
const FRB_NUMB: u32 = 0x1;
const FRB_NUMO: u32 = 0x2;
const FRB_NUMH: u32 = 0x3;
const FRB_NUMD: u32 = 0x4;
const FRB_CHAR: u32 = 0x6;

impl NumberFormat {
    /// The `value_repr_t` FRB_* nibble this format writes.
    #[inline]
    pub(crate) const fn to_frb(self) -> u32 {
        match self {
            Self::Binary => FRB_NUMB,
            Self::Octal => FRB_NUMO,
            Self::Hexadecimal => FRB_NUMH,
            Self::Decimal => FRB_NUMD,
            Self::Char => FRB_CHAR,
        }
    }

    /// The format for a raw FRB_* nibble, or `None` outside the modeled numeric subset
    /// (`FRB_UNK`, or an info-carrying/float/segment nibble idakit does not model).
    #[inline]
    pub(crate) const fn from_frb(vtype: u32) -> Option<Self> {
        Some(match vtype {
            FRB_NUMB => Self::Binary,
            FRB_NUMO => Self::Octal,
            FRB_NUMH => Self::Hexadecimal,
            FRB_NUMD => Self::Decimal,
            FRB_CHAR => Self::Char,
            _ => return None,
        })
    }
}

/// A struct/union member's value representation: radix or char format, forced sign, and leading
/// zeros.
///
/// Read from `TypeMember::repr` (`crate::types::TypeMember::repr`) or written through
/// [`MemberEdit::set_repr`](crate::types::MemberEdit::set_repr). Models only the numeric subset
/// of `value_repr_t`; the info-carrying forms are out of scope. See the module docs.
///
/// ```
/// use idakit::types::{MemberRepr, NumberFormat};
///
/// let repr = MemberRepr {
///     format: NumberFormat::Hexadecimal,
///     signed: true,
///     leading_zeros: false,
/// };
/// assert_eq!(repr.format, NumberFormat::Hexadecimal);
/// assert!(repr.signed);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(alias("value_repr_t"))]
pub struct MemberRepr {
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

    use super::*;

    const ALL: [NumberFormat; 5] = [
        NumberFormat::Binary,
        NumberFormat::Octal,
        NumberFormat::Hexadecimal,
        NumberFormat::Decimal,
        NumberFormat::Char,
    ];

    /// Every variant round-trips through its FRB nibble.
    #[test]
    fn number_format_round_trips() {
        for &f in &ALL {
            assert!(NumberFormat::from_frb(f.to_frb()) == Some(f));
        }
    }

    /// The nibbles are pinned to the SDK's literal `FRB_*` values (`typeinf.hpp`).
    #[test]
    fn number_format_pins_frb_values() {
        assert!(NumberFormat::Binary.to_frb() == 0x1);
        assert!(NumberFormat::Octal.to_frb() == 0x2);
        assert!(NumberFormat::Hexadecimal.to_frb() == 0x3);
        assert!(NumberFormat::Decimal.to_frb() == 0x4);
        assert!(NumberFormat::Char.to_frb() == 0x6);
    }

    /// A nibble outside the modeled numeric subset (unknown, or an info-carrying/float/segment
    /// form) is rejected, not absorbed.
    #[test]
    fn from_frb_rejects_unmodeled() {
        assert!(NumberFormat::from_frb(0x0).is_none()); // FRB_UNK
        assert!(NumberFormat::from_frb(0x5).is_none()); // FRB_FLOAT
        assert!(NumberFormat::from_frb(0x7).is_none()); // FRB_SEG
        assert!(NumberFormat::from_frb(0x8).is_none()); // FRB_ENUM
        assert!(NumberFormat::from_frb(0xff).is_none());
    }
}
