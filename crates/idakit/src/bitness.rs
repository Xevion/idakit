//! The addressing width of an image or segment: 16-, 32-, or 64-bit.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::Database;

impl Database {
    /// The database's addressing width, or `None` if it reports an unrecognized one.
    ///
    /// The width of a [`read_pointer`](Database::read_pointer) and one field of the
    /// [`info`](Database::info) snapshot.
    #[inline]
    #[must_use]
    #[doc(alias("inf_get_app_bitness"))]
    pub fn bitness(&self) -> Option<Bitness> {
        Bitness::try_from_bits(self.bitness_bits().max(0) as u8)
    }
}

/// Addressing width: 16-, 32-, or 64-bit.
///
/// A closed set: IDA reports a width in bits, and a value that is not one of these three
/// (including the `0` the facade returns for an absent segment) becomes `None` at the
/// conversion boundary rather than a silent default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[doc(alias("inf_get_app_bitness"))]
pub enum Bitness {
    /// 16-bit addressing.
    Bits16,
    /// 32-bit addressing.
    Bits32,
    /// 64-bit addressing.
    Bits64,
}

impl Bitness {
    /// Interprets a raw bit width: `16`, `32`, or `64`.
    ///
    /// `None` for any other value, which is how the facade's `0` (no such segment) and any
    /// unexpected width surface.
    #[inline]
    #[must_use]
    pub const fn try_from_bits(bits: u8) -> Option<Self> {
        match bits {
            16 => Some(Self::Bits16),
            32 => Some(Self::Bits32),
            64 => Some(Self::Bits64),
            _ => None,
        }
    }

    /// The width in bits: `16`, `32`, or `64`.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Bits16 => 16,
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }
}

impl fmt::Display for Bitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-bit", self.bits())
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::bits16(16, Some(Bitness::Bits16))]
    #[case::bits32(32, Some(Bitness::Bits32))]
    #[case::bits64(64, Some(Bitness::Bits64))]
    // The facade's "no such segment" sentinel and any odd width map to None.
    #[case::zero_sentinel(0, None)]
    #[case::one(1, None)]
    #[case::eight(8, None)]
    #[case::adjacent_to_16(17, None)]
    #[case::adjacent_to_64(63, None)]
    #[case::max(255, None)]
    fn try_from_bits_boundary(#[case] bits: u8, #[case] expect: Option<Bitness>) {
        assert!(Bitness::try_from_bits(bits) == expect);
    }

    #[rstest]
    #[case(Bitness::Bits16, 16)]
    #[case(Bitness::Bits32, 32)]
    #[case(Bitness::Bits64, 64)]
    fn known_widths_round_trip(#[case] bitness: Bitness, #[case] bits: u8) {
        assert!(bitness.bits() == bits);
        assert!(Bitness::try_from_bits(bits) == Some(bitness));
    }

    #[test]
    fn ord_follows_bit_width() {
        assert!(Bitness::Bits16 < Bitness::Bits32);
        assert!(Bitness::Bits32 < Bitness::Bits64);
    }

    #[rstest]
    #[case(Bitness::Bits16, "16-bit")]
    #[case(Bitness::Bits32, "32-bit")]
    #[case(Bitness::Bits64, "64-bit")]
    fn display_shows_bit_width(#[case] bitness: Bitness, #[case] expect: &str) {
        assert!(bitness.to_string() == expect);
    }

    #[rstest]
    #[case(Bitness::Bits16)]
    #[case(Bitness::Bits32)]
    #[case(Bitness::Bits64)]
    fn serde_round_trips(#[case] bitness: Bitness) {
        let json = serde_json::to_string(&bitness).unwrap();
        assert!(serde_json::from_str::<Bitness>(&json).unwrap() == bitness);
    }

    mod proptests {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            // Across the full u8 domain: only 16/32/64 are accepted, everything else is None.
            #[test]
            fn try_from_bits_matches_known_set(bits in any::<u8>()) {
                let expect = match bits {
                    16 => Some(Bitness::Bits16),
                    32 => Some(Bitness::Bits32),
                    64 => Some(Bitness::Bits64),
                    _ => None,
                };
                prop_assert_eq!(Bitness::try_from_bits(bits), expect);
            }
        }
    }
}
