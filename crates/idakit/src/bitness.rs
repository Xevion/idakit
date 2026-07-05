//! [`Bitness`]: the addressing width of an image or segment.

use crate::Idb;

impl Idb {
    /// The database's addressing width, or `None` if it reports an unrecognized one. The width
    /// of a [`read_pointer`](Idb::read_pointer) and one field of the [`meta`](Idb::meta)
    /// snapshot.
    #[inline]
    #[must_use]
    pub fn bitness(&self) -> Option<Bitness> {
        Bitness::try_from_bits(self.bitness_bits().max(0) as u8)
    }
}

/// Addressing width: 16-, 32-, or 64-bit.
///
/// A closed set: IDA reports a width in bits, and a value that is not one of these three
/// (including the `0` the facade returns for an absent segment) becomes `None` at the
/// conversion boundary rather than a silent default. `#[non_exhaustive]` reserves room for
/// a future width without a breaking change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Bitness {
    /// 16-bit addressing.
    Bits16,
    /// 32-bit addressing.
    Bits32,
    /// 64-bit addressing.
    Bits64,
}

impl Bitness {
    /// Interpret a raw bit width -- `16`, `32`, or `64`. `None` for any other value, which
    /// is how the facade's `0` (no such segment) and any unexpected width surface.
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

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn known_widths_round_trip() {
        for b in [Bitness::Bits16, Bitness::Bits32, Bitness::Bits64] {
            assert!(Bitness::try_from_bits(b.bits()) == Some(b));
        }
    }

    #[test]
    fn unknown_widths_are_rejected() {
        // The facade's "no such segment" sentinel and any odd width map to None.
        assert!(Bitness::try_from_bits(0).is_none());
        assert!(Bitness::try_from_bits(8).is_none());
        assert!(Bitness::try_from_bits(128).is_none());
    }
}
