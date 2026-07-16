//! The array-tag selector and its reserved values.

use serde::{Deserialize, Serialize};

/// A netnode array tag: the `uchar` selector namespacing an alt, sup, or hash array.
///
/// The default accessors use the reserved [`ALT`](Self::ALT)/[`SUP`](Self::SUP)/[`HASH`](Self::HASH)
/// tags; [`Netnode::tag`](super::Netnode::tag) reaches the same arrays under any other tag.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Tag(u8);

impl Tag {
    /// The reserved alt-array tag (`atag`).
    pub const ALT: Self = Self(b'A');
    /// The reserved sup-array tag (`stag`).
    pub const SUP: Self = Self(b'S');
    /// The reserved hash tag (`htag`).
    pub const HASH: Self = Self(b'H');

    /// A tag from a raw selector byte, e.g. `Tag::new(b'X')` for a user array.
    #[inline]
    #[must_use]
    pub const fn new(tag: u8) -> Self {
        Self(tag)
    }

    /// The raw selector byte.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// The selector widened for the FFI boundary (tags cross as `u32`).
    #[inline]
    pub(crate) const fn raw(self) -> u32 {
        self.0 as u32
    }
}

impl std::fmt::Debug for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tag({:?})", self.0 as char)
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::Tag;

    #[test]
    fn orders_by_raw_byte() {
        assert!(Tag::ALT < Tag::HASH);
        assert!(Tag::HASH < Tag::SUP);
        assert!(Tag::new(b'A') == Tag::ALT);
    }

    #[test]
    fn debug_renders_the_selector_char() {
        assert!(format!("{:?}", Tag::ALT) == "Tag('A')");
    }

    #[test]
    fn serde_round_trips() {
        let json = serde_json::to_string(&Tag::new(b'X')).unwrap();
        assert!(serde_json::from_str::<Tag>(&json).unwrap() == Tag::new(b'X'));
    }

    mod proptests {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            // Across the full u8 domain: the selector round-trips exactly, and the FFI-facing
            // widening never changes its numeric value.
            #[test]
            fn new_get_and_raw_round_trip(byte in any::<u8>()) {
                let tag = Tag::new(byte);
                prop_assert_eq!(tag.get(), byte);
                prop_assert_eq!(tag.raw(), u32::from(byte));
            }

            // Ordering follows the raw byte value for any pair.
            #[test]
            fn ord_follows_the_raw_byte(a in any::<u8>(), b in any::<u8>()) {
                prop_assert_eq!(Tag::new(a).cmp(&Tag::new(b)), a.cmp(&b));
            }
        }
    }
}
