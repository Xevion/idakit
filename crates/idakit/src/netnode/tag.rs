//! The array-tag selector and its reserved values.

/// A netnode array tag: the `uchar` selector namespacing an alt, sup, or hash array.
///
/// The default accessors use the reserved [`ALT`](Self::ALT)/[`SUP`](Self::SUP)/[`HASH`](Self::HASH)
/// tags; [`Netnode::tag`](super::Netnode::tag) reaches the same arrays under any other tag.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag(u8);

impl Tag {
    /// The reserved alt-array tag (`atag`).
    pub const ALT: Tag = Tag(b'A');
    /// The reserved sup-array tag (`stag`).
    pub const SUP: Tag = Tag(b'S');
    /// The reserved hash tag (`htag`).
    pub const HASH: Tag = Tag(b'H');

    /// A tag from a raw selector byte, e.g. `Tag::new(b'X')` for a user array.
    #[inline]
    #[must_use]
    pub const fn new(tag: u8) -> Tag {
        Tag(tag)
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
