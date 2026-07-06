//! [`StringLiteral`]: one string from IDA's string list, iterated by [`Strings`].
//!
//! The natural singular name `String` collides with [`std::string::String`], so the view is
//! [`StringLiteral`] while the iterator and the [`Database::strings`] method keep the ergonomic
//! `strings` stem.

use idakit_sys as sys;

use crate::Database;
use crate::address::Address;
use crate::ffi::read_string;

impl Database {
    /// Iterate every string literal IDA located in the database.
    ///
    /// This (re)builds IDA's string list first -- an O(database) scan -- then walks it. Collect
    /// the result once if you iterate repeatedly, rather than calling this again.
    #[must_use]
    pub fn strings(&self) -> Strings<'_> {
        self.strlist_build();
        Strings::new(self)
    }
}

/// A string literal IDA located: its [`address`](Self::address), octet [`len`](Self::len), and
/// decoded [`text`](Self::text). A borrowed view valid while the database stays open -- the raw
/// STRTYPE fields are read once at iteration; the text is decoded on demand.
#[derive(Clone, Copy)]
pub struct StringLiteral<'db> {
    address: Address,
    length: usize,
    raw_type: i32,
    db: &'db Database,
}

impl<'db> StringLiteral<'db> {
    #[inline]
    pub(crate) fn new(address: Address, length: usize, raw_type: i32, db: &'db Database) -> Self {
        Self {
            address,
            length,
            raw_type,
            db,
        }
    }

    /// The string's address.
    #[inline]
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// The string's length in octets (raw bytes), excluding any terminator. Divide by
    /// [`char_width`](Self::char_width) for a character count.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length
    }

    /// Whether the string is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Bytes per character: `1` (byte / UTF-8), `2` (UTF-16), or `4` (UTF-32).
    #[inline]
    #[must_use]
    pub fn char_width(&self) -> u8 {
        char_width_of(self.raw_type)
    }

    /// Whether the string is length-prefixed (Pascal-style) rather than terminated.
    #[inline]
    #[must_use]
    pub fn is_pascal(&self) -> bool {
        is_pascal_of(self.raw_type)
    }

    /// The decoded string as UTF-8, or `None` if the bytes can't be read. Undecodable units
    /// become the Unicode replacement character (U+FFFD) rather than failing.
    #[must_use]
    pub fn text(&self) -> Option<String> {
        read_string(|buf, cap| {
            self.db
                .strlit_contents(self.address, self.length, self.raw_type, buf, cap)
        })
    }
}

impl std::fmt::Debug for StringLiteral<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StringLiteral")
            .field("address", &self.address)
            .field("len", &self.length)
            .field("char_width", &self.char_width())
            .field("text", &self.text())
            .finish()
    }
}

// Identity is the address alone; the `db` borrow is incidental and must not participate.
impl PartialEq for StringLiteral<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.address == o.address
    }
}
impl Eq for StringLiteral<'_> {}
impl std::hash::Hash for StringLiteral<'_> {
    fn hash<H: std::hash::Hasher>(&self, s: &mut H) {
        self.address.hash(s);
    }
}

/// Bytes per character encoded in a STRTYPE code (`STRWIDTH`): 1, 2, or 4. Only the low byte
/// carries width/layout; the high byte's encoding index is irrelevant here.
fn char_width_of(raw_type: i32) -> u8 {
    1u8 << ((raw_type & sys::STRWIDTH_MASK) as u8)
}

/// Whether a STRTYPE layout is Pascal (length-prefixed) rather than terminated -- `STRLYT`
/// values 1..=3 (`PASCAL1`/`PASCAL2`/`PASCAL4`).
fn is_pascal_of(raw_type: i32) -> bool {
    let layout = (raw_type & sys::STRLYT_MASK) >> sys::STRLYT_SHIFT;
    (1..=3).contains(&layout)
}

/// Lazy iterator over IDA's string list, in list order. Borrows `&Database`, so it can't outlive the
/// database or coexist with a write. `size_hint`'s lower bound is `0`: a list entry with no
/// readable address is skipped.
pub struct Strings<'db> {
    db: &'db Database,
    next: usize,
    count: usize,
}

impl<'db> Strings<'db> {
    #[inline]
    pub(crate) fn new(db: &'db Database) -> Self {
        Self {
            db,
            next: 0,
            count: db.strlist_qty(),
        }
    }

    /// Read list entry `n` into a view, or `None` if it is out of range or has no valid address.
    fn item(&self, n: usize) -> Option<StringLiteral<'db>> {
        let (mut ea, mut length, mut ty) = (0u64, 0i32, 0i32);
        if self.db.strlist_item(n, &mut ea, &mut length, &mut ty) == 0 {
            return None;
        }
        let address = Address::try_new(ea)?;
        Some(StringLiteral::new(
            address,
            length.max(0) as usize,
            ty,
            self.db,
        ))
    }
}

impl<'db> Iterator for Strings<'db> {
    type Item = StringLiteral<'db>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next < self.count {
            let n = self.next;
            self.next += 1;
            if let Some(string) = self.item(n) {
                return Some(string);
            }
        }
        None
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.count - self.next))
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    // Raw STRTYPE codes (nalt.hpp): STRWIDTH in bits 0-1, STRLYT in bits 2+.
    const STRTYPE_C: i32 = 0x00; // 1-byte, terminated
    const STRTYPE_C_16: i32 = 0x01; // 2-byte, terminated
    const STRTYPE_C_32: i32 = 0x02; // 4-byte, terminated
    const STRTYPE_PASCAL: i32 = 0x04; // 1-byte, 1-byte length prefix
    const STRTYPE_PASCAL_16: i32 = 0x05; // 2-byte, 1-byte length prefix
    const STRTYPE_LEN2: i32 = 0x08; // 1-byte, 2-byte length prefix

    /// Width comes from the STRWIDTH bits, and a nonzero encoding index (high byte) does not
    /// disturb it.
    #[rstest]
    #[case(STRTYPE_C, 1)]
    #[case(STRTYPE_C_16, 2)]
    #[case(STRTYPE_C_32, 4)]
    #[case(STRTYPE_PASCAL, 1)]
    #[case(STRTYPE_PASCAL_16, 2)]
    #[case(STRTYPE_C | 0x5500_0000, 1)] // encoding index in the high byte is ignored
    fn char_width_reads_the_strwidth_field(#[case] raw: i32, #[case] width: u8) {
        assert!(char_width_of(raw) == width);
    }

    /// Terminated layouts are not Pascal; the three length-prefixed layouts are.
    #[rstest]
    #[case(STRTYPE_C, false)]
    #[case(STRTYPE_C_16, false)]
    #[case(STRTYPE_PASCAL, true)]
    #[case(STRTYPE_PASCAL_16, true)]
    #[case(STRTYPE_LEN2, true)]
    fn is_pascal_reads_the_strlyt_field(#[case] raw: i32, #[case] pascal: bool) {
        assert!(is_pascal_of(raw) == pascal);
    }
}
