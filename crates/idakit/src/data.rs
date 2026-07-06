//! Typed reads of the data at an address: fixed-width integers, pointers, and strings.
//!
//! These interpret the analyzed image (the raw [`bytes`](Database::bytes)) as values, in the
//! database's byte order. Each read is `None` when the covered bytes are not fully mapped, so a
//! read off the end of a segment fails rather than quietly returning zero. They pair with the
//! data [`xrefs_to`](Database::xrefs_to): follow a data xref to an address, then read what
//! lives there.

use crate::Database;
use crate::address::Address;
use crate::bitness::Bitness;

impl Database {
    /// Read the unsigned byte at `address`, or `None` if it is not mapped.
    #[must_use]
    pub fn read_u8(&self, address: Address) -> Option<u8> {
        let mut out = 0u8;
        (self.get_u8(address, &mut out) != 0).then_some(out)
    }

    /// Read a 16-bit unsigned value at `address` (database byte order), or `None` if the two
    /// covered bytes are not fully mapped.
    #[must_use]
    pub fn read_u16(&self, address: Address) -> Option<u16> {
        let mut out = 0u16;
        (self.get_u16(address, &mut out) != 0).then_some(out)
    }

    /// Read a 32-bit unsigned value at `address` (database byte order), or `None` if the four
    /// covered bytes are not fully mapped.
    #[must_use]
    pub fn read_u32(&self, address: Address) -> Option<u32> {
        let mut out = 0u32;
        (self.get_u32(address, &mut out) != 0).then_some(out)
    }

    /// Read a 64-bit unsigned value at `address` (database byte order), or `None` if the eight
    /// covered bytes are not fully mapped.
    #[must_use]
    pub fn read_u64(&self, address: Address) -> Option<u64> {
        let mut out = 0u64;
        (self.get_u64(address, &mut out) != 0).then_some(out)
    }

    /// Read a pointer at `address` -- a value the width of the database's address size (4 bytes
    /// for a 32-bit image, 8 for 64-bit) -- as an [`Address`]. `None` if the database reports no
    /// recognized [`Bitness`], the bytes are unmapped, or the stored value is
    /// [`BADADDR`](crate::BADADDR).
    #[must_use]
    pub fn read_pointer(&self, address: Address) -> Option<Address> {
        let raw = match self.bitness()? {
            Bitness::Bits64 => self.read_u64(address)?,
            Bitness::Bits32 => u64::from(self.read_u32(address)?),
            Bitness::Bits16 => u64::from(self.read_u16(address)?),
        };
        Address::try_new(raw)
    }

    /// Read the C string (1-byte units, NUL-terminated) at `address`, decoded as UTF-8, or
    /// `None` if `address` holds no string. The length is auto-detected up to the terminator;
    /// undecodable bytes become the Unicode replacement character (U+FFFD). For wide strings and
    /// a whole-database sweep, use [`strings`](Database::strings) instead.
    #[must_use]
    pub fn read_string(&self, address: Address) -> Option<String> {
        // Fully qualified: `Database::read_string` (this method) and the `ffi::read_string` buffer
        // helper share a name; the path keeps them apart.
        crate::ffi::read_string(|buf, cap| self.get_strlit(address, 0, buf, cap))
    }
}
