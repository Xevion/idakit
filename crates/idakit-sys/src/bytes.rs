//! The `idakit_get_bytes` read-into twin, the `set_cmt` comment write, and the
//! item-classification / pattern-search flag constants (`bytes.hpp`).

use std::ffi::{c_char, c_int, c_void};

use bitflags::bitflags;

use crate::Address;

// raw bytes
unsafe extern "C" {
    /// Read `size` bytes starting at `address` into `buf`; returns the count read, or negative
    /// on failure.
    pub fn idakit_get_bytes(address: Address, buf: *mut c_void, size: usize) -> i64;
}

bitflags! {
    /// `bin_search` flag bits from `bytes.hpp` (IDA 9.3): `BIN_SEARCH_CASE`/`BIN_SEARCH_BITMASK`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias("BIN_SEARCH_CASE", "BIN_SEARCH_BITMASK"))]
    pub struct BinSearchFlags: c_int {
        /// Match `"..."` string literals case-sensitively (`BIN_SEARCH_CASE`).
        #[doc(alias("BIN_SEARCH_CASE"))]
        const CASE = 0x01;
        /// Match under a strict bit mask rather than byte-granular wildcards (`BIN_SEARCH_BITMASK`).
        #[doc(alias("BIN_SEARCH_BITMASK"))]
        const BITMASK = 0x20;
    }
}

/// Class mask over an address's flags word (`MS_CLS` in `bytes.hpp`); the masked value equals
/// [`FF_CODE`] for an instruction or [`FF_DATA`] for data.
///
/// `get_flags` returns IDA's full `flags_t`, a much wider bitfield idakit does not otherwise
/// model; `MS_CLS`/`FF_CODE`/`FF_DATA` stay plain masked-equality constants rather than a
/// bitflags type, since they classify one two-valued field within that word, not an OR-able flag
/// set of their own.
pub const MS_CLS: u64 = 0x0000_0600;
/// [`MS_CLS`]-masked flag value marking an address as the head of an instruction.
pub const FF_CODE: u64 = 0x0000_0600;
/// [`MS_CLS`]-masked flag value marking an address as the head of a data item.
pub const FF_DATA: u64 = 0x0000_0400;

// comment write (plain libida `set_cmt`).
unsafe extern "C" {
    /// Set the comment at `address` (repeatable when `rptble`); returns whether it succeeded.
    pub fn set_cmt(address: Address, comm: *const c_char, rptble: bool) -> bool;
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn flags_pin_the_raw_sdk_values() {
        assert!(BinSearchFlags::CASE.bits() == 0x01);
        assert!(BinSearchFlags::BITMASK.bits() == 0x20);
    }
}
