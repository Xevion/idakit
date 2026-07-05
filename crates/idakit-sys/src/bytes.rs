//! Raw byte reads, item classification and linear navigation (`bytes.hpp`), binary pattern
//! search, byte patching, and comment read/write.

use std::ffi::{c_char, c_int, c_void};

use crate::Ea;

// raw bytes
unsafe extern "C" {
    pub fn idakit_get_bytes(ea: Ea, buf: *mut c_void, size: usize) -> i64;
}

// binary pattern search (bytes.hpp). A compiled pattern is an opaque handle; `binpat_free`
// releases it. `bin_search` returns BADADDR when the pattern is absent from [start, end).
unsafe extern "C" {
    pub fn idakit_min_ea() -> Ea;
    pub fn idakit_max_ea() -> Ea;
    pub fn idakit_binpat_compile(
        ea: Ea,
        pattern: *const c_char,
        radix: c_int,
        errbuf: *mut c_char,
        errcap: usize,
    ) -> *mut c_void;
    pub fn idakit_binpat_from_bytes(bytes: *const u8, mask: *const u8, len: usize) -> *mut c_void;
    pub fn idakit_binpat_free(pat: *mut c_void);
    pub fn idakit_binpat_stats(pat: *const c_void, total: *mut usize, anchors: *mut usize);
    pub fn idakit_bin_search(start: Ea, end: Ea, pat: *const c_void, flags: c_int) -> Ea;
}

/// `BIN_SEARCH_CASE` from `bytes.hpp` (IDA 9.3): match `"..."` string literals
/// case-sensitively (the default is case-insensitive).
pub const BIN_SEARCH_CASE: c_int = 0x01;
/// `BIN_SEARCH_BITMASK` from `bytes.hpp` (IDA 9.3): match under a strict bit mask rather
/// than byte-granular wildcards.
pub const BIN_SEARCH_BITMASK: c_int = 0x20;

/// Class mask over an address's [`idakit_get_flags`] word (`MS_CLS` in `bytes.hpp`); the
/// masked value equals [`FF_CODE`] for an instruction or [`FF_DATA`] for data.
pub const MS_CLS: u64 = 0x0000_0600;
/// [`MS_CLS`]-masked flag value marking an address as the head of an instruction.
pub const FF_CODE: u64 = 0x0000_0600;
/// [`MS_CLS`]-masked flag value marking an address as the head of a data item.
pub const FF_DATA: u64 = 0x0000_0400;

// byte/item classification and navigation (bytes.hpp)
unsafe extern "C" {
    pub fn idakit_get_flags(ea: Ea) -> u64;
    pub fn idakit_get_item_head(ea: Ea) -> Ea;
    pub fn idakit_get_item_end(ea: Ea) -> Ea;
    pub fn idakit_get_next_head(ea: Ea, maxea: Ea) -> Ea;
    pub fn idakit_get_prev_head(ea: Ea, minea: Ea) -> Ea;
}

// byte patching (bytes.hpp patch_bytes). Returns 0 without writing if any target byte is
// unmapped, 1 on success.
unsafe extern "C" {
    pub fn idakit_patch_bytes(ea: Ea, buf: *const c_void, size: usize) -> c_int;
}

// comment read (facade get_cmt, snprintf-style, -1 if none) and write (plain libida `set_cmt`).
unsafe extern "C" {
    pub fn idakit_get_cmt(ea: Ea, rptble: u8, buf: *mut c_char, cap: usize) -> i64;
    pub fn set_cmt(ea: Ea, comm: *const c_char, rptble: bool) -> bool;
}
