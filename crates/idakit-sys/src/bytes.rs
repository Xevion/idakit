//! Raw byte reads, item classification and linear navigation (`bytes.hpp`), and the
//! comment write (`set_cmt`).

use std::ffi::{c_char, c_void};

use crate::Ea;

// raw bytes
unsafe extern "C" {
    pub fn idakit_get_bytes(ea: Ea, buf: *mut c_void, size: usize) -> i64;
}

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

// comment write (plain libida symbol; the read half lives in the SDK's bytes.hpp too)
unsafe extern "C" {
    pub fn set_cmt(ea: Ea, comm: *const c_char, rptble: bool) -> bool;
}
