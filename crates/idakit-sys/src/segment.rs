//! Segment enumeration facade (`idakit_seg_*`).

use std::ffi::{c_char, c_int};

use crate::Ea;

unsafe extern "C" {
    pub fn idakit_seg_qty() -> c_int;
    pub fn idakit_seg_name(n: c_int, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_seg_start(n: c_int) -> Ea;
    pub fn idakit_seg_end(n: c_int) -> Ea;
    pub fn idakit_seg_perm(n: c_int) -> c_int;
    pub fn idakit_seg_bitness(n: c_int) -> c_int;
    pub fn idakit_seg_class(n: c_int, buf: *mut c_char, cap: usize) -> i64;
}

/// `SEGPERM_EXEC` from `segment.hpp`: the segment is executable.
pub const SEGPERM_EXEC: c_int = 1;
/// `SEGPERM_WRITE` from `segment.hpp`: the segment is writable.
pub const SEGPERM_WRITE: c_int = 2;
/// `SEGPERM_READ` from `segment.hpp`: the segment is readable.
pub const SEGPERM_READ: c_int = 4;
