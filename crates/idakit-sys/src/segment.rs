//! Segment enumeration facade (`idakit_seg_*`).

use std::ffi::{c_char, c_int};

use crate::Ea;

unsafe extern "C" {
    pub fn idakit_seg_qty() -> c_int;
    pub fn idakit_seg_name(n: c_int, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_seg_start(n: c_int) -> Ea;
    pub fn idakit_seg_end(n: c_int) -> Ea;
}
