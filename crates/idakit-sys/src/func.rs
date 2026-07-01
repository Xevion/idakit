//! Function enumeration facade (`idakit_func_*`).

use std::ffi::{c_char, c_int};

use crate::Ea;

unsafe extern "C" {
    pub fn idakit_func_qty() -> usize;
    pub fn idakit_func_ea(n: usize) -> Ea;
    pub fn idakit_func_name(ea: Ea, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_func_chunk_qty(ea: Ea) -> c_int;
    pub fn idakit_func_chunk(ea: Ea, idx: c_int, start: *mut Ea, end: *mut Ea) -> c_int;
}
