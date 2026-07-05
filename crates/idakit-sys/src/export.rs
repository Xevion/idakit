//! Export / entry-point enumeration facade (`idakit_export_*`).

use std::ffi::c_char;

use crate::Address;

unsafe extern "C" {
    pub fn idakit_export_qty() -> usize;
    pub fn idakit_export_ea(idx: usize) -> Address;
    pub fn idakit_export_ordinal(idx: usize) -> u64;
    pub fn idakit_export_name(idx: usize, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_export_forwarder(idx: usize, buf: *mut c_char, cap: usize) -> i64;
}
