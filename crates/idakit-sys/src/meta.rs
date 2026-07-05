//! Database-wide metadata facade (`idakit_bitness`, `idakit_image_base`, processor and
//! input-file names).

use std::ffi::{c_char, c_int};

use crate::Address;

unsafe extern "C" {
    pub fn idakit_bitness() -> c_int;
    pub fn idakit_image_base() -> Address;
    pub fn idakit_proc_name(buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_file_type_name(buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_input_path(buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_root_filename(buf: *mut c_char, cap: usize) -> i64;
}
