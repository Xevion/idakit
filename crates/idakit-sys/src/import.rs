//! Import-table snapshot facade (`idakit_imports_*`).

use std::ffi::{c_char, c_int, c_void};

use crate::Address;

unsafe extern "C" {
    pub fn idakit_imports_build() -> *mut c_void;
    pub fn idakit_imports_qty(h: *const c_void) -> usize;
    pub fn idakit_imports_item(
        h: *const c_void,
        n: usize,
        ea: *mut Address,
        ord: *mut u64,
    ) -> c_int;
    pub fn idakit_imports_name(h: *const c_void, n: usize, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_imports_module(h: *const c_void, n: usize, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_imports_free(h: *mut c_void);
}
