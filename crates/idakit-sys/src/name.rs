//! Name lookup and the name list (`name.hpp`), plus the name write (`set_name`).

use std::ffi::{c_char, c_int};

use crate::Address;

// names and the name list (name.hpp)
unsafe extern "C" {
    pub fn idakit_get_ea_name(address: Address, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_get_name_ea(name: *const c_char) -> Address;
    pub fn idakit_demangle_name(name: *const c_char, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_nlist_size() -> usize;
    pub fn idakit_nlist_ea(idx: usize) -> Address;
    pub fn idakit_nlist_name(idx: usize, buf: *mut c_char, cap: usize) -> i64;
}

// name write (plain libida symbol)
unsafe extern "C" {
    pub fn set_name(address: Address, name: *const c_char, flags: c_int) -> bool;
}
