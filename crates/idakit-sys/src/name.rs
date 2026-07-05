//! Name lookup and the name list (`name.hpp`), plus the name write (`set_name`).

use std::ffi::{c_char, c_int};

use crate::Address;

/// `FF_NAME` (`bytes.hpp`): the address has an explicit or auto-generated name. With
/// [`FF_LABL`] it forms IDA's two-bit name classification. The SDK `#undef`s these at the end
/// of the header, so the values are mirrored here and pinned to IDA's own predicates by an
/// alignment test in `idakit`.
pub const FF_NAME: u64 = 1 << 14;
/// `FF_LABL` (`bytes.hpp`): the address has a dummy (address-derived) name. See [`FF_NAME`].
pub const FF_LABL: u64 = 1 << 15;

// names and the name list (name.hpp)
unsafe extern "C" {
    pub fn idakit_get_ea_name(address: Address, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_get_name_ea(name: *const c_char) -> Address;
    pub fn idakit_demangle_name(name: *const c_char, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_nlist_size() -> usize;
    pub fn idakit_nlist_ea(idx: usize) -> Address;
    pub fn idakit_nlist_name(idx: usize, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_has_user_name(flags: u64) -> c_int;
    pub fn idakit_has_auto_name(flags: u64) -> c_int;
    pub fn idakit_has_dummy_name(flags: u64) -> c_int;
}

// name write (plain libida symbol)
unsafe extern "C" {
    pub fn set_name(address: Address, name: *const c_char, flags: c_int) -> bool;
}
