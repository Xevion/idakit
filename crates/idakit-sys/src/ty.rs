//! Type-information facade (`idakit_func_type`, `idakit_type_*`).

use std::ffi::c_char;

use crate::Address;

unsafe extern "C" {
    pub fn idakit_func_type(address: Address, buf: *mut c_char, cap: usize) -> i64;

    /// Exclusive upper bound on local-type ordinals: valid ordinals run `1..limit`.
    pub fn idakit_type_ordinal_limit() -> u32;

    /// Name of the type at `ordinal` into `(buf, cap)`, returning its full length (0 for an
    /// anonymous type, negative if the ordinal holds no type).
    pub fn idakit_type_name_at(ordinal: u32, buf: *mut c_char, cap: usize) -> i64;
}
