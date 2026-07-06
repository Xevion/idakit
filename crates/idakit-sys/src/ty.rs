//! Type-information facade (`idakit_func_type`, `idakit_type_*`).

use std::ffi::{c_char, c_int, c_void};

use crate::Address;
use crate::hexrays::TypeVtbl;

unsafe extern "C" {
    pub fn idakit_func_type(address: Address, buf: *mut c_char, cap: usize) -> i64;

    /// Resolve the local named type `name` and walk it into one interned table via `v` (with
    /// `ctx`), writing its root handle to `*root`. Returns 0 on success, non-zero if no such type.
    pub fn idakit_type_walk(
        name: *const c_char,
        v: *const TypeVtbl,
        ctx: *mut c_void,
        root: *mut u32,
    ) -> c_int;

    /// Walk the stored prototype of the function at `address` into one interned table via `v`
    /// (with `ctx`), writing its root handle to `*root`. Returns 0 on success, non-zero if the
    /// function has no type info.
    pub fn idakit_func_type_walk(
        address: Address,
        v: *const TypeVtbl,
        ctx: *mut c_void,
        root: *mut u32,
    ) -> c_int;
    pub fn idakit_type_ordinal_count() -> usize;
    pub fn idakit_type_ordinal_name(ordinal: u32, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_type_open(name: *const c_char) -> *mut c_void;
    pub fn idakit_type_dispose(h: *mut c_void);
    pub fn idakit_type_size(h: *mut c_void) -> i64;
    pub fn idakit_type_print(h: *mut c_void, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_type_nmembers(h: *mut c_void) -> usize;
    pub fn idakit_type_member_info(
        h: *mut c_void,
        i: usize,
        offset: *mut u64,
        size: *mut u64,
    ) -> c_int;
    pub fn idakit_type_member_name(h: *mut c_void, i: usize, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_type_member_type(h: *mut c_void, i: usize, buf: *mut c_char, cap: usize) -> i64;
}
