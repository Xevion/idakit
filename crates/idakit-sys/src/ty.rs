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
}
