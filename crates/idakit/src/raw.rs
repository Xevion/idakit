//! The crate's kernel-global FFI boundary, as private [`Idb`] methods.
//!
//! Every `idakit-sys` call that operates on the implicit current database lives
//! here as one thin wrapper. The handle-scoped calls (`Cfunc`, `TypeInfo`) stay on
//! those types, since they own the handle they act on.
//!
//! # Safety
//!
//! Every method below is sound by one invariant, discharged here once: an [`Idb`]
//! is `!Send` and constructed only inside the kernel-thread pump of
//! [`Ida::run`](crate::Ida::run), so holding `&self` proves we are on the kernel
//! thread with the library initialized and a database open — exactly the
//! thread-affinity and live-database preconditions the kernel demands. `&mut self`
//! adds exclusivity for writes. Raw buffer pointers are valid for the call;
//! string getters fill `(buf, cap)` and return the value's full length.

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use idakit_sys as sys;

use crate::Idb;
use crate::ea::Ea;

impl Idb {
    pub(crate) fn open_database(&mut self, path: *const c_char) -> c_int {
        unsafe { sys::open_database(path, false, ptr::null()) }
    }

    pub(crate) fn close_database(&mut self, save: bool) {
        unsafe { sys::close_database(save) }
    }

    pub(crate) fn get_bytes(&self, ea: Ea, buf: *mut c_void, size: usize) -> i64 {
        unsafe { sys::idakit_get_bytes(ea.get(), buf, size) }
    }

    pub(crate) fn xrefs_to_raw(
        &self,
        ea: Ea,
        from: *mut sys::Ea,
        kind: *mut u8,
        iscode: *mut u8,
        cap: usize,
    ) -> usize {
        unsafe { sys::idakit_xrefs_to(ea.get(), from, kind, iscode, cap) }
    }

    pub(crate) fn type_open(&self, name: *const c_char) -> *mut c_void {
        unsafe { sys::idakit_type_open(name) }
    }

    pub(crate) fn hexrays_init(&self) -> c_int {
        unsafe { sys::idakit_hexrays_init() }
    }

    pub(crate) fn decompile_at(&self, ea: Ea) -> *mut c_void {
        unsafe { sys::idakit_decompile(ea.get()) }
    }

    pub(crate) fn set_name(&mut self, ea: Ea, name: *const c_char) -> bool {
        unsafe { sys::set_name(ea.get(), name, 0) }
    }

    pub(crate) fn set_cmt(&mut self, ea: Ea, comment: *const c_char, repeatable: bool) -> bool {
        unsafe { sys::set_cmt(ea.get(), comment, repeatable) }
    }

    pub(crate) fn func_qty(&self) -> usize {
        unsafe { sys::idakit_func_qty() }
    }

    pub(crate) fn func_ea(&self, n: usize) -> sys::Ea {
        unsafe { sys::idakit_func_ea(n) }
    }

    pub(crate) fn func_name(&self, ea: Ea, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_func_name(ea.get(), buf, cap) }
    }

    pub(crate) fn func_type(&self, ea: Ea, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_func_type(ea.get(), buf, cap) }
    }

    pub(crate) fn seg_qty(&self) -> c_int {
        unsafe { sys::idakit_seg_qty() }
    }

    pub(crate) fn seg_name(&self, n: c_int, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_seg_name(n, buf, cap) }
    }

    pub(crate) fn seg_start(&self, n: c_int) -> sys::Ea {
        unsafe { sys::idakit_seg_start(n) }
    }

    pub(crate) fn seg_end(&self, n: c_int) -> sys::Ea {
        unsafe { sys::idakit_seg_end(n) }
    }
}
