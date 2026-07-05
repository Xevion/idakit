//! Cross-reference cursor facade (`idakit_xref_*`).
//!
//! `idakit_xref_open` returns an owned handle the caller must release with
//! `idakit_xref_close`; `is_to` selects xrefs *to* `address` (1) or *from* it (0).
//! `idakit_xref_next` writes the edge endpoints and returns 1 until exhausted.

use std::ffi::c_void;

use crate::Address;

unsafe extern "C" {
    pub fn idakit_xref_open(address: Address, is_to: u8) -> *mut c_void;
    pub fn idakit_xref_next(
        cursor: *mut c_void,
        from: *mut Address,
        to: *mut Address,
        type_: *mut u8,
        iscode: *mut u8,
    ) -> u8;
    pub fn idakit_xref_close(cursor: *mut c_void);
}
