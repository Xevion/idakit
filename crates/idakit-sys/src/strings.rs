//! String-literal enumeration facade (`idakit_strlist_*`, `idakit_strlit_contents`).

use std::ffi::{c_char, c_int};

use crate::Address;

unsafe extern "C" {
    pub fn idakit_strlist_build();
    pub fn idakit_strlist_qty() -> usize;
    pub fn idakit_strlist_item(
        n: usize,
        ea: *mut Address,
        length: *mut c_int,
        ty: *mut c_int,
    ) -> c_int;
    pub fn idakit_strlit_contents(
        ea: Address,
        len: usize,
        ty: c_int,
        buf: *mut c_char,
        cap: usize,
    ) -> i64;
}

/// `STRWIDTH_MASK` from `nalt.hpp`: the STRTYPE bits selecting bytes-per-character.
pub const STRWIDTH_MASK: c_int = 0x03;
/// `STRLYT_MASK` from `nalt.hpp`: the STRTYPE bits selecting the layout (terminated vs Pascal).
pub const STRLYT_MASK: c_int = 0xFC;
/// `STRLYT_SHIFT` from `nalt.hpp`: right-shift applied to the [`STRLYT_MASK`] field.
pub const STRLYT_SHIFT: c_int = 2;
