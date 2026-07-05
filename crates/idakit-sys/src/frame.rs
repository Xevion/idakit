//! Function stack-frame facade (`idakit_frame_*`).

use std::ffi::{c_char, c_int, c_void};

use crate::Address;

unsafe extern "C" {
    pub fn idakit_frame_build(ea: Address) -> *mut c_void;
    pub fn idakit_frame_size(h: *const c_void) -> u64;
    pub fn idakit_frame_nvars(h: *const c_void) -> usize;
    pub fn idakit_frame_var(
        h: *const c_void,
        i: usize,
        offset: *mut i64,
        size: *mut u64,
        flags: *mut u32,
    ) -> c_int;
    pub fn idakit_frame_var_name(h: *const c_void, i: usize, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_frame_var_type(h: *const c_void, i: usize, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_frame_free(h: *mut c_void);
}

/// `frame_var` flag: the return-address slot in the frame.
pub const FRAME_VAR_RETADDR: u32 = 1;
/// `frame_var` flag: the saved-registers slot in the frame.
pub const FRAME_VAR_SAVREGS: u32 = 2;
