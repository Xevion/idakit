//! Control-flow graph facade (`idakit_cfg_*`).

use std::ffi::{c_int, c_void};

use crate::Address;

unsafe extern "C" {
    pub fn idakit_cfg_build(address: Address, flags: c_int) -> *mut c_void;
    pub fn idakit_cfg_nblocks(h: *const c_void) -> c_int;
    pub fn idakit_cfg_nproper(h: *const c_void) -> c_int;
    pub fn idakit_cfg_block(
        h: *const c_void,
        n: c_int,
        start: *mut Address,
        end: *mut Address,
        kind: *mut c_int,
    ) -> c_int;
    pub fn idakit_cfg_nsucc(h: *const c_void, n: c_int) -> c_int;
    pub fn idakit_cfg_succ(h: *const c_void, n: c_int, i: c_int) -> c_int;
    pub fn idakit_cfg_npred(h: *const c_void, n: c_int) -> c_int;
    pub fn idakit_cfg_pred(h: *const c_void, n: c_int, i: c_int) -> c_int;
    pub fn idakit_cfg_free(h: *mut c_void);
}

/// `FC_NOEXT` from `gdl.hpp`: omit external blocks (jump targets outside the function).
pub const FC_NOEXT: c_int = 0x0002;
/// `FC_CALL_ENDS` from `gdl.hpp`: call instructions terminate a basic block.
pub const FC_CALL_ENDS: c_int = 0x0020;
/// `FC_NOPREDS` from `gdl.hpp`: skip predecessor-list computation.
pub const FC_NOPREDS: c_int = 0x0040;
