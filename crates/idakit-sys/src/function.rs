//! Function enumeration facade (`idakit_func_*`).

use std::ffi::{c_char, c_int};

use crate::Address;

unsafe extern "C" {
    pub fn idakit_func_qty() -> usize;
    pub fn idakit_func_ea(n: usize) -> Address;
    pub fn idakit_func_name(address: Address, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_func_chunk_qty(address: Address) -> c_int;
    pub fn idakit_func_chunk(
        address: Address,
        idx: c_int,
        start: *mut Address,
        end: *mut Address,
    ) -> c_int;
    pub fn idakit_func_start(address: Address) -> Address;
    pub fn idakit_func_end(address: Address) -> Address;
    pub fn idakit_func_flags(address: Address) -> u64;
}

/// `FUNC_NORET` from `funcs.hpp`: the function does not return.
pub const FUNC_NORET: u64 = 0x0000_0001;
/// `FUNC_LIB` from `funcs.hpp`: a library function.
pub const FUNC_LIB: u64 = 0x0000_0004;
/// `FUNC_THUNK` from `funcs.hpp`: a thunk (jump) function.
pub const FUNC_THUNK: u64 = 0x0000_0080;
