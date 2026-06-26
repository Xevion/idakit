//! Raw FFI bindings to IDA's idalib runtime and the idakit C++ facade.

use std::ffi::{c_char, c_int};

pub type Ea = u64;

unsafe extern "C" {
    pub fn init_library(argc: c_int, argv: *mut *mut c_char) -> c_int;
    pub fn get_library_version(major: *mut c_int, minor: *mut c_int, build: *mut c_int) -> bool;
    pub fn open_database(path: *const c_char, run_auto: bool, args: *const c_char) -> c_int;
    pub fn close_database(save: bool);
    pub fn enable_console_messages(enable: bool);
    pub fn idakit_func_qty() -> usize;
    pub fn idakit_func_ea(n: usize) -> Ea;
    pub fn idakit_func_name(ea: Ea, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_seg_qty() -> c_int;
    pub fn idakit_seg_name(n: c_int, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_seg_start(n: c_int) -> Ea;
    pub fn idakit_seg_end(n: c_int) -> Ea;
}
