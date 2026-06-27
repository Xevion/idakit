//! Raw FFI bindings to IDA's idalib runtime and the idakit C++ facade.
//!
//! # Buffer conventions
//!
//! Functions that accept `(*mut c_char, cap: usize)` copy the value into the
//! caller-supplied buffer and NUL-terminate within `cap` bytes. The return value
//! is the full source length, which may exceed `cap` when the output was
//! truncated. A negative return value means the query failed (missing symbol,
//! null handle, etc.).
//!
//! # Owned handles
//!
//! `idakit_decompile` and `idakit_type_open` return opaque `*mut c_void` handles
//! that are owned by the caller. Each must be released with its matching
//! `*_dispose` function (`idakit_cfunc_dispose` / `idakit_type_dispose`).
//! Passing a handle to any other function after disposal is undefined behaviour.

pub type Ea = u64;
pub const BADADDR: Ea = u64::MAX;

use std::ffi::{c_char, c_int, c_void};

// idalib lifecycle entry points (plain C ABI from libidalib.so)
unsafe extern "C" {
    pub fn init_library(argc: c_int, argv: *mut *mut c_char) -> c_int;
    pub fn get_library_version(major: *mut c_int, minor: *mut c_int, build: *mut c_int) -> bool;
    pub fn open_database(path: *const c_char, run_auto: bool, args: *const c_char) -> c_int;
    pub fn close_database(save: bool);
    pub fn enable_console_messages(enable: bool);
}

// kernel thread-affinity (plain C ABI from libida.so). `is_main_thread` reads
// libida's nullable `g_main`: non-null -> compares to caller; null -> claims caller.
unsafe extern "C" {
    pub fn is_main_thread() -> bool;
}

// IDA's thread-safe error reporting (plain C ABI from libida.so). `error_t` is an
// `int`; `get_qerrno` reads the thread's last code and `qstrerror` describes one
// (folding in the C `errno` text for the `eOS` code).
unsafe extern "C" {
    pub fn get_qerrno() -> c_int;
    pub fn qstrerror(code: c_int) -> *const c_char;
}

// idakit facade functions (C++ SDK wrapped behind a clean C ABI)
unsafe extern "C" {
    pub fn idakit_func_qty() -> usize;
    pub fn idakit_func_ea(n: usize) -> Ea;
    pub fn idakit_func_name(ea: Ea, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_seg_qty() -> c_int;
    pub fn idakit_seg_name(n: c_int, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_seg_start(n: c_int) -> Ea;
    pub fn idakit_seg_end(n: c_int) -> Ea;
}

// raw bytes + cross-references
unsafe extern "C" {
    pub fn idakit_get_bytes(ea: Ea, buf: *mut c_void, size: usize) -> i64;
    pub fn idakit_xrefs_to(
        ea: Ea,
        from: *mut Ea,
        type_: *mut u8,
        iscode: *mut u8,
        cap: usize,
    ) -> usize;
}

// type information
unsafe extern "C" {
    pub fn idakit_func_type(ea: Ea, buf: *mut c_char, cap: usize) -> i64;
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

// hex-rays decompiler
unsafe extern "C" {
    pub fn idakit_hexrays_init() -> c_int;
    pub fn idakit_decompile(ea: Ea, errbuf: *mut c_char, cap: usize) -> *mut c_void;
    pub fn idakit_cfunc_dispose(cfunc: *mut c_void);
    pub fn idakit_cfunc_pseudocode(cfunc: *mut c_void, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_cfunc_ctree_counts(
        cfunc: *mut c_void,
        n_insn: *mut c_int,
        n_expr: *mut c_int,
        n_calls: *mut c_int,
    );
}

// libida kernel writes
unsafe extern "C" {
    pub fn set_name(ea: Ea, name: *const c_char, flags: c_int) -> bool;
    pub fn set_cmt(ea: Ea, comm: *const c_char, rptble: bool) -> bool;
}
