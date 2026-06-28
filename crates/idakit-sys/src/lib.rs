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

// auto-analysis (plain C ABI from libida.so). `open_database(run_auto=true)` only
// *enables* the analysis queue; `auto_wait` blocks until it drains, so a caller that
// wants a fully analyzed database calls it after opening (mirrors idalib).
unsafe extern "C" {
    pub fn auto_wait() -> bool;
}

// IDA's thread-safe error reporting (plain C ABI from libida.so). `error_t` is an
// `int`; `get_qerrno` reads the thread's last code and `qstrerror` describes one
// (folding in the C `errno` text for the `eOS` code).
unsafe extern "C" {
    pub fn get_qerrno() -> c_int;
    /// Describe an `error_t`. The returned pointer borrows IDA's static/thread-local
    /// storage: it must not be freed, and a later `qstrerror` call on the same thread may
    /// overwrite it. Copy it into a `CStr`/`String` before the next IDA call.
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

/// Absent optional child / sentinel, matching `IDAKIT_NONE` in the facade.
pub const IDAKIT_NONE: u32 = 0xFFFF_FFFF;

/// One struct/union member, as the facade passes it to [`EmitVtbl::t_fill_struct`].
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemberDesc {
    pub name: *const c_char,
    pub name_len: usize,
    pub bit_offset: u64,
    pub ty: u32,
    pub bitfield_width: u32,
}

/// One enum constant, as passed to [`EmitVtbl::t_fill_enum`].
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EnumConstDesc {
    pub name: *const c_char,
    pub name_len: usize,
    pub value: u64,
}

/// One `switch` case, as passed to [`EmitVtbl::s_switch`].
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CaseDesc {
    pub values: *const u64,
    pub nvalues: usize,
    pub body: u32,
}

/// The callbacks the facade invokes while streaming a ctree walk. The consumer (idakit)
/// builds owned nodes inside each callback and returns the handle the parent will
/// reference; children are emitted before parents. `#[repr(C)]` and field order mirror
/// `idakit_emit_vtbl_t` exactly — the facade indexes by offset.
///
/// Every `*const c_char`/byte-slice pointer passed to a callback (names, string literals,
/// member and enum-constant names, comments, value arrays) borrows a C++ stack temporary
/// owned by the walk. It is valid for that single callback invocation only and dangles once
/// the callback returns, so a callback must copy any data it needs to outlive the call.
#[repr(C)]
pub struct EmitVtbl {
    pub e_num: unsafe extern "C" fn(*mut c_void, Ea, u64, u32) -> u32,
    pub e_fnum: unsafe extern "C" fn(*mut c_void, Ea, f64, u32) -> u32,
    pub e_obj: unsafe extern "C" fn(*mut c_void, Ea, Ea, *const c_char, usize, u32) -> u32,
    pub e_var: unsafe extern "C" fn(*mut c_void, Ea, u32, u32) -> u32,
    pub e_str: unsafe extern "C" fn(*mut c_void, Ea, *const c_char, usize, u32) -> u32,
    pub e_helper: unsafe extern "C" fn(*mut c_void, Ea, *const c_char, usize, u32) -> u32,
    pub e_call: unsafe extern "C" fn(*mut c_void, Ea, u32, *const u32, usize, u32) -> u32,
    pub e_memref: unsafe extern "C" fn(*mut c_void, Ea, u32, u32, u32) -> u32,
    pub e_memptr: unsafe extern "C" fn(*mut c_void, Ea, u32, u32, u32) -> u32,
    pub e_deref: unsafe extern "C" fn(*mut c_void, Ea, u32, u32, u32) -> u32,
    pub e_op: unsafe extern "C" fn(*mut c_void, Ea, u32, u32, u32, u32, u32) -> u32,

    pub s_block: unsafe extern "C" fn(*mut c_void, Ea, *const u32, usize) -> u32,
    pub s_expr: unsafe extern "C" fn(*mut c_void, Ea, u32) -> u32,
    pub s_if: unsafe extern "C" fn(*mut c_void, Ea, u32, u32, u32) -> u32,
    pub s_for: unsafe extern "C" fn(*mut c_void, Ea, u32, u32, u32, u32) -> u32,
    pub s_while: unsafe extern "C" fn(*mut c_void, Ea, u32, u32) -> u32,
    pub s_do: unsafe extern "C" fn(*mut c_void, Ea, u32, u32) -> u32,
    pub s_switch: unsafe extern "C" fn(*mut c_void, Ea, u32, *const CaseDesc, usize) -> u32,
    pub s_break: unsafe extern "C" fn(*mut c_void, Ea) -> u32,
    pub s_continue: unsafe extern "C" fn(*mut c_void, Ea) -> u32,
    pub s_return: unsafe extern "C" fn(*mut c_void, Ea, u32) -> u32,
    pub s_goto: unsafe extern "C" fn(*mut c_void, Ea, i32) -> u32,
    pub s_asm: unsafe extern "C" fn(*mut c_void, Ea, *const u64, usize) -> u32,
    pub s_try: unsafe extern "C" fn(*mut c_void, Ea, u32, *const u32, usize) -> u32,
    pub s_throw: unsafe extern "C" fn(*mut c_void, Ea, u32) -> u32,
    pub s_empty: unsafe extern "C" fn(*mut c_void, Ea) -> u32,

    pub t_scalar: unsafe extern "C" fn(*mut c_void, u32, u32, u32, u64, u32) -> u32,
    pub t_ptr: unsafe extern "C" fn(*mut c_void, u32, u64, u32) -> u32,
    pub t_array: unsafe extern "C" fn(*mut c_void, u32, u64, u64, u32) -> u32,
    pub t_func: unsafe extern "C" fn(*mut c_void, u32, *const u32, usize, u32) -> u32,
    pub t_named_ref: unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> u32,
    pub t_anon: unsafe extern "C" fn(*mut c_void) -> u32,
    pub t_fill_struct:
        unsafe extern "C" fn(*mut c_void, u32, u32, *const MemberDesc, usize, u64, u32),
    pub t_fill_enum:
        unsafe extern "C" fn(*mut c_void, u32, u32, *const EnumConstDesc, usize, u64, u32),
    pub t_fill_typedef: unsafe extern "C" fn(*mut c_void, u32, u32),

    pub l_lvar: unsafe extern "C" fn(
        *mut c_void,
        *const c_char,
        usize,
        u32,
        u32,
        u32,
        *const c_char,
        usize,
        u32,
        i64,
    ),
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
    /// Walk `cfunc`'s ctree, driving `vtbl` (with `ctx`) per node and writing the root
    /// statement handle to `*root`. Returns 0 on success, non-zero if `cfunc` is null.
    pub fn idakit_cfunc_walk_ctree(
        cfunc: *mut c_void,
        vtbl: *const EmitVtbl,
        ctx: *mut c_void,
        root: *mut u32,
    ) -> c_int;
}

// libida kernel writes
unsafe extern "C" {
    pub fn set_name(ea: Ea, name: *const c_char, flags: c_int) -> bool;
    pub fn set_cmt(ea: Ea, comm: *const c_char, rptble: bool) -> bool;
}
