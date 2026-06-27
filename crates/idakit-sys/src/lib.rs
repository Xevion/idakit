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

// ctree extraction records: the flat, POD image of a decompiled function's ctree that
// the facade fills (one DFS) and idakit's ctree builder reads. Field meaning depends on
// `tag` and is interpreted there — these are layout only. `#[repr(C)]` so the layout
// matches the facade's identical structs byte-for-byte (the `static_assert`s on the C++
// side and the size checks below are the tripwire if either drifts).

/// One expression node. `tag` is a `ctype_t` (`cot_*`) value; `a`/`b`/`c` are child or
/// pool references, `aux` carries a wide literal (`cot_num`/`cot_obj`/`cot_fnum`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ExprRec {
    pub ea: Ea,
    pub aux: u64,
    pub ty: u32,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub tag: u32,
    pub flags: u32,
}

/// One statement node. `tag` is a `ctype_t` (`cit_*`) value; otherwise like [`ExprRec`]
/// without a type (`aux` holds a `body` statement reference for `cit_for`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct StmtRec {
    pub ea: Ea,
    pub aux: u64,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub tag: u32,
    pub flags: u32,
}

/// One resolved type. `tag` is a small type-kind code (not a `ctype_t`); `a`/`b` are a
/// child type or a `bytes`-pool string slice (named types).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TypeRec {
    pub size: u64,
    pub aux: u64,
    pub a: u32,
    pub b: u32,
    pub tag: u32,
    pub bytes: u32,
    pub signed: u32,
    pub has_size: u32,
}

/// One `switch` case: a slice of `longs` (the case values) and a `body` statement.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CaseRec {
    pub values_off: u32,
    pub values_len: u32,
    pub body: u32,
    pub flags: u32,
}

const _: () = {
    assert!(core::mem::size_of::<ExprRec>() == 40);
    assert!(core::mem::size_of::<StmtRec>() == 40);
    assert!(core::mem::size_of::<TypeRec>() == 40);
    assert!(core::mem::size_of::<CaseRec>() == 16);
};

/// A view over a facade-owned ctree extraction (see [`idakit_cfunc_extract_ctree`]). All
/// pointers are valid until the extraction handle is disposed; lengths are element
/// counts (and the pointer may be null when the count is zero).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CtreeView {
    pub types: *const TypeRec,
    pub n_types: usize,
    pub exprs: *const ExprRec,
    pub n_exprs: usize,
    pub stmts: *const StmtRec,
    pub n_stmts: usize,
    pub nodes: *const u32,
    pub n_nodes: usize,
    pub bytes: *const u8,
    pub n_bytes: usize,
    pub longs: *const u64,
    pub n_longs: usize,
    pub cases: *const CaseRec,
    pub n_cases: usize,
    pub root: u32,
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
    /// Extract `cfunc`'s ctree, returning a handle that owns the storage `out` points
    /// into. Release with [`idakit_ctree_dispose`]. Returns null if `cfunc` is null.
    pub fn idakit_cfunc_extract_ctree(cfunc: *mut c_void, out: *mut CtreeView) -> *mut c_void;
    pub fn idakit_ctree_dispose(h: *mut c_void);
}

// libida kernel writes
unsafe extern "C" {
    pub fn set_name(ea: Ea, name: *const c_char, flags: c_int) -> bool;
    pub fn set_cmt(ea: Ea, comm: *const c_char, rptble: bool) -> bool;
}
