//! Hex-Rays decompiler facade: the ctree-emit vtbl PODs ([`EmitVtbl`]) and the
//! `idakit_cfunc_*` / `idakit_decompile` entry points.

use std::ffi::{c_char, c_int, c_void};

use crate::Address;

/// Absent optional child / sentinel, matching `IDAKIT_NONE` in the facade.
pub const IDAKIT_NONE: u32 = 0xFFFF_FFFF;

/// One struct/union member, as the facade passes it to [`TypeVtbl::t_fill_struct`].
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemberDesc {
    pub name: *const c_char,
    pub name_len: usize,
    pub bit_offset: u64,
    pub ty: u32,
    pub bitfield_width: u32,
}

/// One enum constant, as passed to [`TypeVtbl::t_fill_enum`].
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

/// One fragment of a scattered (`ALOC_DIST`) local's location, as the facade passes it inside
/// [`LvarLoc::pieces`]. `atype` is the fragment's own `ALOC_*` (a register or stack slot).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LocPiece {
    pub atype: u32,
    pub reg: u32,
    pub sval: i64,
    pub off: u32,
    pub size: u32,
}

/// A local variable's location, decoded from IDA's `argloc_t` and passed to
/// [`EmitVtbl::l_lvar`]. `atype` is the `ALOC_*` discriminant; only the fields it selects are
/// meaningful: `reg1` (REG1 / REG2 low / RREL reg), `reg2` (REG2 high), `sval` (STACK offset /
/// STATIC ea / RREL displacement). `pieces`/`npieces` describe a scattered location and are
/// empty otherwise.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LvarLoc {
    pub atype: u32,
    pub reg1: u32,
    pub reg2: u32,
    pub sval: i64,
    pub pieces: *const LocPiece,
    pub npieces: u32,
}

/// The type-emit callbacks, shared by every walk that builds an interned type table (the
/// ctree walk via [`EmitVtbl::types`] and the bare-tinfo walks). `#[repr(C)]` and field order
/// mirror `idakit_type_vtbl_t`. Every name/member-name span borrows a C++ stack temporary
/// valid only for that single callback (see [`EmitVtbl`]).
#[repr(C)]
pub struct TypeVtbl {
    pub t_scalar: unsafe extern "C" fn(*mut c_void, u32, u32, u32, u64, u32) -> u32,
    pub t_ptr: unsafe extern "C" fn(*mut c_void, u32, u64, u32) -> u32,
    pub t_array: unsafe extern "C" fn(*mut c_void, u32, u64, u64, u32) -> u32,
    pub t_func: unsafe extern "C" fn(*mut c_void, u32, *const u32, usize, u32) -> u32,
    pub t_opaque: unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> u32,
    pub t_named_ref: unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> u32,
    pub t_anon: unsafe extern "C" fn(*mut c_void) -> u32,
    pub t_fill_struct:
        unsafe extern "C" fn(*mut c_void, u32, u32, *const MemberDesc, usize, u64, u32),
    pub t_fill_enum:
        unsafe extern "C" fn(*mut c_void, u32, u32, *const EnumConstDesc, usize, u64, u32),
    pub t_fill_typedef: unsafe extern "C" fn(*mut c_void, u32, u32),
}

/// The callbacks the facade invokes while streaming a ctree walk. The consumer (idakit)
/// builds owned nodes inside each callback and returns the handle the parent will
/// reference; children are emitted before parents. `#[repr(C)]` and field order mirror
/// `idakit_emit_vtbl_t` exactly -- the facade indexes by offset.
///
/// Every `*const c_char`/byte-slice pointer passed to a callback (names, string literals,
/// member and enum-constant names, comments, value arrays) borrows a C++ stack temporary
/// owned by the walk. It is valid for that single callback invocation only and dangles once
/// the callback returns, so a callback must copy any data it needs to outlive the call.
#[repr(C)]
pub struct EmitVtbl {
    pub e_num: unsafe extern "C" fn(*mut c_void, Address, u64, u32) -> u32,
    pub e_fnum: unsafe extern "C" fn(*mut c_void, Address, f64, u32) -> u32,
    pub e_obj:
        unsafe extern "C" fn(*mut c_void, Address, Address, *const c_char, usize, u32) -> u32,
    pub e_var: unsafe extern "C" fn(*mut c_void, Address, u32, u32) -> u32,
    pub e_str: unsafe extern "C" fn(*mut c_void, Address, *const c_char, usize, u32) -> u32,
    pub e_helper: unsafe extern "C" fn(*mut c_void, Address, *const c_char, usize, u32) -> u32,
    pub e_call: unsafe extern "C" fn(*mut c_void, Address, u32, *const u32, usize, u32) -> u32,
    pub e_memref: unsafe extern "C" fn(*mut c_void, Address, u32, u32, u32) -> u32,
    pub e_memptr: unsafe extern "C" fn(*mut c_void, Address, u32, u32, u32) -> u32,
    pub e_deref: unsafe extern "C" fn(*mut c_void, Address, u32, u32, u32) -> u32,
    pub e_op: unsafe extern "C" fn(*mut c_void, Address, u32, u32, u32, u32, u32) -> u32,

    pub s_block: unsafe extern "C" fn(*mut c_void, Address, *const u32, usize) -> u32,
    pub s_expr: unsafe extern "C" fn(*mut c_void, Address, u32) -> u32,
    pub s_if: unsafe extern "C" fn(*mut c_void, Address, u32, u32, u32) -> u32,
    pub s_for: unsafe extern "C" fn(*mut c_void, Address, u32, u32, u32, u32) -> u32,
    pub s_while: unsafe extern "C" fn(*mut c_void, Address, u32, u32) -> u32,
    pub s_do: unsafe extern "C" fn(*mut c_void, Address, u32, u32) -> u32,
    pub s_switch: unsafe extern "C" fn(*mut c_void, Address, u32, *const CaseDesc, usize) -> u32,
    pub s_break: unsafe extern "C" fn(*mut c_void, Address) -> u32,
    pub s_continue: unsafe extern "C" fn(*mut c_void, Address) -> u32,
    pub s_return: unsafe extern "C" fn(*mut c_void, Address, u32) -> u32,
    pub s_goto: unsafe extern "C" fn(*mut c_void, Address, i32) -> u32,
    pub s_asm: unsafe extern "C" fn(*mut c_void, Address, *const u64, usize) -> u32,
    pub s_try: unsafe extern "C" fn(*mut c_void, Address, u32, *const u32, usize) -> u32,
    pub s_throw: unsafe extern "C" fn(*mut c_void, Address, u32) -> u32,
    pub s_empty: unsafe extern "C" fn(*mut c_void, Address) -> u32,

    pub types: TypeVtbl,

    pub l_lvar: unsafe extern "C" fn(
        *mut c_void,
        *const c_char,
        usize,
        u32,
        u32,
        u32,
        *const c_char,
        usize,
        *const LvarLoc,
    ),
}

// hex-rays decompiler
unsafe extern "C" {
    pub fn idakit_hexrays_init() -> c_int;
    pub fn idakit_decompile(address: Address, errbuf: *mut c_char, cap: usize) -> *mut c_void;
    pub fn idakit_cfunc_dispose(cfunc: *mut c_void);
    pub fn idakit_cfunc_pseudocode(cfunc: *mut c_void, buf: *mut c_char, cap: usize) -> i64;
    pub fn idakit_cfunc_ctree_counts(
        cfunc: *mut c_void,
        n_insn: *mut c_int,
        n_expr: *mut c_int,
        n_calls: *mut c_int,
    );
    /// Diagnostic: fill two 256-int per-op expression histograms -- `v_hist` from the SDK's
    /// `ctree_visitor_t` (ground truth), `w_hist` from a mirror of the extraction walker's
    /// recursion. Their per-op difference localizes any extraction under/over-visit.
    pub fn idakit_cfunc_ctree_expr_gap(cfunc: *mut c_void, v_hist: *mut c_int, w_hist: *mut c_int);
    /// Walk `cfunc`'s ctree, driving `vtbl` (with `ctx`) per node and writing the root
    /// statement handle to `*root`. Returns 0 on success, non-zero if `cfunc` is null.
    pub fn idakit_cfunc_walk_ctree(
        cfunc: *mut c_void,
        vtbl: *const EmitVtbl,
        ctx: *mut c_void,
        root: *mut u32,
    ) -> c_int;
}
