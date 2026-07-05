//! Function stack-frame facade (`idakit_frame_*`).

use std::ffi::{c_char, c_int, c_void};

use crate::Address;
use crate::hexrays::TypeVtbl;

/// Callbacks for [`idakit_frame_type_walk`]: the shared type-emit table ([`TypeVtbl`]) plus a
/// per-variable callback. `#[repr(C)]` and field order mirror `idakit_frame_vtbl_t`.
#[repr(C)]
pub struct FrameVtbl {
    pub types: TypeVtbl,
    /// One frame variable: name span, fp-relative `offset`, byte `size`, `flags` (see
    /// [`FRAME_VAR_RETADDR`]/[`FRAME_VAR_SAVREGS`]), and its resolved type handle `ty`.
    pub f_var: unsafe extern "C" fn(*mut c_void, *const c_char, usize, i64, u64, u32, u32),
}

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

    /// Walk the frame of the function at `ea`, driving `v` (with `ctx`): each variable's type
    /// through `v->types`, then the variable via `v->f_var`, and the frame's total byte size into
    /// `*frame_size`. Returns 0 on success, non-zero if there is no function or frame at `ea`.
    pub fn idakit_frame_type_walk(
        ea: Address,
        v: *const FrameVtbl,
        ctx: *mut c_void,
        frame_size: *mut u64,
    ) -> c_int;
}

/// `frame_var` flag: the return-address slot in the frame.
pub const FRAME_VAR_RETADDR: u32 = 1;
/// `frame_var` flag: the saved-registers slot in the frame.
pub const FRAME_VAR_SAVREGS: u32 = 2;
