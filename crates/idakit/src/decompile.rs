//! [`Cfunc`]: an owned decompiled function; disposes its handle on [`Drop`].
//! Exposes pseudocode and ctree counts (the borrowed `Cexpr` AST is a later phase).

use std::ffi::c_void;
use std::marker::PhantomData;

use idakit_sys as sys;

use crate::Idb;
use crate::ctree::{Ctree, ExtractError, Records, build};
use crate::ffi::read_string;

/// Statement / expression / call-site counts of a decompiled function's ctree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtreeCounts {
    pub insns: i32,
    pub exprs: i32,
    pub calls: i32,
}

/// An owned decompiled function. Disposes its kernel handle on drop.
///
/// `handle` is the safety invariant for every call below: non-null (checked at
/// construction), from `idakit_decompile`, disposed exactly once on [`Drop`]. The
/// raw pointer makes `Cfunc` `!Send`, so it lives only on the kernel thread.
pub struct Cfunc<'db> {
    handle: *mut c_void,
    _db: PhantomData<&'db Idb>,
}

impl<'db> Cfunc<'db> {
    /// Take ownership of a non-null `idakit_decompile` handle.
    #[inline]
    pub(crate) fn from_handle(handle: *mut c_void, _db: &'db Idb) -> Self {
        debug_assert!(!handle.is_null(), "Cfunc handle must be non-null");
        Self {
            handle,
            _db: PhantomData,
        }
    }

    /// The rendered pseudocode, tags stripped.
    #[must_use]
    pub fn pseudocode(&self) -> Option<String> {
        // SAFETY: live handle (see type docs).
        read_string(|buf, cap| unsafe { sys::idakit_cfunc_pseudocode(self.handle, buf, cap) })
    }

    /// Counts of statements, expressions, and call sites in the ctree.
    #[must_use]
    pub fn counts(&self) -> CtreeCounts {
        let (mut insns, mut exprs, mut calls) = (0, 0, 0);
        // SAFETY: live handle (see type docs); out-params are valid locals.
        unsafe {
            sys::idakit_cfunc_ctree_counts(self.handle, &mut insns, &mut exprs, &mut calls);
        }
        CtreeCounts {
            insns,
            exprs,
            calls,
        }
    }

    /// Materialize the whole ctree as an owned, `Send` [`Ctree`]: the facade emits a flat
    /// record image on this (kernel) thread, and [`build`] turns it into arenas that any
    /// worker can then analyze.
    pub fn ctree(&self) -> Result<Ctree, ExtractError> {
        // Zeroed (not uninit) so a null handle leaves an all-empty view that `build`
        // rejects cleanly rather than reading uninitialized memory.
        let mut view: sys::CtreeView = unsafe { std::mem::zeroed() };
        // SAFETY: live handle (see type docs); `view` is a valid out-param.
        let handle = unsafe { sys::idakit_cfunc_extract_ctree(self.handle, &mut view) };

        // SAFETY: on success the facade filled `view` with arrays it owns until disposed;
        // `build` copies everything out of these borrows, so the result outlives them.
        let result = unsafe {
            build(&Records {
                types: as_slice(view.types, view.n_types),
                exprs: as_slice(view.exprs, view.n_exprs),
                stmts: as_slice(view.stmts, view.n_stmts),
                nodes: as_slice(view.nodes, view.n_nodes),
                bytes: as_slice(view.bytes, view.n_bytes),
                longs: as_slice(view.longs, view.n_longs),
                cases: as_slice(view.cases, view.n_cases),
                root: view.root,
            })
        };

        // SAFETY: dispose the extraction handle exactly once; a null handle is a no-op.
        unsafe { sys::idakit_ctree_dispose(handle) };
        result
    }
}

/// Borrow a facade array as a slice; a zero length yields an empty slice without
/// dereferencing the (possibly null) pointer.
///
/// # Safety
///
/// For a non-zero `len`, `ptr` must point to `len` initialized `T` valid for the
/// returned borrow's lifetime.
unsafe fn as_slice<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
}

impl Drop for Cfunc<'_> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: live handle (see type docs); disposed exactly once, here.
        unsafe { sys::idakit_cfunc_dispose(self.handle) };
    }
}

impl std::fmt::Debug for Cfunc<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cfunc")
            .field("counts", &self.counts())
            .finish()
    }
}
