//! [`Cfunc`]: an owned decompiled function; disposes its handle on [`Drop`].
//! Exposes pseudocode and ctree counts (the borrowed `Cexpr` AST is a later phase).

use std::ffi::c_void;
use std::marker::PhantomData;

use idakit_sys as sys;

use crate::Idb;
use crate::ctree::{Ctree, ExtractError, walk};
use crate::ffi::read_string;

/// Statement / expression / call-site counts of a decompiled function's ctree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtreeCounts {
    /// Number of statement nodes (`Cinsn`).
    pub insns: i32,
    /// Number of expression nodes (`Cexpr`).
    pub exprs: i32,
    /// Number of call sites.
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

    /// Materialize the whole ctree as an owned, `Send` [`Ctree`]: the facade streams a
    /// depth-first walk on this (kernel) thread, minting owned nodes through callbacks
    /// so any worker can then analyze the result.
    pub fn ctree(&self) -> Result<Ctree, ExtractError> {
        // SAFETY: live handle (see type docs); `walk` copies everything it needs out of
        // the SDK objects, so the result outlives this `cfunc`.
        walk(self.handle)
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
