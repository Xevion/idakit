//! [`Cfunc`]: an owned decompiled function; disposes its handle on [`Drop`].
//! Exposes pseudocode and ctree counts (the borrowed `Cexpr` AST is a later phase).

use std::ffi::c_void;
use std::marker::PhantomData;

use idakit_sys as sys;

use crate::Idb;
use crate::ffi::read_string;

/// Statement / expression / call-site counts of a decompiled function's ctree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtreeCounts {
    pub insns: i32,
    pub exprs: i32,
    pub calls: i32,
}

/// An owned decompiled function. Disposes its kernel handle on drop.
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
        read_string(|buf, cap| unsafe { sys::idakit_cfunc_pseudocode(self.handle, buf, cap) })
    }

    /// Counts of statements, expressions, and call sites in the ctree.
    #[must_use]
    pub fn counts(&self) -> CtreeCounts {
        let (mut insns, mut exprs, mut calls) = (0, 0, 0);
        unsafe {
            sys::idakit_cfunc_ctree_counts(self.handle, &mut insns, &mut exprs, &mut calls);
        }
        CtreeCounts {
            insns,
            exprs,
            calls,
        }
    }
}

impl Drop for Cfunc<'_> {
    #[inline]
    fn drop(&mut self) {
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
