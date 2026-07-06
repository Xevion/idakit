//! [`DecompiledFunction`]: an owned decompiled function; disposes its handle on [`Drop`].
//! Exposes pseudocode and ctree counts (the borrowed `ExpressionKind` AST is a later phase).

use std::ffi::c_void;
use std::marker::PhantomData;

use idakit_sys as sys;

use crate::Database;
use crate::address::Address;
use crate::ctree::{Ctree, ExtractError, walk};
use crate::error::{Error, Result};
use crate::ffi::read_string;

impl Database {
    /// Decompile the function at `address` and materialize its ctree. Sugar for
    /// [`function(address)`](Self::function)`.`[`ctree()`](crate::function::Function::ctree).
    pub fn ctree(&self, address: Address) -> Result<Ctree> {
        self.function(address).ctree()
    }

    /// Decompile the function containing `address` (inits Hex-Rays on first use).
    pub fn decompile(&self, address: Address) -> Result<DecompiledFunction<'_>> {
        if !self.hexrays_ready.get() {
            let rc = self.hexrays_init();
            if rc != 1 {
                return Err(Error::HexRaysInit { code: rc });
            }
            self.hexrays_ready.set(true);
        }
        let (handle, reason) = self.decompile_at(address);
        if handle.is_null() {
            // A trapped fatal exit() during decompilation is a dead kernel, not an ordinary
            // decompile miss -- surface it as such.
            if self.was_trapped() {
                return Err(self.kernel_exit_error());
            }
            return Err(Error::Decompile {
                address: address.get(),
                reason,
            });
        }
        Ok(DecompiledFunction::from_handle(handle, self))
    }
}

/// Statement / expression / call-site counts of a decompiled function's ctree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtreeCounts {
    /// Number of statement nodes (`StatementKind`).
    pub insns: i32,
    /// Number of expression nodes (`ExpressionKind`).
    pub expressions: i32,
    /// Number of call sites.
    pub calls: i32,
}

/// An owned decompiled function. Disposes its kernel handle on drop.
///
/// `handle` is the safety invariant for every call below: non-null (checked at
/// construction), from `idakit_decompile`, disposed exactly once on [`Drop`]. The
/// raw pointer makes `DecompiledFunction` `!Send`, so it lives only on the kernel thread.
pub struct DecompiledFunction<'db> {
    handle: *mut c_void,
    _db: PhantomData<&'db Database>,
}

impl<'db> DecompiledFunction<'db> {
    /// Take ownership of a non-null `idakit_decompile` handle.
    #[inline]
    pub(crate) fn from_handle(handle: *mut c_void, _db: &'db Database) -> Self {
        debug_assert!(
            !handle.is_null(),
            "DecompiledFunction handle must be non-null"
        );
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
        let (mut insns, mut expressions, mut calls) = (0, 0, 0);
        // SAFETY: live handle (see type docs); out-params are valid locals.
        unsafe {
            sys::idakit_cfunc_ctree_counts(self.handle, &mut insns, &mut expressions, &mut calls);
        }
        CtreeCounts {
            insns,
            expressions,
            calls,
        }
    }

    /// Diagnostic anchor for extraction fidelity: `(visitor_total, expected)` where `visitor_total`
    /// is every expression the SDK's own ctree visitor sees, and `expected` is how many the
    /// extraction walker should materialize -- `visitor_total` minus the `cot_empty` placeholders
    /// sitting in *optional* operand slots (a `for(;;)` init/cond/step, a bare `return;`) that the
    /// walker faithfully elides to `None`. A faithful [`ctree`](Self::ctree) has exactly `expected`
    /// expression nodes; a shortfall or surplus is a real drop or invention.
    #[must_use]
    pub fn expr_extraction_expectation(&self) -> (i32, i32) {
        let (mut v, mut w) = ([0i32; 256], [0i32; 256]);
        // SAFETY: live handle (see type docs); both out-params are 256-int buffers.
        unsafe {
            sys::idakit_cfunc_ctree_expr_gap(self.handle, v.as_mut_ptr(), w.as_mut_ptr());
        }
        (v.iter().sum(), w.iter().sum())
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

impl Drop for DecompiledFunction<'_> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: live handle (see type docs); disposed exactly once, here.
        unsafe { sys::idakit_cfunc_dispose(self.handle) };
    }
}

impl std::fmt::Debug for DecompiledFunction<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecompiledFunction")
            .field("counts", &self.counts())
            .finish()
    }
}
