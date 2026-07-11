//! Decompiles a function to C pseudocode and a walkable [`Ctree`] syntax tree.
//!
//! [`Database::decompile`] runs Hex-Rays on the function at an address and returns a
//! [`DecompiledFunction`] carrying the pseudocode text and [`CtreeCounts`]. Its [`Ctree`] is an
//! owned, `Send` syntax tree for structured analysis off the kernel thread.

pub mod ctree;

use std::ffi::c_void;
use std::marker::PhantomData;

use idakit_sys as sys;

use crate::Database;
use crate::address::Address;
use crate::decompiler::ctree::{Ctree, ExtractError, walk};
use crate::error::{Error, Result};

impl Database {
    /// Decompiles the function at `address` and materializes its ctree.
    ///
    /// Sugar for
    /// [`function(address)`](Self::function)`.`[`ctree()`](crate::function::Function::ctree).
    ///
    /// # Errors
    /// Propagates [`Function::ctree`](crate::function::Function::ctree)'s errors.
    pub fn ctree(&self, address: Address) -> Result<Ctree> {
        self.function(address).ctree()
    }

    /// Decompiles the function containing `address` (inits Hex-Rays on first use).
    ///
    /// # Errors
    /// [`Error::HexRaysInit`] if the decompiler could not be initialized, [`Error::Decompile`]
    /// if Hex-Rays rejected the function, or [`Error::KernelExit`] if decompilation trapped a
    /// fatal exit.
    #[doc(alias("decompile_func"))]
    pub fn decompile(&self, address: Address) -> Result<DecompiledFunction<'_>> {
        if !self.hexrays_ready.get() {
            let rc = self.hexrays_init();
            if rc != 1 {
                return Err(Error::HexRaysInit { code: rc });
            }
            self.hexrays_ready.set(true);
        }
        match sys::decompile(address.get()) {
            Ok(handle) => Ok(DecompiledFunction::from_handle(handle, self)),
            Err(e) => {
                // A trapped fatal exit() during decompilation is a dead kernel, not an ordinary
                // decompile miss, so surface it as such.
                if self.was_trapped() {
                    return Err(self.kernel_exit_error());
                }
                Err(Error::Decompile {
                    address: address.get(),
                    reason: e.what().to_owned(),
                })
            }
        }
    }
}

/// Statement, expression, and call-site counts of a decompiled function's syntax tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(alias("ctree_visitor_t"))]
pub struct CtreeCounts {
    /// Number of statement nodes (`StatementKind`).
    pub insns: i32,
    /// Number of expression nodes (`ExpressionKind`).
    pub expressions: i32,
    /// Number of call sites.
    pub calls: i32,
}

/// A decompiled function that frees its Hex-Rays result on [`Drop`].
///
/// `handle` is a [`UniquePtr`](cxx::UniquePtr)`<`[`CFunc`](sys::CFunc)`>`, non-null by construction;
/// cxx's deleter runs `~cfuncptr_t` (`release()`) on drop. A `PhantomData<*const ()>` keeps
/// `DecompiledFunction` `!Send`, so it lives only on the kernel thread.
#[doc(alias("cfuncptr_t", "cfunc_t"))]
pub struct DecompiledFunction<'db> {
    handle: cxx::UniquePtr<sys::CFunc>,
    _db: PhantomData<&'db Database>,
    _not_send: PhantomData<*const ()>,
}

impl<'db> DecompiledFunction<'db> {
    /// Take ownership of a non-null decompilation handle.
    #[inline]
    pub(crate) fn from_handle(handle: cxx::UniquePtr<sys::CFunc>, _db: &'db Database) -> Self {
        debug_assert!(!handle.is_null());
        Self {
            handle,
            _db: PhantomData,
            _not_send: PhantomData,
        }
    }

    /// The live `cfuncptr_t` behind the handle, non-null by construction (see the type docs).
    #[inline]
    fn cfunc(&self) -> &sys::CFunc {
        self.handle.as_ref().expect("live handle")
    }

    /// The rendered pseudocode, tags stripped.
    #[must_use]
    #[doc(alias("get_pseudocode"))]
    pub fn pseudocode(&self) -> Option<String> {
        sys::cfunc_pseudocode(self.cfunc()).ok()
    }

    /// Counts of statements, expressions, and call sites in the ctree.
    #[must_use]
    pub fn counts(&self) -> CtreeCounts {
        let c = sys::cfunc_counts(self.cfunc());
        CtreeCounts {
            insns: c.insns,
            expressions: c.expressions,
            calls: c.calls,
        }
    }

    /// Diagnostic anchor for extraction fidelity: `(visitor_total, expected)` where
    /// `visitor_total` is every expression the SDK's own ctree visitor sees, and `expected` is
    /// how many the extraction walker should materialize, namely `visitor_total` minus the
    /// empty-expression placeholders sitting in *optional* operand slots (a `for(;;)`
    /// init/cond/step, a bare `return;`) that the walker faithfully elides to `None`.
    ///
    /// A faithful [`ctree`](Self::ctree) has exactly `expected` expression nodes; a shortfall or
    /// surplus is a real drop or invention.
    #[must_use]
    pub fn expr_extraction_expectation(&self) -> (i32, i32) {
        let g = sys::cfunc_expr_gap(self.cfunc());
        (g.visitor_total, g.expected)
    }

    /// Materializes the whole ctree as an owned, `Send` [`Ctree`]: the facade streams a
    /// depth-first walk on this (kernel) thread, minting owned nodes through callbacks so any
    /// worker can then analyze the result.
    ///
    /// # Errors
    /// [`ExtractError`] if the ctree fails to materialize.
    pub fn ctree(&self) -> Result<Ctree, ExtractError> {
        // The UniquePtr holds the cfuncptr_t the raw walk expects (the generated `decompile` made
        // the same `new cfuncptr_t`), and keeps it alive across the walk. `walk` copies everything
        // it needs out of the SDK objects, so the result outlives this `cfunc`.
        let cfunc = self.cfunc() as *const sys::CFunc as *mut c_void;
        walk(cfunc)
    }
}

impl std::fmt::Debug for DecompiledFunction<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecompiledFunction")
            .field("counts", &self.counts())
            .finish()
    }
}
