//! Decompiles a function to C pseudocode and a walkable [`Ctree`] syntax tree.
//!
//! [`Database::decompile`] runs Hex-Rays on the function at an address and returns a
//! [`DecompiledFunction`] carrying the pseudocode text and [`CtreeCounts`]. Its [`Ctree`] is an
//! owned, `Send` syntax tree for structured analysis off the kernel thread.

pub mod ctree;

use std::collections::HashSet;
use std::marker::PhantomData;

use idakit_sys as sys;

use crate::Database;
use crate::address::Address;
use crate::decompiler::ctree::{Ctree, ExtractError, walk};
use crate::error::{Error, Result};

impl Database {
    /// Decompiles the function at `address` and materializes its ctree.
    ///
    /// Sugar for calling [`ctree()`](crate::function::Function::ctree) on
    /// [`function(address)`](Self::function).
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
            if !self.hexrays_init() {
                return Err(Error::HexRaysInit);
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

    /// Evict one function's cached decompilation, forcing a fresh decompile on next access.
    ///
    /// Returns whether a cached entry existed. A no-op returning `false` when the decompiler was
    /// never initialized, since nothing is cached yet.
    ///
    /// This evicts only the named function. A prototype change that alters how callers render its
    /// call sites does not propagate here, since Hex-Rays keeps no caller graph: invalidate each
    /// caller too, or drive the edit through the [`FunctionEdit`](crate::function::FunctionEdit)
    /// cursor, which does it automatically.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let entry = db.functions().next().unwrap().address();
    /// if db.decompile(entry).is_ok() {
    ///     assert!(db.is_decompilation_cached(entry));
    ///     assert!(db.invalidate_decompilation(entry));
    ///     assert!(!db.is_decompilation_cached(entry));
    /// }
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[doc(alias("mark_cfunc_dirty"))]
    pub fn invalidate_decompilation(&mut self, address: Address) -> bool {
        self.hexrays_ready.get() && self.mark_cfunc_dirty(address, false)
    }

    /// Evict every cached decompilation, the broad hammer for a whole-library structural change.
    ///
    /// Prefer [`invalidate_decompilation`](Self::invalidate_decompilation) for a single function. A
    /// no-op when the decompiler was never initialized.
    #[doc(alias("clear_cached_cfuncs"))]
    pub fn clear_decompilation_cache(&mut self) {
        if self.hexrays_ready.get() {
            self.clear_cached_cfuncs();
        }
    }

    /// Whether the function at `address` has a cached decompilation.
    ///
    /// Always `false` when the decompiler was never initialized, since nothing is cached.
    #[must_use]
    #[doc(alias("has_cached_cfunc"))]
    pub fn is_decompilation_cached(&self, address: Address) -> bool {
        self.hexrays_ready.get() && self.has_cached_cfunc(address)
    }

    /// Evict the decompilation of `entry` and of every function that directly references it, so a
    /// rename or retype re-renders at those sites. A no-op if the decompiler was never initialized.
    ///
    /// Reference sites are found through every cross-reference to `entry`, not just calls and jumps:
    /// an address taken into a function pointer or vtable is a data reference, yet Hex-Rays still
    /// prints the name there. Any reference whose source sits inside a function marks that function;
    /// a source outside every function resolves to `BADADDR` and is skipped.
    ///
    /// Only direct references are marked. A type change that Hex-Rays propagates across a call, into
    /// a function that has no cross-reference to `entry`, leaves that function's cached text stale;
    /// reach for [`clear_decompilation_cache`](Self::clear_decompilation_cache) when an edit's
    /// effects can travel past direct references.
    pub(crate) fn invalidate_decompilation_dependents(&mut self, entry: Address) {
        if !self.hexrays_ready.get() {
            return;
        }
        self.mark_cfunc_dirty(entry, false);
        let mut seen = HashSet::from([entry]);
        for xref in self.xrefs_to(entry) {
            let Some(referrer) = Address::try_new(self.func_start(xref.from)) else {
                continue;
            };
            if seen.insert(referrer) {
                self.mark_cfunc_dirty(referrer, false);
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
/// `handle` is a [`UniquePtr`](cxx::UniquePtr) of [`CFunc`](sys::CFunc), non-null by
/// construction; cxx's deleter runs `~cfuncptr_t` (`release()`) on drop. A
/// `PhantomData<*const ()>` keeps `DecompiledFunction` `!Send`, so it lives only on the kernel
/// thread.
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

    /// Re-print the pseudocode from this handle's current ctree, then return it.
    ///
    /// Roughly 70x cheaper than a fresh [`decompile`](Database::decompile), since it re-walks the
    /// already-decompiled ctree instead of running the microcode pipeline again: a rename resolves
    /// fresh, since ctree nodes reference callees and symbols by address, not by baked-in name. It
    /// does not reflect a structural, type, or prototype change made after this handle was
    /// produced, since those change the ctree itself, not just how it prints; get a fresh handle
    /// through [`decompile`](Database::decompile) for that.
    #[must_use]
    #[doc(alias("refresh_func_ctext"))]
    pub fn refresh_text(&self) -> Option<String> {
        sys::cfunc_refresh_text(self.cfunc()).ok()
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
        walk(self.cfunc())
    }
}

impl std::fmt::Debug for DecompiledFunction<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecompiledFunction")
            .field("counts", &self.counts())
            .finish()
    }
}
