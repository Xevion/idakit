//! `cxx` `extern "Rust"` opaque-visitor bridge for the ctree walk (`idakit_cxx::cfunc_walk_ctree`).
//!
//! The production ctree walk drives an [`extern "Rust"`] **opaque visitor** ([`CtreeVisitor`])
//! whose `&mut self` methods `cxx` exposes to C++ as callable member functions. The C++ driver in
//! `facade/ctree_cxx.cc` (`walker_t`) walks a decompiled `cfunc_t` depth-first and calls
//! `nodes.e_num(...)`, `nodes.s_if(...)`, `nodes.l_lvar(...)` per node, statement, or local. There is
//! no function-pointer table, no `void*` context: the visitor forwards each call straight into a
//! [`CtreeSink`] the consumer supplies. Node types are resolved through the same opaque tinfo walker
//! [`bridge_typewalk`](crate::bridge_typewalk) uses, driven alongside via [`cfunc_walk_ctree`]'s
//! `type_visitor` address.
//!
//! Per-call data crosses zero-copy, borrowed only for the duration of that one call. Names and
//! string literals are **not** guaranteed valid UTF-8, so every byte-string field crosses as
//! `&[u8]` (`rust::Slice<const uint8_t>`) rather than `&str`; the sink decodes with
//! [`String::from_utf8_lossy`], matching the crate's existing lossy-name convention exactly.
//!
//! # Panic safety
//!
//! A `cxx` `extern "Rust"` function (including an opaque type's methods) that panics is caught at
//! the boundary: `cxx` logs and calls `std::process::abort`, so a panic never unwinds into C++.
//! The visitor methods here are panic-free in the normal path regardless; this is the contract if
//! one ever did.
use std::ptr::NonNull;

/// Absent optional child / sentinel, matching the facade's own `IDAKIT_NONE` constant.
pub const IDAKIT_NONE: u32 = 0xFFFF_FFFF;

/// A ctree walk target the visitor drives inline, one method per expression, statement, and local
/// variable kind.
///
/// The consumer (`idakit`) implements it over its own node builder, and [`CtreeVisitor`] forwards
/// every C++ call straight into it. Expression/statement methods mint and return the walk-local
/// handle the parent will reference; children are visited before parents (post-order), so a
/// method's array/slice arguments are already-minted handles. [`l_lvar`](Self::l_lvar) is void and
/// appended in index order, the order [`e_var`](Self::e_var)'s `idx` refers to. Byte slices (names,
/// string literals, comments) are borrowed for the one call only.
pub trait CtreeSink {
    /// A numeric literal; returns its handle.
    fn e_num(&mut self, ea: u64, value: u64, ty: u32) -> u32;
    /// A floating-point literal; returns its handle.
    fn e_fnum(&mut self, ea: u64, value: f64, ty: u32) -> u32;
    /// A reference to the global object at `target`, named `name`; returns its handle.
    fn e_obj(&mut self, ea: u64, target: u64, name: &[u8], ty: u32) -> u32;
    /// A reference to local variable `idx` (the [`l_lvar`](Self::l_lvar) append order); returns its
    /// handle.
    fn e_var(&mut self, ea: u64, idx: u32, ty: u32) -> u32;
    /// A string literal; returns its handle.
    fn e_str(&mut self, ea: u64, bytes: &[u8], ty: u32) -> u32;
    /// A decompiler-synthesized helper name; returns its handle.
    fn e_helper(&mut self, ea: u64, bytes: &[u8], ty: u32) -> u32;
    /// A call to the already-visited `callee` with the already-visited `args`; returns its handle.
    fn e_call(&mut self, ea: u64, callee: u32, args: &[u32], ty: u32) -> u32;
    /// A `.` member reference into the already-visited `obj` at bit `offset`; returns its handle.
    fn e_memref(&mut self, ea: u64, obj: u32, offset: u32, ty: u32) -> u32;
    /// A `->` member pointer into the already-visited `obj` at bit `offset`; returns its handle.
    fn e_memptr(&mut self, ea: u64, obj: u32, offset: u32, ty: u32) -> u32;
    /// A pointer dereference of the already-visited `x`, `size` bytes; returns its handle.
    fn e_deref(&mut self, ea: u64, x: u32, size: u32, ty: u32) -> u32;
    /// A generic operator node (binary/assign/unary/ternary/cast/index/sizeof/empty/type/insn); the
    /// raw `ctype_t` is passed for the sink to classify, absent operands as [`IDAKIT_NONE`]; returns
    /// its handle.
    fn e_op(&mut self, ea: u64, ctype: u32, x: u32, y: u32, z: u32, ty: u32) -> u32;
    /// A `{ ... }` block of the already-visited `kids`; returns its handle.
    fn s_block(&mut self, ea: u64, kids: &[u32]) -> u32;
    /// An expression statement wrapping the already-visited `e`; returns its handle.
    fn s_expr(&mut self, ea: u64, e: u32) -> u32;
    /// An `if`/`then`/`else` (else is [`IDAKIT_NONE`] when absent); returns its handle.
    fn s_if(&mut self, ea: u64, cond: u32, then_s: u32, else_s: u32) -> u32;
    /// A `for` loop; any of `init`/`cond`/`step` may be [`IDAKIT_NONE`]; returns its handle.
    fn s_for(&mut self, ea: u64, init: u32, cond: u32, step: u32, body: u32) -> u32;
    /// A `while` loop; returns its handle.
    fn s_while(&mut self, ea: u64, cond: u32, body: u32) -> u32;
    /// A `do`/`while` loop; returns its handle.
    fn s_do(&mut self, ea: u64, body: u32, cond: u32) -> u32;
    /// A `switch`, as parallel flat arrays: `bodies[i]` is case `i`'s body handle,
    /// `value_counts[i]` is how many `u64` values case `i` has, and `values` is all case values
    /// concatenated in order (case 0's values, then case 1's, ...). An empty values run is the
    /// default case. Returns its handle.
    fn s_switch(
        &mut self,
        ea: u64,
        expr: u32,
        bodies: &[u32],
        value_counts: &[u32],
        values: &[u64],
    ) -> u32;
    /// A `break`; returns its handle.
    fn s_break(&mut self, ea: u64) -> u32;
    /// A `continue`; returns its handle.
    fn s_continue(&mut self, ea: u64) -> u32;
    /// A `return`, or a bare `return;` when `e` is [`IDAKIT_NONE`]; returns its handle.
    fn s_return(&mut self, ea: u64, e: u32) -> u32;
    /// A `goto` to `label`; returns its handle.
    fn s_goto(&mut self, ea: u64, label: i32) -> u32;
    /// An inline-asm block, one already-computed address per line; returns its handle.
    fn s_asm(&mut self, ea: u64, addrs: &[u64]) -> u32;
    /// A `try`/`catch`, the already-visited guarded `body` and each `catches` block; returns its
    /// handle.
    fn s_try(&mut self, ea: u64, body: u32, catches: &[u32]) -> u32;
    /// A `throw`, or a bare `throw;` when `e` is [`IDAKIT_NONE`]; returns its handle.
    fn s_throw(&mut self, ea: u64, e: u32) -> u32;
    /// An empty statement (or any statement kind the walk doesn't otherwise model); returns its
    /// handle.
    fn s_empty(&mut self, ea: u64) -> u32;
    /// One local variable, appended in index order, the index [`e_var`](Self::e_var)'s `idx`
    /// refers to. `flags`: bit0 `is_arg`, bit1 `is_result`, bit2 `is_byref`. `atype`/`reg1`/`reg2`/
    /// `sval` are the flattened `argloc_t` scalars; `pieces` is the scattered-location fragments,
    /// empty unless `atype` marks a scattered (`ALOC_DIST`) location.
    #[allow(clippy::too_many_arguments)]
    fn l_lvar(
        &mut self,
        name: &[u8],
        ty: u32,
        flags: u32,
        width: u32,
        comment: &[u8],
        atype: u32,
        reg1: u32,
        reg2: u32,
        sval: i64,
        pieces: &[ffi::LocPiece],
    );
}

/// The `cxx` `extern "Rust"` opaque the C++ ctree walk drives by calling its `&mut self` methods,
/// each forwarding into the [`CtreeSink`] it was built over.
///
/// `cxx` generates a C++ class with a member function per method below; `facade/ctree_cxx.cc`
/// receives a `CtreeVisitor&` and calls them. The visitor holds the sink as a lifetime-erased raw
/// pointer: [`ctree_visitor`] is its only constructor, and the caller keeps the borrowed sink
/// alive across the one synchronous walk, so the pointer is always valid and unaliased when a
/// method reborrows it.
pub struct CtreeVisitor {
    sink: NonNull<dyn CtreeSink>,
}

impl CtreeVisitor {
    /// Reborrow the erased sink for one callback.
    ///
    /// # Safety
    /// See the type docs: the pointer is valid and unaliased for the walk (single-threaded,
    /// non-reentrant, the walk holds the only borrow).
    fn sink(&mut self) -> &mut dyn CtreeSink {
        unsafe { self.sink.as_mut() }
    }

    fn e_num(&mut self, ea: u64, value: u64, ty: u32) -> u32 {
        self.sink().e_num(ea, value, ty)
    }
    fn e_fnum(&mut self, ea: u64, value: f64, ty: u32) -> u32 {
        self.sink().e_fnum(ea, value, ty)
    }
    fn e_obj(&mut self, ea: u64, target: u64, name: &[u8], ty: u32) -> u32 {
        self.sink().e_obj(ea, target, name, ty)
    }
    fn e_var(&mut self, ea: u64, idx: u32, ty: u32) -> u32 {
        self.sink().e_var(ea, idx, ty)
    }
    fn e_str(&mut self, ea: u64, bytes: &[u8], ty: u32) -> u32 {
        self.sink().e_str(ea, bytes, ty)
    }
    fn e_helper(&mut self, ea: u64, bytes: &[u8], ty: u32) -> u32 {
        self.sink().e_helper(ea, bytes, ty)
    }
    fn e_call(&mut self, ea: u64, callee: u32, args: &[u32], ty: u32) -> u32 {
        self.sink().e_call(ea, callee, args, ty)
    }
    fn e_memref(&mut self, ea: u64, obj: u32, offset: u32, ty: u32) -> u32 {
        self.sink().e_memref(ea, obj, offset, ty)
    }
    fn e_memptr(&mut self, ea: u64, obj: u32, offset: u32, ty: u32) -> u32 {
        self.sink().e_memptr(ea, obj, offset, ty)
    }
    fn e_deref(&mut self, ea: u64, x: u32, size: u32, ty: u32) -> u32 {
        self.sink().e_deref(ea, x, size, ty)
    }
    fn e_op(&mut self, ea: u64, ctype: u32, x: u32, y: u32, z: u32, ty: u32) -> u32 {
        self.sink().e_op(ea, ctype, x, y, z, ty)
    }
    fn s_block(&mut self, ea: u64, kids: &[u32]) -> u32 {
        self.sink().s_block(ea, kids)
    }
    fn s_expr(&mut self, ea: u64, e: u32) -> u32 {
        self.sink().s_expr(ea, e)
    }
    fn s_if(&mut self, ea: u64, cond: u32, then_s: u32, else_s: u32) -> u32 {
        self.sink().s_if(ea, cond, then_s, else_s)
    }
    fn s_for(&mut self, ea: u64, init: u32, cond: u32, step: u32, body: u32) -> u32 {
        self.sink().s_for(ea, init, cond, step, body)
    }
    fn s_while(&mut self, ea: u64, cond: u32, body: u32) -> u32 {
        self.sink().s_while(ea, cond, body)
    }
    fn s_do(&mut self, ea: u64, body: u32, cond: u32) -> u32 {
        self.sink().s_do(ea, body, cond)
    }
    fn s_switch(
        &mut self,
        ea: u64,
        expr: u32,
        bodies: &[u32],
        value_counts: &[u32],
        values: &[u64],
    ) -> u32 {
        self.sink().s_switch(ea, expr, bodies, value_counts, values)
    }
    fn s_break(&mut self, ea: u64) -> u32 {
        self.sink().s_break(ea)
    }
    fn s_continue(&mut self, ea: u64) -> u32 {
        self.sink().s_continue(ea)
    }
    fn s_return(&mut self, ea: u64, e: u32) -> u32 {
        self.sink().s_return(ea, e)
    }
    fn s_goto(&mut self, ea: u64, label: i32) -> u32 {
        self.sink().s_goto(ea, label)
    }
    fn s_asm(&mut self, ea: u64, addrs: &[u64]) -> u32 {
        self.sink().s_asm(ea, addrs)
    }
    fn s_try(&mut self, ea: u64, body: u32, catches: &[u32]) -> u32 {
        self.sink().s_try(ea, body, catches)
    }
    fn s_throw(&mut self, ea: u64, e: u32) -> u32 {
        self.sink().s_throw(ea, e)
    }
    fn s_empty(&mut self, ea: u64) -> u32 {
        self.sink().s_empty(ea)
    }
    #[allow(clippy::too_many_arguments)]
    fn l_lvar(
        &mut self,
        name: &[u8],
        ty: u32,
        flags: u32,
        width: u32,
        comment: &[u8],
        atype: u32,
        reg1: u32,
        reg2: u32,
        sval: i64,
        pieces: &[ffi::LocPiece],
    ) {
        self.sink().l_lvar(
            name, ty, flags, width, comment, atype, reg1, reg2, sval, pieces,
        );
    }
}

#[cxx::bridge(namespace = "idakit_cxx")]
mod ffi {
    /// One fragment of a scattered (`ALOC_DIST`) local's location, the same shape as the deleted
    /// `repr(C)` `LocPiece`. `atype` is the fragment's own `ALOC_*` (a register or stack slot);
    /// `off`/`size` give the byte range of the whole value this fragment covers.
    struct LocPiece {
        /// The fragment's own `ALOC_*` discriminant.
        atype: u32,
        /// Register number, meaningful only for a register fragment.
        reg: u32,
        /// Stack offset or static address, meaningful only for a stack/static fragment.
        sval: i64,
        /// Byte offset of this fragment within the whole scattered value.
        off: u32,
        /// Byte size of this fragment.
        size: u32,
    }

    extern "Rust" {
        type CtreeVisitor;

        fn e_num(self: &mut CtreeVisitor, ea: u64, value: u64, ty: u32) -> u32;
        fn e_fnum(self: &mut CtreeVisitor, ea: u64, value: f64, ty: u32) -> u32;
        fn e_obj(self: &mut CtreeVisitor, ea: u64, target: u64, name: &[u8], ty: u32) -> u32;
        fn e_var(self: &mut CtreeVisitor, ea: u64, idx: u32, ty: u32) -> u32;
        fn e_str(self: &mut CtreeVisitor, ea: u64, bytes: &[u8], ty: u32) -> u32;
        fn e_helper(self: &mut CtreeVisitor, ea: u64, bytes: &[u8], ty: u32) -> u32;
        fn e_call(self: &mut CtreeVisitor, ea: u64, callee: u32, args: &[u32], ty: u32) -> u32;
        fn e_memref(self: &mut CtreeVisitor, ea: u64, obj: u32, offset: u32, ty: u32) -> u32;
        fn e_memptr(self: &mut CtreeVisitor, ea: u64, obj: u32, offset: u32, ty: u32) -> u32;
        fn e_deref(self: &mut CtreeVisitor, ea: u64, x: u32, size: u32, ty: u32) -> u32;
        fn e_op(
            self: &mut CtreeVisitor,
            ea: u64,
            ctype: u32,
            x: u32,
            y: u32,
            z: u32,
            ty: u32,
        ) -> u32;
        fn s_block(self: &mut CtreeVisitor, ea: u64, kids: &[u32]) -> u32;
        fn s_expr(self: &mut CtreeVisitor, ea: u64, e: u32) -> u32;
        fn s_if(self: &mut CtreeVisitor, ea: u64, cond: u32, then_s: u32, else_s: u32) -> u32;
        fn s_for(
            self: &mut CtreeVisitor,
            ea: u64,
            init: u32,
            cond: u32,
            step: u32,
            body: u32,
        ) -> u32;
        fn s_while(self: &mut CtreeVisitor, ea: u64, cond: u32, body: u32) -> u32;
        fn s_do(self: &mut CtreeVisitor, ea: u64, body: u32, cond: u32) -> u32;
        fn s_switch(
            self: &mut CtreeVisitor,
            ea: u64,
            expr: u32,
            bodies: &[u32],
            value_counts: &[u32],
            values: &[u64],
        ) -> u32;
        fn s_break(self: &mut CtreeVisitor, ea: u64) -> u32;
        fn s_continue(self: &mut CtreeVisitor, ea: u64) -> u32;
        fn s_return(self: &mut CtreeVisitor, ea: u64, e: u32) -> u32;
        fn s_goto(self: &mut CtreeVisitor, ea: u64, label: i32) -> u32;
        fn s_asm(self: &mut CtreeVisitor, ea: u64, addrs: &[u64]) -> u32;
        fn s_try(self: &mut CtreeVisitor, ea: u64, body: u32, catches: &[u32]) -> u32;
        fn s_throw(self: &mut CtreeVisitor, ea: u64, e: u32) -> u32;
        fn s_empty(self: &mut CtreeVisitor, ea: u64) -> u32;
        // The flattened argloc scalars (atype/reg1/reg2/sval) plus pieces push this past clippy's
        // 7-argument default; splitting them into a struct would cross an extra type for no
        // benefit, since every field is already a plain scalar the C++ side computed inline.
        #[allow(clippy::too_many_arguments)]
        fn l_lvar(
            self: &mut CtreeVisitor,
            name: &[u8],
            ty: u32,
            flags: u32,
            width: u32,
            comment: &[u8],
            atype: u32,
            reg1: u32,
            reg2: u32,
            sval: i64,
            pieces: &[LocPiece],
        );
    }

    unsafe extern "C++" {
        include!("ctree_cxx.h");

        /// The same `cfuncptr_t` the [`bridge_gen`](crate::bridge_gen) bridge bound; this is a
        /// type alias, not a fresh opaque type, so [`decompile`](crate::decompile)'s result feeds
        /// [`cfunc_walk_ctree`] with no conversion.
        #[namespace = ""]
        #[cxx_name = "cfuncptr_t"]
        type CFunc = crate::bridge_gen::CFunc;

        /// Initialize the Hex-Rays decompiler (loading the plugin if needed); `true` once ready.
        fn hexrays_init() -> bool;
        /// Evict the cached decompilation for `ea`; `true` if an entry existed, `false` if none or
        /// the decompiler is not initialized.
        fn mark_cfunc_dirty(ea: u64, close_views: bool) -> bool;
        /// Evict every cached decompilation; a no-op if the decompiler is not initialized.
        fn clear_cached_cfuncs();
        /// Whether `ea` has a cached decompilation; `false` if none or not initialized.
        fn has_cached_cfunc(ea: u64) -> bool;

        /// Walk `cfunc`'s ctree, minting nodes and locals through `nodes` and node types through
        /// the tinfo walker whose pointer is passed as an integer address in `type_visitor` (`cxx`
        /// has no `c_void`; the C++ side reinterprets it back to `void*` for the shared type
        /// walker). Returns the root statement handle.
        ///
        /// # Safety
        /// `type_visitor` must be a live `TypeWalkVisitor*`, cast to `usize`, that outlives the
        /// call.
        #[allow(clippy::missing_safety_doc)]
        unsafe fn cfunc_walk_ctree(
            cfunc: &CFunc,
            nodes: &mut CtreeVisitor,
            type_visitor: usize,
        ) -> u32;
    }
}

pub use ffi::{
    LocPiece, cfunc_walk_ctree, clear_cached_cfuncs, has_cached_cfunc, hexrays_init,
    mark_cfunc_dirty,
};

/// Wrap a raw sink pointer as a [`CtreeVisitor`] for a walk driven by [`cfunc_walk_ctree`].
///
/// Passing `sink` as a raw pointer (not `&mut`) lets the caller derive both it and any node
/// context it aliases (e.g. a shared builder) from one provenance, so per-callback reborrows
/// never conflict.
///
/// # Safety
/// `sink` must be non-null and point to a live [`CtreeSink`] that outlives every use of the
/// returned visitor, and stay unaliased for the duration of each callback (the walk is
/// single-threaded and non-reentrant).
#[must_use]
pub unsafe fn ctree_visitor(sink: *mut dyn CtreeSink) -> CtreeVisitor {
    CtreeVisitor {
        sink: NonNull::new(sink).expect("sink pointer must be non-null"),
    }
}
