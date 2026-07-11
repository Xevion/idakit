//! `cxx` opaque-handle bridge for the control-flow-graph domain (`idakit_cxx::cfg_*`).
//!
//! The SDK's `qflow_chart_t` is exposed as a `cxx` opaque type (`FlowChart`) owned by
//! [`UniquePtr`](cxx::UniquePtr): the C++ constructor free-function `cfg_build` yields
//! `std::unique_ptr<qflow_chart_t>`, and dropping the `UniquePtr` calls the C++ deleter. That
//! retires the raw layer's manual `idakit_cfg_free` plus a Rust `Drop` impl entirely. The
//! bodies are hand-written in `facade/cfg_cxx.cc` (declarations in `facade/cfg_cxx.h`), same
//! split as the segment bridge; this coexists with the raw `idakit_cfg_*` facade rather than
//! replacing it.
//!
//! [`BlockInfo`] is a `cxx` **shared struct**: one POD declared once here, generated into both
//! languages, and returned by value from `cfg_block`. It replaces the raw path's
//! `(n, *out start, *out end, *out kind) -> int` out-param dance with a single fallible
//! return. Out-of-range block/edge indices throw on the C++ side and surface as a Rust `Err`.
//!
//! [`FlowChart`] is bound to the SDK's `qflow_chart_t` through a hand-written
//! [`cxx::ExternType`] impl (`type_id!("qflow_chart_t")`, `Kind = Opaque`) rather than an
//! in-bridge `type FlowChart;` plus a C++ `using` alias. Because the impl names the real SDK
//! symbol, the *same* Rust `FlowChart` type is shareable across bridges: the sibling
//! [`bridge_cfg2`](crate::bridge_cfg2) bridge references `crate::bridge_cfg::FlowChart` and
//! accepts a `&FlowChart` built here, which the alias approach could not express.

/// The SDK's `qflow_chart_t`, an opaque C++ type handled only behind indirection.
///
/// Bound to the real C++ symbol by the [`cxx::ExternType`] impl below (`Kind = Opaque`, since
/// `qflow_chart_t` has a virtual destructor). The opaque body mirrors `cxx`'s own generated
/// opaque representation, so the type is zero-sized, `!Unpin`, and never held by value in Rust.
#[repr(C)]
pub struct FlowChart {
    _private: cxx::private::Opaque,
}

// SAFETY: the type id names the real SDK class qflow_chart_t; Opaque is correct because
// qflow_chart_t has a virtual destructor (nontrivial), so it may only cross the bridge behind a
// reference or UniquePtr, never by value.
unsafe impl cxx::ExternType for FlowChart {
    type Id = cxx::type_id!("qflow_chart_t");
    type Kind = cxx::kind::Opaque;
}

#[cxx::bridge(namespace = "idakit_cxx")]
mod ffi {
    /// One basic block's bounds and kind, returned by value from [`cfg_block`].
    struct BlockInfo {
        /// Start address of the block.
        start: u64,
        /// End address (exclusive) of the block.
        end: u64,
        /// Raw `fc_block_type_t` discriminant (`fcb_normal`, `fcb_ret`, ...).
        kind: i32,
    }

    unsafe extern "C++" {
        include!("cfg_cxx.h");

        /// The control-flow graph of one function, the SDK's `qflow_chart_t`, bound by
        /// [`super::FlowChart`]'s hand-written `ExternType` impl.
        ///
        /// `#[namespace = ""]` + `#[cxx_name = "qflow_chart_t"]` make `cxx` emit the real global
        /// `::qflow_chart_t`, so the earlier C++ `using FlowChart = ::qflow_chart_t;` alias is
        /// gone: the SDK header supplies the type directly.
        #[namespace = ""]
        #[cxx_name = "qflow_chart_t"]
        type FlowChart = super::FlowChart;

        /// Build the flow chart for the function containing `ea`; `Err` when no function is
        /// there. Runs analysis, so it can also fail from a thrown SDK exception.
        fn cfg_build(ea: u64, flags: i32) -> Result<UniquePtr<FlowChart>>;
        /// Number of basic blocks, bound to the SDK's `qflow_chart_t::size()` **member**
        /// function via the `self:` receiver (contrast the free-function accessors below). The
        /// return type is `i32` because it must match the member's exact `int` signature: `cxx`
        /// takes the address of the member and would reject a `usize` mismatch at compile time.
        fn size(self: &FlowChart) -> i32;
        /// Total number of basic blocks (external blocks included).
        fn cfg_nblocks(fc: &FlowChart) -> usize;
        /// Number of blocks belonging to the function's own range.
        fn cfg_nproper(fc: &FlowChart) -> usize;
        /// Bounds and kind of block `n`; `Err` when `n` is out of range.
        fn cfg_block(fc: &FlowChart, n: usize) -> Result<BlockInfo>;
        /// Number of successors of block `n` (`0` when `n` is out of range).
        fn cfg_nsucc(fc: &FlowChart, n: usize) -> usize;
        /// The `i`-th successor block index of block `n`; `Err` when `n`/`i` is out of range.
        fn cfg_succ(fc: &FlowChart, n: usize, i: usize) -> Result<usize>;
        /// Number of predecessors of block `n` (`0` when `n` is out of range).
        fn cfg_npred(fc: &FlowChart, n: usize) -> usize;
        /// The `i`-th predecessor block index of block `n`; `Err` when `n`/`i` is out of range.
        fn cfg_pred(fc: &FlowChart, n: usize, i: usize) -> Result<usize>;

        /// The whole successor edge list of block `n` in one call; `Err` when `n` is out of
        /// range. Copies the SDK's `intvec_t` (`qvector<int>`) into an owned [`Vec<u32>`],
        /// retiring the per-index [`cfg_nsucc`] + [`cfg_succ`] loop.
        fn cfg_succs(fc: &FlowChart, n: usize) -> Result<Vec<u32>>;
        /// The whole predecessor edge list of block `n` in one call; `Err` when `n` is out of
        /// range. The predecessor twin of [`cfg_succs`].
        fn cfg_preds(fc: &FlowChart, n: usize) -> Result<Vec<u32>>;
    }

    // Explicit instantiation of the `UniquePtr<FlowChart>` glue. A hand-written `ExternType` is
    // not declared in any bridge, so `cxx` does not auto-generate its container support the way
    // it does for an in-bridge `type X;`; this empty impl forces it.
    impl UniquePtr<FlowChart> {}
}

pub use ffi::{
    BlockInfo, cfg_block, cfg_build, cfg_nblocks, cfg_npred, cfg_nproper, cfg_nsucc, cfg_pred,
    cfg_preds, cfg_succ, cfg_succs,
};
