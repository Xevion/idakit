//! `cxx` bindings for IDA's own generic container `qvector<T>` (`idakit_cxx::*vec_*`).
//!
//! `cxx` has no generic-template support and its built-in `CxxVector<T>` is `std::vector`-only,
//! so it cannot match `qvector`'s `{ T* array; size_t n; size_t alloc; }` ABI. This module
//! applies the KDAB cxx-qt per-instantiation recipe: each concrete `qvector<T>` is bound as its
//! own `Opaque` [`cxx::ExternType`] (one distinct `type_id!` per instantiation), and the
//! mechanical per-`T` boilerplate is emitted by the [`qvec_opaque!`] macro. Two instantiations
//! prove the recipe from scalar `T` to a `Trivial`-struct `T`:
//!
//! - [`IntVec`] binds the SDK's `intvec_t` (`qvector<int>`), sourced from a flow-chart block's
//!   successor edge list.
//! - [`RangeVec`] binds the SDK's `rangevec_t` (`struct : qvector<range_t>`), built from a
//!   function's chunk ranges, with [`RangeT`](crate::bridge_range::RangeT) (the `Trivial`
//!   ExternType from [`bridge_range`](crate::bridge_range)) as its element.
//!
//! Both `intvec_t` and `rangevec_t` are real global SDK names, so `#[cxx_name]` names them
//! directly with no C++ `using` alias (angle-bracketed `#[cxx_name = "qvector<int>"]` does not
//! parse in `type_id!`/`cxx_name`, which require an identifier path).
//!
//! Each instantiation is read two ways, contrasting cost:
//!
//! - **Copy** (`intvec_copy`): one linear copy into an owned [`Vec`], no lifetime tie. The safe
//!   default when the data outlives the container.
//! - **Zero-copy** (`intvec_slice`, `rangevec_slice`): a `&[T]` reconstructed on the C++ side
//!   from the container's `{array, n}` and returned as `rust::Slice`, borrowing the live
//!   backing store with no allocation and no copy. Sound only because the returned slice's
//!   lifetime is tied to the borrowed container (`&'a V -> &'a [T]`), the access is read-only
//!   (`alloc`/`qalloc`/`qfree` are never touched), and the `{array, n}` layout is fixed by the
//!   ABI-per-minor pin. The bodies are hand-written in `facade/qvec_cxx.cc`.

/// Emit the per-instantiation `Opaque` handle for one `qvector<T>`: a zero-sized `!Unpin`
/// mirror struct plus its [`cxx::ExternType`] impl bound to the SDK type named by `$cxx`.
///
/// This is the reusable core of the recipe: the ExternType boilerplate that differs only by
/// `(RustName, "cxx_name")` per instantiation. The `#[cxx::bridge]` fn declarations and the
/// `impl UniquePtr<T> {}` container glue cannot be folded in here, because `cxx_build` parses
/// the source file textually (with `syn`) and cannot expand a `macro_rules!`, so anything it
/// must see -- the bridge module itself -- has to be written literally below.
macro_rules! qvec_opaque {
    ($rust:ident, $cxx:literal) => {
        #[doc = concat!("An `Opaque` `cxx` binding of the SDK container `", $cxx, "`.")]
        ///
        /// Never held by value in Rust; only borrowed (`&Self`) or owned behind
        /// [`UniquePtr`](cxx::UniquePtr). The opaque body mirrors `cxx`'s own generated
        /// representation, so the type is zero-sized and `!Unpin`.
        #[repr(C)]
        pub struct $rust {
            _private: cxx::private::Opaque,
        }

        // SAFETY: the type id names the real global SDK type; Opaque is correct because a
        // qvector owns a heap buffer (nontrivial destructor), so it may only cross the bridge
        // behind a reference or UniquePtr, never by value.
        unsafe impl cxx::ExternType for $rust {
            type Id = cxx::type_id!($cxx);
            type Kind = cxx::kind::Opaque;
        }
    };
}

qvec_opaque!(IntVec, "intvec_t");
qvec_opaque!(RangeVec, "rangevec_t");

#[cxx::bridge(namespace = "idakit_cxx")]
mod ffi {
    unsafe extern "C++" {
        include!("qvec_cxx.h");

        /// The SDK's `range_t`, shared from [`bridge_range`](crate::bridge_range) so it can be a
        /// zero-copy [`RangeVec`] slice element (one ExternType across both bridges).
        #[namespace = ""]
        #[cxx_name = "range_t"]
        type RangeT = crate::bridge_range::RangeT;

        /// The SDK's `qflow_chart_t`, shared from [`bridge_cfg`](crate::bridge_cfg); the source
        /// of the borrowed [`IntVec`].
        #[namespace = ""]
        #[cxx_name = "qflow_chart_t"]
        type FlowChart = crate::bridge_cfg::FlowChart;

        /// `qvector<int>`, bound by [`super::IntVec`]'s macro-generated `ExternType` impl.
        #[namespace = ""]
        #[cxx_name = "intvec_t"]
        type IntVec = super::IntVec;

        /// `qvector<range_t>`, bound by [`super::RangeVec`]'s macro-generated `ExternType` impl.
        #[namespace = ""]
        #[cxx_name = "rangevec_t"]
        type RangeVec = super::RangeVec;

        /// Borrow block `n`'s successor edge list (`qbasic_block_t::succ`, an `intvec_t`) out of
        /// the live flow chart; `Err` when `n` is out of range. The returned `&IntVec` borrows
        /// `fc`, so it cannot outlive it.
        fn cfg_succ_vec<'a>(fc: &'a FlowChart, n: usize) -> Result<&'a IntVec>;

        /// Element count of an `intvec_t`, via its `qvector::size()`.
        fn intvec_len(v: &IntVec) -> usize;
        /// Copy an `intvec_t` into an owned [`Vec<i32>`] (the allocation/copy path).
        fn intvec_copy(v: &IntVec) -> Vec<i32>;
        /// Borrow an `intvec_t`'s backing store as `&[i32]` (the zero-copy path). The slice
        /// borrows `v`, so it cannot outlive it.
        fn intvec_slice<'a>(v: &'a IntVec) -> &'a [i32];

        /// Build a `rangevec_t` of every chunk (entry plus tails) of the function at `ea`, owned
        /// by a [`UniquePtr`](cxx::UniquePtr); `Err` when no function is there.
        fn rangevec_build_chunks(ea: u64) -> Result<UniquePtr<RangeVec>>;
        /// Element count of a `rangevec_t`, via its inherited `qvector::size()`.
        fn rangevec_len(v: &RangeVec) -> usize;
        /// Borrow a `rangevec_t`'s backing store as `&[RangeT]` (the zero-copy path). The slice
        /// borrows `v`, so it cannot outlive it.
        fn rangevec_slice<'a>(v: &'a RangeVec) -> &'a [RangeT];
    }

    // Force cxx to emit the UniquePtr<RangeVec> glue. A hand-written ExternType is not declared
    // by an in-bridge `type X;`, so this empty impl is what triggers its container support.
    impl UniquePtr<RangeVec> {}
}

pub use ffi::{
    cfg_succ_vec, intvec_copy, intvec_len, intvec_slice, rangevec_build_chunks, rangevec_len,
    rangevec_slice,
};
