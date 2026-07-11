//! `cxx` `ExternType` bridge for the SDK's `range_t` POD (`idakit_cxx::range_*`).
//!
//! This is the by-value unlock the earlier opaque-handle bridges skipped. [`RangeT`] is a
//! `#[repr(C)]` Rust mirror of the SDK's `range_t` (`{ ea_t start_ea; ea_t end_ea; }`), bound to
//! the real C++ type through a hand-written [`cxx::ExternType`] impl with
//! `type_id!("range_t")` and `Kind = Trivial`. Because `range_t` is trivially move-constructible
//! and trivially destructible, `cxx` lets it cross the bridge **by value**: as a function
//! argument ([`range_size`]), a function return ([`range_entry_chunk`]), a by-value field of a
//! shared struct ([`ChunkInfo`]), and an element of an owned [`Vec`] ([`range_all_chunks`]).
//!
//! `cxx` verifies the triviality claim with a C++ `static_assert` in the generated glue, so a
//! mis-marked type fails at compile time rather than corrupting memory. The bodies are
//! hand-written in `facade/range_cxx.cc` (declarations in `facade/range_cxx.h`); this coexists
//! with the raw `idakit_func_chunk` out-param facade rather than replacing it.

use cxx::{ExternType, type_id};

/// A `#[repr(C)]` mirror of the SDK's `range_t`, bound as a `Trivial` [`cxx::ExternType`].
///
/// The two `u64` fields match `range_t`'s two `ea_t` members under `__EA64__`. `cxx` needs a
/// concrete Rust type (not the opaque C++ one) to hold and move `range_t` values by value; this
/// struct is that type, tied to the C++ `range_t` by the [`ExternType`] impl below.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RangeT {
    /// `start_ea`, inclusive.
    pub start: u64,
    /// `end_ea`, exclusive.
    pub end: u64,
}

// SAFETY: RangeT's layout (two u64) matches ::range_t's two ea_t members under __EA64__, and
// range_t has a trivial move constructor and trivial destructor, so passing it by value across
// the bridge is sound. cxx re-checks the triviality half with a C++ static_assert.
unsafe impl ExternType for RangeT {
    type Id = type_id!("range_t");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge(namespace = "idakit_cxx")]
mod ffi {
    /// One function chunk: its index paired with its address range.
    ///
    /// A `cxx` shared struct carrying a [`RangeT`] **by value**, proving a `Trivial`
    /// `ExternType` is usable as a by-value shared-struct field.
    struct ChunkInfo {
        /// Zero-based chunk index (entry chunk is `0`).
        index: usize,
        /// The chunk's address range.
        range: RangeT,
    }

    unsafe extern "C++" {
        include!("range_cxx.h");

        /// The SDK's `range_t`, bound by [`super::RangeT`]'s hand-written `ExternType` impl.
        ///
        /// `#[namespace = ""]` + `#[cxx_name = "range_t"]` make `cxx` emit the real global
        /// `::range_t` in its generated glue, so no C++ `using` alias or redeclaration is needed:
        /// the SDK header alone supplies the type. (`type_id!` only fixes the ExternType
        /// identity; the emitted C++ name comes from the namespace and `cxx_name`.)
        #[namespace = ""]
        #[cxx_name = "range_t"]
        type RangeT = super::RangeT;

        /// Entry chunk (index `0`) of the function containing `ea`, returned by value; `Err`
        /// when no function is there.
        fn range_entry_chunk(ea: u64) -> Result<RangeT>;
        /// Size (`end - start`) of a range passed **by value**, proving by-value argument
        /// passing of a `Trivial` `ExternType`.
        fn range_size(r: RangeT) -> u64;
        /// Chunk `n` of the function at `ea` as a [`ChunkInfo`]; `Err` when `n` is out of range.
        fn range_chunk_info(ea: u64, n: usize) -> Result<ChunkInfo>;
        /// Every chunk (entry plus tails) of the function at `ea` as one owned `Vec<RangeT>`;
        /// `Err` when no function is there. Proves a `Trivial` `ExternType` is a `Vec` element.
        fn range_all_chunks(ea: u64) -> Result<Vec<RangeT>>;
    }

    // Explicit instantiation of the `Vec<RangeT>` glue. A hand-written `ExternType` is not
    // declared in any bridge, so `cxx` does not auto-generate its container support the way it
    // does for an in-bridge `type X;`; this empty impl forces it.
    impl Vec<RangeT> {}
}

pub use ffi::{ChunkInfo, range_all_chunks, range_chunk_info, range_entry_chunk, range_size};
