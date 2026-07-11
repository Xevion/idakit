//! Spec-generated `cxx` bridge for the `segment` domain (`idakit_gen::gen_seg_*`).
//!
//! Unlike the hand-written [`bridge`](crate::bridge) module, nothing here is authored by hand:
//! build.rs builds the `#[cxx::bridge] mod` tokens from `build_support/gen.rs`'s declarative
//! `SEGMENT_SPEC`, writes them to `$OUT_DIR/gen_bridge.rs`, and `include!`s the result below so
//! the `#[cxx::bridge]` proc-macro expands it as ordinary source. The same tokens drive the C++
//! side through `cxx-gen`, and the C++ bodies are generated from each spec's `BodyKind`. This is
//! the proof that one spec can generate every face at once.
//!
//! The Rust items re-export flat at the crate root per convention, so callers see
//! `idakit_sys::gen_seg_qty`, parallel to the hand-written `seg_qty`.

include!(concat!(env!("OUT_DIR"), "/gen_bridge.rs"));

pub use ffi::{
    gen_seg_bitness, gen_seg_class, gen_seg_end, gen_seg_name, gen_seg_perm, gen_seg_qty,
    gen_seg_span_total, gen_seg_start,
};
