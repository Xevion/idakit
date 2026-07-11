//! `cxx` signature-bridge spine for the `segment` domain (`idakit_cxx::seg_*`).
//!
//! A `#[cxx::bridge]` declares each facade function once, in Rust, and `cxx` generates the
//! matching C++ declarations; the hand-written bodies live in `facade/segment_cxx.cc`. This
//! coexists with the raw `extern "C"` facade (`idakit_seg_*`) rather than replacing it: the
//! raw layer stays the escape hatch for what `cxx` can't model. The idiomatic returns here
//! (owned [`String`], `Result<String>`) retire the snprintf-style `(buf, cap) -> length`
//! marshalling the raw string functions still carry.
//!
//! The bridge's C++ namespace is `idakit_cxx`; the Rust items re-export flat at the crate root
//! per the crate convention, so callers see `idakit_sys::seg_qty`.

#[cxx::bridge(namespace = "idakit_cxx")]
mod ffi {
    unsafe extern "C++" {
        include!("segment_cxx.h");

        /// Number of segments in the current database (`get_segm_qty`).
        fn seg_qty() -> usize;
        /// Start address of segment `n`, or `BADADDR` when `n` is out of range.
        fn seg_start(n: i32) -> u64;
        /// End address of segment `n`, or `BADADDR` when `n` is out of range.
        fn seg_end(n: i32) -> u64;
        /// Permission bits (`SEGPERM_*`) of segment `n`, or `0` when out of range.
        fn seg_perm(n: i32) -> i32;
        /// Address bits (16/32/64) of segment `n`, or `0` when out of range.
        fn seg_bitness(n: i32) -> i32;
        /// Visible name of segment `n`; `Err` when `n` is out of range.
        fn seg_name(n: i32) -> Result<String>;
        /// Class of segment `n`; `Err` when `n` is out of range or has no class.
        fn seg_class(n: i32) -> Result<String>;
    }
}

pub use ffi::{seg_bitness, seg_class, seg_end, seg_name, seg_perm, seg_qty, seg_start};
