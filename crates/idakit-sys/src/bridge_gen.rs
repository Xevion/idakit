//! The spec-generated `cxx` bridge, `include!`d from `$OUT_DIR/gen_bridge.rs`.
//!
//! Written by the `idakit-sys-codegen` crate's `emit` engine from its `domains` manifest,
//! including the `netnode` matrix.

// cxx::bridge auto-derives Clone/Debug/etc. for each shared struct it declares, and that
// generated code trips unused_qualifications on the struct's own name; scoped here since the
// generated module can't carry its own attribute. Likewise, one of cxx's own generated
// container-glue methods mis-attributes a missing_errors_doc warning to the `mod ffi` span
// itself, though every spec'd fn here already documents its `Err` condition in prose.
#![expect(
    unused_qualifications,
    reason = "false positive from cxx::bridge's auto-derived impls for shared structs"
)]
#![expect(
    clippy::missing_errors_doc,
    reason = "false positive misattributed to `mod ffi` by cxx::bridge's generated container glue"
)]
#![expect(
    clippy::unreadable_literal,
    reason = "generated const literals mirror raw facade/SDK sentinels (e.g. u64::MAX), not \
              hand-grouped numbers"
)]

include!(concat!(env!("OUT_DIR"), "/gen_bridge.rs"));

pub use ffi::*;
