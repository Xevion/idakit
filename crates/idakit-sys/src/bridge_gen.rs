//! The spec-generated `cxx` bridge, `include!`d from `$OUT_DIR/gen_bridge.rs` (written by the `idakit-sys-codegen` crate's `emit` engine from its `domains` manifest, including the `netnode` matrix).

include!(concat!(env!("OUT_DIR"), "/gen_bridge.rs"));

pub use ffi::*;
