//! The spec-generated `cxx` bridge, `include!`d from `$OUT_DIR/gen_bridge.rs` (written by the `build_support/` generator from its `spec` manifest and `netnode` matrix).

include!(concat!(env!("OUT_DIR"), "/gen_bridge.rs"));

pub use ffi::*;
