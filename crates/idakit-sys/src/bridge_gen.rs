//! The spec-generated `cxx` bridge, `include!`d from `$OUT_DIR/gen_bridge.rs` (written by `build_support/gen.rs`'s `DOMAINS`).

include!(concat!(env!("OUT_DIR"), "/gen_bridge.rs"));

pub use ffi::*;
