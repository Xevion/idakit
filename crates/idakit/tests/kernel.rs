//! Every test that wants the canonical database, run as one binary against a pool of warm kernels.
//!
//! `harness = false` because these are `#[kernel_test]`s, not libtest tests: they register
//! themselves with [`common::registry`] and are driven by [`common::kernel`], which pays kernel
//! bring-up once per worker instead of once per test while still naming, timing, and reporting each
//! one on its own. This binary only pulls the test modules in, so that registration links.
//!
//! Tests that deliberately exercise kernel bring-up itself, or that need a process with no kernel
//! in it, stay outside as ordinary `#[test]` binaries.

mod common;

#[path = "kernel/attributes.rs"]
mod attributes;
#[path = "kernel/cfg.rs"]
mod cfg;
#[path = "kernel/data.rs"]
mod data;
#[path = "kernel/dbinfo.rs"]
mod dbinfo;
#[path = "kernel/decode_sweep.rs"]
mod decode_sweep;
#[path = "kernel/decompile_cache.rs"]
mod decompile_cache;
#[path = "kernel/disasm.rs"]
mod disasm;
#[path = "kernel/frame.rs"]
mod frame;
#[path = "kernel/function_name.rs"]
mod function_name;
#[path = "kernel/function_scalars.rs"]
mod function_scalars;
#[path = "kernel/name.rs"]
mod name;
#[path = "kernel/netnode.rs"]
mod netnode;
#[path = "kernel/roundtrip.rs"]
mod roundtrip;
#[path = "kernel/search.rs"]
mod search;
#[path = "kernel/strings.rs"]
mod strings;
#[path = "kernel/symbols.rs"]
mod symbols;
#[path = "kernel/tinfo.rs"]
mod tinfo;

#[path = "kernel/write/location.rs"]
mod location;
#[path = "kernel/write/type_apply.rs"]
mod type_apply;
#[path = "kernel/write/type_enum.rs"]
mod type_enum;
#[path = "kernel/write/type_function.rs"]
mod type_function;
#[path = "kernel/write/type_member.rs"]
mod type_member;

fn main() -> std::process::ExitCode {
    common::kernel::run()
}
