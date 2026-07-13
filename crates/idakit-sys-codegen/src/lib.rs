//! Spec-driven `cxx` bridge generation via `cxx-gen`, the build-time engine behind `idakit-sys`.
//!
//! `idakit-sys`'s `build.rs` calls [`generate`] as a `[build-dependencies]` path crate; nothing
//! here runs at `idakit-sys` compile time.
//!
//! `cxx_build::bridge()` parses bridge source textually with `syn`, so a `macro_rules!` can never
//! author a `#[cxx::bridge] mod`: its symbols would be invisible to the parser and undefined at
//! link. `cxx-gen` is the escape hatch: its `generate_header_and_cc` takes a `TokenStream` that
//! already contains a `#[cxx::bridge] mod` and returns the C++ header + impl, so build.rs can build
//! the module's tokens from a declarative spec and drive every face off it.
//!
//! One [`Domain`] is one slice of the facade (segment, function, ...). Every domain feeds one
//! unified `#[cxx::bridge] mod ffi` (namespace `idakit_gen`): the generator emits all three
//! declaration faces from the spec (the Rust bridge decl, the C++ header decl, the `cxx` glue),
//! and the function *bodies* stay hand-written in per-domain `.cc` translation units, exactly as
//! the raw facade's bodies are. A handful of trivial scalar/string bodies are templated from their
//! [`BodyKind`] as a convenience; the netnode domain supplies its own matrix-rendered
//! [`BodyKind::Rendered`] bodies; everything else is [`BodyKind::Custom`] and hand-written.
//!
//! The engine is split into three sibling files: `dsl` (the authoring macros), `model` (the spec
//! data vocabulary), and `emit` (the token/string emitters). The declarative manifest of domains
//! lives in the sibling `domains` submodule ([`domains`]), one file per domain; the
//! matrix-generated netnode domain lives in `domains`'s private `netnode` submodule.
//!
//! Files written to `$OUT_DIR`:
//!
//! * `gen_bridge.rs`: the `#[cxx::bridge] mod` Rust source, `include!`d by `src/bridge_gen.rs`.
//! * `gen_bridge.cc` / `gen_bridge.h`: the `cxx` shim glue from `cxx-gen`.
//! * `gen_<name>.h`: one per domain, the real C++ declarations the bodies define.
//! * `gen_<name>_bodies.cc`: one per domain with any templated bodies (omitted when all Custom).
//! * `rust/cxx.h`: the `cxx` support header (`cxx_gen::HEADER`) for the body TUs.

use std::path::{Path, PathBuf};

#[macro_use]
mod dsl;

mod emit;
mod model;

mod domains;
mod visitors;

use domains::domains;
use emit::{bridge_tokens, reexport_tokens};

/// The generated body TUs (the `cxx-gen` glue plus each domain's templated bodies) that build.rs
/// must compile.
pub fn body_tus(out_dir: &Path) -> Vec<PathBuf> {
    let mut tus = vec![
        out_dir.join("gen_bridge.cc"),
        out_dir.join("gen_visitors.cc"),
    ];
    for d in domains() {
        if d.has_templated_body() {
            tus.push(out_dir.join(d.bodies_file()));
        }
    }
    tus
}

/// The hand-written `Custom`-body TUs build.rs must compile alongside the generated ones.
pub fn custom_tus() -> Vec<&'static str> {
    domains().iter().filter_map(|d| d.custom_tu).collect()
}

/// Generate every artifact into `$OUT_DIR` from [`domains`].
///
/// # Panics
///
/// Panics if `cxx-gen` rejects the generated tokens, a spec references an unknown `ExternType`, or
/// any file write fails. All are build bugs, not recoverable conditions.
pub fn generate(out_dir: &Path) {
    let tokens = bridge_tokens();

    // Rust side: the proc-macro expands this on `include!`. `TokenStream`'s Display is valid (if
    // unformatted) Rust; OUT_DIR files are never formatted, so that is fine. The aliased re-exports
    // are appended here only, outside the bridge module, so cxx-gen never sees them.
    let mut rust = tokens.to_string();
    rust.push('\n');
    rust.push_str(&reexport_tokens().to_string());
    std::fs::write(out_dir.join("gen_bridge.rs"), rust).expect("write gen_bridge.rs");

    // C++ side: same tokens => matching shim symbol names on both sides.
    let opt = cxx_gen::Opt::default();
    let code = cxx_gen::generate_header_and_cc(tokens, &opt)
        .expect("cxx-gen rejected the generated bridge tokens");
    std::fs::write(out_dir.join("gen_bridge.h"), &code.header).expect("write gen_bridge.h");
    std::fs::write(out_dir.join("gen_bridge.cc"), &code.implementation)
        .expect("write gen_bridge.cc");

    for d in domains() {
        std::fs::write(out_dir.join(d.header()), d.header_source())
            .unwrap_or_else(|e| panic!("write {}: {e}", d.header()));
        if let Some(bodies) = d.bodies_source() {
            std::fs::write(out_dir.join(d.bodies_file()), bodies)
                .unwrap_or_else(|e| panic!("write {}: {e}", d.bodies_file()));
        }
    }

    // The ctree/tinfo extern "Rust" opaque-visitor bridge, generated the same way as the domain
    // bridge above: one token stream feeds both the Rust side (include!d by bridge_visitors.rs)
    // and cxx-gen (the C++ shim glue, compiled alongside the domain bodies in build.rs).
    let visitor_tokens = visitors::VISITOR_BRIDGE.tokens();
    let visitor_rust = visitor_tokens.to_string();
    std::fs::write(out_dir.join("gen_visitors.rs"), visitor_rust).expect("write gen_visitors.rs");
    let visitor_code = cxx_gen::generate_header_and_cc(visitor_tokens, &opt)
        .expect("cxx-gen rejected the generated visitor bridge tokens");
    std::fs::write(out_dir.join("gen_visitors.h"), &visitor_code.header)
        .expect("write gen_visitors.h");
    std::fs::write(
        out_dir.join("gen_visitors.cc"),
        &visitor_code.implementation,
    )
    .expect("write gen_visitors.cc");

    let rust_dir = out_dir.join("rust");
    std::fs::create_dir_all(&rust_dir).expect("create OUT_DIR/rust");
    std::fs::write(rust_dir.join("cxx.h"), cxx_gen::HEADER).expect("write rust/cxx.h");
}
