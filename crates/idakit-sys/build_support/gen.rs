//! Spec-driven `cxx` bridge generation via `cxx-gen`.
//!
//! `cxx_build::bridge()` parses bridge source textually with `syn`, so a `macro_rules!` can
//! never author a `#[cxx::bridge] mod`: its symbols would be invisible to the parser and
//! undefined at link. `cxx-gen` is the escape hatch. `generate_header_and_cc` takes a
//! `proc_macro2::TokenStream` that already contains a `#[cxx::bridge] mod` and returns the C++
//! header + impl, so build.rs can build the module's tokens from a declarative spec with
//! `quote!` and drive every face off it.
//!
//! The arrangement that actually compiles and links:
//!
//! * The Rust side must be real source the `#[cxx::bridge]` proc-macro expands, so the same
//!   tokens are written to `$OUT_DIR/gen_bridge.rs` and `include!`d by `src/bridge_gen.rs`.
//! * The C++ shim glue comes from `cxx_gen::generate_header_and_cc` on those same tokens
//!   (`$OUT_DIR/gen_bridge.cc`). Same tokens + same `cxx`/`cxx-gen` version => the shim symbol
//!   names on both sides match.
//! * The C++ function bodies are generated from each spec's [`BodyKind`]
//!   (`$OUT_DIR/gen_seg_bodies.cc`); the [`BodyKind::Custom`] escape hatch declares the
//!   signature but leaves the body to a hand-written TU (`facade/gen_custom.cc`).
//! * `cxx_gen::HEADER` (the `rust/cxx.h` text) is written under `$OUT_DIR/rust/` so the bodies
//!   TU sees `rust::String` without depending on cxx-build's private layout.

use std::path::Path;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

/// One facade function: its shared name, arguments, return shape, and how its C++ body is
/// produced. `name` is used verbatim for both the Rust bridge fn and the C++ symbol.
pub struct FnSpec {
    pub name: &'static str,
    pub args: &'static [Arg],
    pub ret: RetKind,
    pub body: BodyKind,
    pub doc: &'static str,
}

/// A bridge-function argument.
pub struct Arg {
    pub name: &'static str,
    pub ty: ArgTy,
}

/// The argument types the segment slice needs. The taxonomy grows as new shapes are added.
pub enum ArgTy {
    I32,
}

/// The return shapes the spec can express, each a (Rust type, C++ type) pair.
pub enum RetKind {
    Usize,
    U64,
    I32,
    ResultString,
}

/// How a function's C++ body is produced. The first three variants are mechanically
/// templated; [`Custom`](BodyKind::Custom) is the escape hatch for bodies with SDK-specific
/// control flow, emitting only the declaration so a hand-written TU can define it.
pub enum BodyKind {
    /// Nullary scalar passthrough: `return (ret)CALL;`.
    ScalarCall { call: &'static str },
    /// `getnseg(n)`, then read scalar `s->ACCESSOR`, returning `SENTINEL` when null.
    SegScalar {
        accessor: &'static str,
        null_sentinel: &'static str,
    },
    /// `getnseg(n)`, then fill a `qstring` via `GETTER(&out, s)`; throw when null, and (when
    /// `require_positive`) throw when the getter returns `<= 0`.
    SegString {
        getter: &'static str,
        require_positive: bool,
    },
    /// Declaration only; the body is hand-written in a separate TU.
    Custom,
}

const N: &[Arg] = &[Arg {
    name: "n",
    ty: ArgTy::I32,
}];

/// The segment-domain spec: the source of truth every generated face is derived from. Mirrors
/// the hand-written `idakit_cxx::seg_*` bridge one-for-one, plus a `Custom` proof.
pub const SEGMENT_SPEC: &[FnSpec] = &[
    FnSpec {
        name: "gen_seg_qty",
        args: &[],
        ret: RetKind::Usize,
        body: BodyKind::ScalarCall {
            call: "get_segm_qty()",
        },
        doc: "Number of segments in the current database (`get_segm_qty`).",
    },
    FnSpec {
        name: "gen_seg_start",
        args: N,
        ret: RetKind::U64,
        body: BodyKind::SegScalar {
            accessor: "start_ea",
            null_sentinel: "BADADDR",
        },
        doc: "Start address of segment `n`, or `BADADDR` when `n` is out of range.",
    },
    FnSpec {
        name: "gen_seg_end",
        args: N,
        ret: RetKind::U64,
        body: BodyKind::SegScalar {
            accessor: "end_ea",
            null_sentinel: "BADADDR",
        },
        doc: "End address of segment `n`, or `BADADDR` when `n` is out of range.",
    },
    FnSpec {
        name: "gen_seg_perm",
        args: N,
        ret: RetKind::I32,
        body: BodyKind::SegScalar {
            accessor: "perm",
            null_sentinel: "0",
        },
        doc: "Permission bits (`SEGPERM_*`) of segment `n`, or `0` when out of range.",
    },
    FnSpec {
        name: "gen_seg_bitness",
        args: N,
        ret: RetKind::I32,
        body: BodyKind::SegScalar {
            accessor: "abits()",
            null_sentinel: "0",
        },
        doc: "Address bits (16/32/64) of segment `n`, or `0` when out of range.",
    },
    FnSpec {
        name: "gen_seg_name",
        args: N,
        ret: RetKind::ResultString,
        body: BodyKind::SegString {
            getter: "get_visible_segm_name",
            require_positive: false,
        },
        doc: "Visible name of segment `n`; `Err` when `n` is out of range.",
    },
    FnSpec {
        name: "gen_seg_class",
        args: N,
        ret: RetKind::ResultString,
        body: BodyKind::SegString {
            getter: "get_segm_class",
            require_positive: true,
        },
        doc: "Class of segment `n`; `Err` when `n` is out of range or has no class.",
    },
    // Escape hatch: sum of every segment's byte span. Too bespoke to template (it iterates the
    // whole table), so the spec declares only the signature; facade/gen_custom.cc defines it.
    FnSpec {
        name: "gen_seg_span_total",
        args: &[],
        ret: RetKind::U64,
        body: BodyKind::Custom,
        doc: "Total byte span across all segments (sum of `end - start`). Hand-written body.",
    },
];

const NAMESPACE: &str = "idakit_gen";

impl ArgTy {
    fn rust(&self) -> TokenStream {
        match self {
            ArgTy::I32 => quote!(i32),
        }
    }
    fn cxx(&self) -> &'static str {
        match self {
            ArgTy::I32 => "int32_t",
        }
    }
}

impl RetKind {
    fn rust(&self) -> TokenStream {
        match self {
            RetKind::Usize => quote!(-> usize),
            RetKind::U64 => quote!(-> u64),
            RetKind::I32 => quote!(-> i32),
            RetKind::ResultString => quote!(-> Result<String>),
        }
    }
    fn cxx(&self) -> &'static str {
        match self {
            RetKind::Usize => "size_t",
            RetKind::U64 => "uint64_t",
            RetKind::I32 => "int32_t",
            RetKind::ResultString => "rust::String",
        }
    }
}

/// Build the `#[cxx::bridge] mod` token stream from the spec. This is fed to both the Rust side
/// (written out and `include!`d) and `cxx-gen` (C++ side), so the two stay in lockstep.
fn bridge_tokens(specs: &[FnSpec]) -> TokenStream {
    let fns = specs.iter().map(|f| {
        let name = format_ident!("{}", f.name);
        let args = f.args.iter().map(|a| {
            let an = format_ident!("{}", a.name);
            let at = a.ty.rust();
            quote!(#an: #at)
        });
        let ret = f.ret.rust();
        let doc = f.doc;
        quote! {
            #[doc = #doc]
            fn #name(#(#args),*) #ret;
        }
    });
    quote! {
        #[cxx::bridge(namespace = #NAMESPACE)]
        mod ffi {
            unsafe extern "C++" {
                include!("gen_seg.h");
                #(#fns)*
            }
        }
    }
}

/// The C++ signature `RET name(ARGS)` shared by the header decl and the body definition.
fn cxx_signature(f: &FnSpec) -> String {
    let args: Vec<String> = f
        .args
        .iter()
        .map(|a| format!("{} {}", a.ty.cxx(), a.name))
        .collect();
    format!("{} {}({})", f.ret.cxx(), f.name, args.join(", "))
}

/// The shared C++ header declaring every facade function (all body kinds contribute a decl).
fn header_source(specs: &[FnSpec]) -> String {
    let mut s = String::new();
    s.push_str("#pragma once\n\n");
    s.push_str("#include <cstddef>\n#include <cstdint>\n\n");
    s.push_str("#include \"rust/cxx.h\"\n\n");
    s.push_str(&format!("namespace {NAMESPACE} {{\n\n"));
    for f in specs {
        s.push_str(&cxx_signature(f));
        s.push_str(";\n");
    }
    s.push_str(&format!("\n}} // namespace {NAMESPACE}\n"));
    s
}

/// The C++ body for one templated (non-`Custom`) spec, mirroring the hand-written facade.
fn body_source(f: &FnSpec) -> Option<String> {
    let sig = cxx_signature(f);
    let body = match &f.body {
        BodyKind::ScalarCall { call } => {
            format!("  return ({}){};\n", f.ret.cxx(), call)
        }
        BodyKind::SegScalar {
            accessor,
            null_sentinel,
        } => {
            let cast = f.ret.cxx();
            format!(
                "  segment_t *s = getnseg(n);\n  \
                 return s != nullptr ? ({cast})s->{accessor} : ({cast}){null_sentinel};\n"
            )
        }
        BodyKind::SegString {
            getter,
            require_positive,
        } => {
            let mut b = String::from(
                "  segment_t *s = getnseg(n);\n  \
                 if (s == nullptr)\n    throw std::out_of_range(\"no segment at index\");\n  \
                 qstring out;\n",
            );
            if *require_positive {
                b.push_str(&format!(
                    "  if ({getter}(&out, s) <= 0)\n    \
                     throw std::runtime_error(\"segment has no class\");\n"
                ));
            } else {
                b.push_str(&format!("  {getter}(&out, s);\n"));
            }
            b.push_str("  return rust::String(out.c_str(), out.length());\n");
            b
        }
        BodyKind::Custom => return None,
    };
    Some(format!("{sig} {{\n{body}}}\n\n"))
}

/// The generated bodies TU: SDK includes, the shared header, and every templated body.
fn bodies_source(specs: &[FnSpec]) -> String {
    let mut s = String::new();
    s.push_str(
        "// GENERATED from build_support/gen.rs SEGMENT_SPEC -- do not edit.\n\
         #include <pro.h>\n#include <ida.hpp>\n#include <segment.hpp>\n\
         #include <stdexcept>\n\n#include \"gen_seg.h\"\n\n",
    );
    s.push_str(&format!("namespace {NAMESPACE} {{\n\n"));
    for f in specs {
        if let Some(body) = body_source(f) {
            s.push_str(&body);
        }
    }
    s.push_str(&format!("}} // namespace {NAMESPACE}\n"));
    s
}

/// Whether the spec has any [`BodyKind::Custom`] entry (so build.rs knows to compile the
/// hand-written TU).
pub fn has_custom(specs: &[FnSpec]) -> bool {
    specs.iter().any(|f| matches!(f.body, BodyKind::Custom))
}

/// Generate every artifact into `$OUT_DIR` from [`SEGMENT_SPEC`]:
///
/// * `gen_bridge.rs` -- the `#[cxx::bridge] mod` Rust source, `include!`d by the crate.
/// * `gen_bridge.cc` / `gen_bridge.h` -- the C++ shim glue from `cxx-gen`.
/// * `gen_seg.h` -- the shared declarations of the real C++ functions.
/// * `gen_seg_bodies.cc` -- the templated C++ bodies.
/// * `rust/cxx.h` -- the `cxx` support header (`cxx_gen::HEADER`) for the bodies TU.
///
/// # Panics
///
/// Panics if `cxx-gen` rejects the generated tokens or any file write fails -- both are build
/// bugs, not recoverable conditions.
pub fn generate(out_dir: &Path) {
    let specs = SEGMENT_SPEC;
    let tokens = bridge_tokens(specs);

    // Rust side: the proc-macro expands this on `include!`. `TokenStream`'s Display is valid
    // (if unformatted) Rust; OUT_DIR files are never formatted, so that is fine.
    std::fs::write(out_dir.join("gen_bridge.rs"), tokens.to_string()).expect("write gen_bridge.rs");

    // C++ side: same tokens => matching shim symbol names on both sides.
    let opt = cxx_gen::Opt::default();
    let code = cxx_gen::generate_header_and_cc(tokens, &opt)
        .expect("cxx-gen rejected the generated bridge tokens");
    std::fs::write(out_dir.join("gen_bridge.h"), &code.header).expect("write gen_bridge.h");
    std::fs::write(out_dir.join("gen_bridge.cc"), &code.implementation)
        .expect("write gen_bridge.cc");

    std::fs::write(out_dir.join("gen_seg.h"), header_source(specs)).expect("write gen_seg.h");
    std::fs::write(out_dir.join("gen_seg_bodies.cc"), bodies_source(specs))
        .expect("write gen_seg_bodies.cc");

    let rust_dir = out_dir.join("rust");
    std::fs::create_dir_all(&rust_dir).expect("create OUT_DIR/rust");
    std::fs::write(rust_dir.join("cxx.h"), cxx_gen::HEADER).expect("write rust/cxx.h");
}
