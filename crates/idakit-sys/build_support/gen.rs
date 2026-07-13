//! Spec-driven `cxx` bridge generation via `cxx-gen`.
//!
//! `cxx_build::bridge()` parses bridge source textually with `syn`, so a `macro_rules!` can never
//! author a `#[cxx::bridge] mod`: its symbols would be invisible to the parser and undefined at
//! link. `cxx-gen` is the escape hatch. `generate_header_and_cc` takes a `TokenStream` that already
//! contains a `#[cxx::bridge] mod` and returns the C++ header + impl, so build.rs can build the
//! module's tokens from a declarative spec and drive every face off it.
//!
//! One [`Domain`] is one slice of the facade (segment, function, ...). Every domain feeds one
//! unified `#[cxx::bridge] mod ffi` (namespace `idakit_gen`): the generator emits all three
//! declaration faces from the spec (the Rust bridge decl, the C++ header decl, the `cxx` glue),
//! and the function *bodies* stay hand-written in per-domain `.cc` translation units, exactly as
//! the raw facade's bodies are. A handful of trivial scalar/string bodies are templated from their
//! [`BodyKind`] as a convenience; the netnode domain supplies its own matrix-rendered
//! [`BodyKind::Rendered`] bodies; everything else is [`BodyKind::Custom`] and hand-written.
//!
//! This module is the engine only. The declarative manifest of hand-written domains lives in the
//! sibling `spec` module ([`domains`]); the matrix-generated netnode domain lives in `netnode`.
//!
//! Files written to `$OUT_DIR`:
//!
//! * `gen_bridge.rs`: the `#[cxx::bridge] mod` Rust source, `include!`d by `src/bridge_gen.rs`.
//! * `gen_bridge.cc` / `gen_bridge.h`: the `cxx` shim glue from `cxx-gen`.
//! * `gen_<name>.h`: one per domain, the real C++ declarations the bodies define.
//! * `gen_<name>_bodies.cc`: one per domain with any templated bodies (omitted when all Custom).
//! * `rust/cxx.h`: the `cxx` support header (`cxx_gen::HEADER`) for the body TUs.

use std::path::{Path, PathBuf};

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

#[path = "netnode.rs"]
mod netnode;
#[path = "spec.rs"]
mod spec;
#[path = "visitor_spec.rs"]
mod visitor_spec;

use spec::domains;

/// The C++ namespace every generated bridge function lives in.
const NAMESPACE: &str = "idakit_gen";

/// One slice of the facade: its own C++ header and body TU, the SDK types it binds, the shared
/// structs it returns, and its functions. All domains feed one unified bridge module.
pub struct Domain {
    /// Short identifier, e.g. `"seg"`. Names the generated `gen_<name>.h` / `gen_<name>_bodies.cc`.
    pub name: &'static str,
    /// SDK headers the body TU must include (e.g. `"<segment.hpp>"`), plus `<stdexcept>` when a
    /// body throws. `<pro.h>`/`<ida.hpp>` are always included.
    pub sdk_includes: &'static [&'static str],
    /// SDK types this domain binds as `cxx` `ExternType`s (POD by value, or opaque behind a handle).
    pub externs: &'static [ExternTy],
    /// `cxx` shared structs this domain declares and returns by value.
    pub structs: &'static [SharedStruct],
    /// Raw C++ emitted `inline` into this domain's header, ahead of the fn decls: shared helpers
    /// that both the generated bodies and the `custom_tu` call. `None` for self-contained bodies.
    pub body_helpers: Option<&'static str>,
    /// The domain's functions.
    pub fns: &'static [FnSpec],
    /// A hand-written TU defining this domain's [`BodyKind::Custom`] bodies, if any.
    pub custom_tu: Option<&'static str>,
}

impl Domain {
    fn header(&self) -> String {
        format!("gen_{}.h", self.name)
    }
    fn bodies_file(&self) -> String {
        format!("gen_{}_bodies.cc", self.name)
    }
    fn has_templated_body(&self) -> bool {
        self.fns.iter().any(|f| body_source(f).is_some())
    }
}

/// An SDK type bound as a `cxx` [`ExternType`](cxx::ExternType), so `cxx` glue can pass it without
/// redeclaring it: the impl names the real C++ symbol by `type_id!`.
pub struct ExternTy {
    /// The Rust-side name (e.g. `"RangeT"`).
    pub rust_name: &'static str,
    /// The real C++ symbol (e.g. `"range_t"`), emitted as `::range_t` and used in `type_id!`.
    pub cxx_name: &'static str,
    /// Trivial (crosses by value) or Opaque (only behind a reference or `UniquePtr`).
    pub kind: ExternKind,
    /// One-line summary for the generated Rust type's doc comment.
    pub doc: &'static str,
    /// The `// SAFETY:` justification for the `unsafe impl ExternType`.
    pub safety: &'static str,
}

/// Whether an [`ExternTy`] is trivially relocatable (crosses by value) or opaque.
pub enum ExternKind {
    /// `#[repr(C)]` mirror crossing by value; the fields mirror the SDK POD's layout.
    Trivial(&'static [Field]),
    /// Zero-sized opaque body; only ever behind `&T` / `UniquePtr<T>`.
    Opaque,
}

/// A `cxx` shared struct: one POD declared once, generated into both languages, crossed by value.
pub struct SharedStruct {
    /// The struct's name (e.g. `"ChunkInfo"`).
    pub name: &'static str,
    /// One-line summary for its doc comment.
    pub doc: &'static str,
    /// Its fields, in declaration order.
    pub fields: &'static [Field],
}

/// One field of a [`SharedStruct`] or a `Trivial` [`ExternTy`] mirror.
pub struct Field {
    /// Field name.
    pub name: &'static str,
    /// Field type.
    pub ty: FieldTy,
    /// Terse noun-phrase doc fragment (renders in a generated table).
    pub doc: &'static str,
}

/// The field types a shared struct or POD mirror may carry.
// The allow covers taxonomy slots no current spec constructs.
#[allow(dead_code)]
pub enum FieldTy {
    U8,
    U16,
    U32,
    U64,
    I32,
    I64,
    Usize,
    Bool,
    /// An owned string (`String` in Rust, `rust::String` in C++).
    Str,
    /// A by-value `Trivial` `ExternType`, named by its Rust name (e.g. `"RangeT"`).
    Extern(&'static str),
    /// A nested shared struct by value, by name (e.g. `"RegisterData"`); `cxx` lays it inline.
    Struct(&'static str),
    /// An owned `Vec` of a shared struct, by name (e.g. `"OperandData"`).
    VecStruct(&'static str),
}

/// One facade function: its shared name, optional `self:` receiver, arguments, return shape, and
/// how its C++ body is produced. `name` is used verbatim for the Rust bridge fn and the C++ symbol.
pub struct FnSpec {
    pub name: &'static str,
    /// `Some(extern rust_name)` for a `self: &T` member call; `None` for a free function.
    pub receiver: Option<&'static str>,
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

/// The argument shapes the spec can express. Each is a (Rust type, C++ type) pair.
// The allow covers taxonomy slots no current spec constructs.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum ArgTy {
    I32,
    U32,
    U64,
    Usize,
    Bool,
    /// A borrowed string (`&str` / `rust::Str`).
    Str,
    /// A borrowed byte slice (`&[u8]` / `rust::Slice<const uint8_t>`).
    Bytes,
    /// A by-value `Trivial` `ExternType`, by Rust name.
    Extern(&'static str),
    /// A borrowed `ExternType` (`&T` / `const ::cxx_name&`), by Rust name.
    ExternRef(&'static str),
    /// A borrowed `f64` (`f64` / `double`).
    F64,
    /// A borrowed `i64` (`i64` / `int64_t`).
    I64,
    /// A borrowed `u32` slice (`&[u32]` / `rust::Slice<const uint32_t>`).
    SliceU32,
    /// A borrowed `u64` slice (`&[u64]` / `rust::Slice<const uint64_t>`).
    SliceU64,
    /// A borrowed slice of a shared struct, by name (`&[Name]` / `rust::Slice<const Name>`).
    SliceStruct(&'static str),
    /// A borrowed mutable reference to an `extern "Rust"` opaque visitor, by name (`&mut Name` /
    /// `Name &`).
    VisitorMut(&'static str),
}

/// The return shapes the spec can express. `Result<T>` variants surface a thrown C++ exception as
/// a Rust `Err`; the non-`Result` twins are for infallible calls.
// The allow covers taxonomy slots no current spec constructs.
#[allow(dead_code)]
pub enum RetKind {
    Unit,
    Bool,
    I32,
    U32,
    U64,
    Usize,
    ResultUsize,
    ResultU8,
    ResultU16,
    ResultU32,
    ResultU64,
    String,
    ResultString,
    /// A by-value `Trivial` `ExternType`, by Rust name.
    Extern(&'static str),
    ResultExtern(&'static str),
    /// A shared struct by value, by name.
    Shared(&'static str),
    ResultShared(&'static str),
    /// `UniquePtr<T>` over an opaque `ExternType`, by Rust name.
    UniquePtr(&'static str),
    ResultUniquePtr(&'static str),
    /// An owned `Vec` of a `Trivial` `ExternType` or a shared struct, by name.
    Vec(&'static str),
    ResultVec(&'static str),
    /// An owned `Vec` of a scalar (`u32`).
    VecU32,
    ResultVecU32,
    /// An owned `Vec<u8>` (a raw byte-range snapshot, or an alignment-id list).
    VecU8,
    ResultVecU8,
}

/// How a function's C++ body is produced. The templated variants exist for segment's trivial
/// scalar/string shapes; the netnode matrix supplies its own [`Rendered`](BodyKind::Rendered)
/// bodies; every other body is [`Custom`](BodyKind::Custom) and hand-written in the domain's
/// `custom_tu`.
pub enum BodyKind {
    /// Nullary scalar passthrough: `return (ret)CALL;`.
    ScalarCall { call: &'static str },
    /// A fully-rendered body (the lines between the braces), supplied by a matrix emitter that owns
    /// both the function's signature and its body. Emitted into the domain's `gen_<name>_bodies.cc`.
    Rendered(&'static str),
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
    /// Declaration only; the body is hand-written in the domain's `custom_tu`.
    Custom,
}

impl FieldTy {
    fn rust(&self) -> TokenStream {
        match self {
            FieldTy::U8 => quote!(u8),
            FieldTy::U16 => quote!(u16),
            FieldTy::U32 => quote!(u32),
            FieldTy::U64 => quote!(u64),
            FieldTy::I32 => quote!(i32),
            FieldTy::I64 => quote!(i64),
            FieldTy::Usize => quote!(usize),
            FieldTy::Bool => quote!(bool),
            FieldTy::Str => quote!(String),
            FieldTy::Extern(name) | FieldTy::Struct(name) => {
                let id = format_ident!("{name}");
                quote!(#id)
            }
            FieldTy::VecStruct(name) => {
                let id = format_ident!("{name}");
                quote!(Vec<#id>)
            }
        }
    }
}

impl ArgTy {
    fn rust(&self) -> TokenStream {
        match self {
            ArgTy::I32 => quote!(i32),
            ArgTy::U32 => quote!(u32),
            ArgTy::U64 => quote!(u64),
            ArgTy::Usize => quote!(usize),
            ArgTy::Bool => quote!(bool),
            ArgTy::Str => quote!(&str),
            ArgTy::Bytes => quote!(&[u8]),
            ArgTy::Extern(name) => {
                let id = format_ident!("{name}");
                quote!(#id)
            }
            ArgTy::ExternRef(name) => {
                let id = format_ident!("{name}");
                quote!(&#id)
            }
            ArgTy::F64 => quote!(f64),
            ArgTy::I64 => quote!(i64),
            ArgTy::SliceU32 => quote!(&[u32]),
            ArgTy::SliceU64 => quote!(&[u64]),
            ArgTy::SliceStruct(name) => {
                let id = format_ident!("{name}");
                quote!(&[#id])
            }
            ArgTy::VisitorMut(name) => {
                let id = format_ident!("{name}");
                quote!(&mut #id)
            }
        }
    }
    fn cxx(&self, arg_name: &str) -> String {
        let ty = match self {
            ArgTy::I32 => "int32_t".into(),
            ArgTy::U32 => "uint32_t".into(),
            ArgTy::U64 => "uint64_t".into(),
            ArgTy::Usize => "size_t".into(),
            ArgTy::Bool => "bool".into(),
            ArgTy::Str => "rust::Str".into(),
            ArgTy::Bytes => "rust::Slice<const uint8_t>".into(),
            ArgTy::Extern(name) => format!("::{}", extern_cxx_name(name)),
            ArgTy::ExternRef(name) => format!("const ::{}&", extern_cxx_name(name)),
            ArgTy::F64 => "double".into(),
            ArgTy::I64 => "int64_t".into(),
            ArgTy::SliceU32 => "rust::Slice<const uint32_t>".into(),
            ArgTy::SliceU64 => "rust::Slice<const uint64_t>".into(),
            ArgTy::SliceStruct(name) => format!("rust::Slice<const {name}>"),
            ArgTy::VisitorMut(name) => format!("{name} &"),
        };
        format!("{ty} {arg_name}")
    }
}

/// `ty`'s Rust token, `ffi_qualified` prefixing a [`ArgTy::SliceStruct`]'s struct name with `ffi::`
/// for use outside `mod ffi` (the sink trait and the visitor's forwarding impl); inside `mod ffi`
/// the bare name already resolves, so callers there pass `false`.
fn visitor_arg_rust(ty: &ArgTy, ffi_qualified: bool) -> TokenStream {
    if let (true, ArgTy::SliceStruct(name)) = (ffi_qualified, ty) {
        let id = format_ident!("{name}");
        return quote!(&[ffi::#id]);
    }
    ty.rust()
}

impl RetKind {
    fn rust(&self) -> TokenStream {
        fn named(name: &str) -> TokenStream {
            let id = format_ident!("{name}");
            quote!(#id)
        }
        match self {
            RetKind::Unit => quote!(),
            RetKind::Bool => quote!(-> bool),
            RetKind::I32 => quote!(-> i32),
            RetKind::U32 => quote!(-> u32),
            RetKind::U64 => quote!(-> u64),
            RetKind::Usize => quote!(-> usize),
            RetKind::ResultUsize => quote!(-> Result<usize>),
            RetKind::ResultU8 => quote!(-> Result<u8>),
            RetKind::ResultU16 => quote!(-> Result<u16>),
            RetKind::ResultU32 => quote!(-> Result<u32>),
            RetKind::ResultU64 => quote!(-> Result<u64>),
            RetKind::String => quote!(-> String),
            RetKind::ResultString => quote!(-> Result<String>),
            RetKind::Extern(n) => {
                let t = named(n);
                quote!(-> #t)
            }
            RetKind::ResultExtern(n) => {
                let t = named(n);
                quote!(-> Result<#t>)
            }
            RetKind::Shared(n) => {
                let t = named(n);
                quote!(-> #t)
            }
            RetKind::ResultShared(n) => {
                let t = named(n);
                quote!(-> Result<#t>)
            }
            RetKind::UniquePtr(n) => {
                let t = named(n);
                quote!(-> UniquePtr<#t>)
            }
            RetKind::ResultUniquePtr(n) => {
                let t = named(n);
                quote!(-> Result<UniquePtr<#t>>)
            }
            RetKind::Vec(n) => {
                let t = named(n);
                quote!(-> Vec<#t>)
            }
            RetKind::ResultVec(n) => {
                let t = named(n);
                quote!(-> Result<Vec<#t>>)
            }
            RetKind::VecU32 => quote!(-> Vec<u32>),
            RetKind::ResultVecU32 => quote!(-> Result<Vec<u32>>),
            RetKind::VecU8 => quote!(-> Vec<u8>),
            RetKind::ResultVecU8 => quote!(-> Result<Vec<u8>>),
        }
    }
    /// The C++ return type. `cxx` maps a `Result<T>` to a C++ function returning `T` that throws,
    /// so both twins share one C++ type.
    fn cxx(&self) -> String {
        match self {
            RetKind::Unit => "void".into(),
            RetKind::Bool => "bool".into(),
            RetKind::I32 => "int32_t".into(),
            RetKind::ResultU8 => "uint8_t".into(),
            RetKind::ResultU16 => "uint16_t".into(),
            RetKind::U32 | RetKind::ResultU32 => "uint32_t".into(),
            RetKind::U64 | RetKind::ResultU64 => "uint64_t".into(),
            RetKind::Usize | RetKind::ResultUsize => "size_t".into(),
            RetKind::String | RetKind::ResultString => "rust::String".into(),
            RetKind::Extern(n) | RetKind::ResultExtern(n) => format!("::{}", extern_cxx_name(n)),
            RetKind::Shared(n) | RetKind::ResultShared(n) => (*n).into(),
            RetKind::UniquePtr(n) | RetKind::ResultUniquePtr(n) => {
                format!("std::unique_ptr<::{}>", extern_cxx_name(n))
            }
            RetKind::Vec(n) | RetKind::ResultVec(n) => format!("rust::Vec<{}>", vec_elem_cxx(n)),
            RetKind::VecU32 | RetKind::ResultVecU32 => "rust::Vec<uint32_t>".into(),
            RetKind::VecU8 | RetKind::ResultVecU8 => "rust::Vec<uint8_t>".into(),
        }
    }
}

/// Resolve a `Vec<Name>` element's C++ spelling: a `Trivial` `ExternType` becomes `::cxx_name`, a
/// shared struct keeps its own name.
fn vec_elem_cxx(name: &str) -> String {
    if is_extern(name) {
        format!("::{}", extern_cxx_name(name))
    } else {
        name.to_string()
    }
}

/// The C++ symbol behind an `ExternType`'s Rust name, e.g. `RangeT` -> `range_t`.
fn extern_cxx_name(rust_name: &str) -> &'static str {
    for d in domains() {
        for e in d.externs {
            if e.rust_name == rust_name {
                return e.cxx_name;
            }
        }
    }
    panic!("unknown ExternType `{rust_name}` referenced in a spec");
}

fn is_extern(rust_name: &str) -> bool {
    domains()
        .iter()
        .any(|d| d.externs.iter().any(|e| e.rust_name == rust_name))
}

/// The module-level `#[repr(C)]` mirror + `unsafe impl ExternType` for one `Trivial`/`Opaque`
/// `ExternType`. These sit outside `mod ffi`, in the same file `bridge_gen.rs` `include!`s.
fn extern_type_tokens(e: &ExternTy) -> TokenStream {
    let rust_id = format_ident!("{}", e.rust_name);
    let type_id_str = e.cxx_name;
    let doc = e.doc;
    let safety = e.safety;
    match &e.kind {
        ExternKind::Trivial(fields) => {
            let field_decls = fields.iter().map(|f| {
                let fid = format_ident!("{}", f.name);
                let fty = f.ty.rust();
                let fdoc = f.doc;
                quote! { #[doc = #fdoc] pub #fid: #fty, }
            });
            quote! {
                #[doc = #doc]
                #[repr(C)]
                #[derive(Clone, Copy, PartialEq, Eq, Debug)]
                pub struct #rust_id {
                    #(#field_decls)*
                }
                #[doc = #safety]
                unsafe impl cxx::ExternType for #rust_id {
                    type Id = cxx::type_id!(#type_id_str);
                    type Kind = cxx::kind::Trivial;
                }
            }
        }
        ExternKind::Opaque => quote! {
            #[doc = #doc]
            #[repr(C)]
            pub struct #rust_id {
                _private: ::cxx::private::Opaque,
            }
            #[doc = #safety]
            unsafe impl cxx::ExternType for #rust_id {
                type Id = cxx::type_id!(#type_id_str);
                type Kind = cxx::kind::Opaque;
            }
        },
    }
}

/// A `cxx` shared struct's declaration inside `mod ffi`, shared by the domain bridge and the
/// visitor bridge.
fn struct_tokens(s: &SharedStruct) -> TokenStream {
    let sid = format_ident!("{}", s.name);
    let doc = s.doc;
    let fields = s.fields.iter().map(|f| {
        let fid = format_ident!("{}", f.name);
        let fty = f.ty.rust();
        let fdoc = f.doc;
        quote! { #[doc = #fdoc] #fid: #fty, }
    });
    quote! {
        #[doc = #doc]
        struct #sid {
            #(#fields)*
        }
    }
}

/// One domain's items inside `mod ffi`: its shared structs, extern-type aliases, its `extern "C++"`
/// block (including the domain header + its fn decls), and any container `impl` blocks.
fn domain_ffi_tokens(d: &Domain) -> TokenStream {
    let structs = d.structs.iter().map(struct_tokens);

    let extern_aliases = d.externs.iter().map(|e| {
        let rust_id = format_ident!("{}", e.rust_name);
        let cxx_name = e.cxx_name;
        quote! {
            #[namespace = ""]
            #[cxx_name = #cxx_name]
            type #rust_id = super::#rust_id;
        }
    });

    let header = d.header();
    let fns = d.fns.iter().map(|f| {
        let name = format_ident!("{}", f.name);
        let recv = f.receiver.map(|r| {
            let rid = format_ident!("{r}");
            quote!(self: &#rid,)
        });
        let args = f.args.iter().map(|a| {
            let an = format_ident!("{}", a.name);
            let at = a.ty.rust();
            quote!(#an: #at)
        });
        let ret = f.ret.rust();
        let doc = f.doc;
        quote! {
            #[doc = #doc]
            fn #name(#recv #(#args),*) #ret;
        }
    });

    // Container glue for hand-written ExternTypes: cxx auto-generates UniquePtr/Vec support only
    // for an in-bridge `type X;`, so force it for each opaque/trivial extern this domain returns.
    let impls = container_impls(d);

    quote! {
        #(#structs)*
        unsafe extern "C++" {
            include!(#header);
            #(#extern_aliases)*
            #(#fns)*
        }
        #impls
    }
}

/// The `impl UniquePtr<T> {}` / `impl Vec<T> {}` blocks a domain needs to force `cxx` to
/// instantiate container glue for its hand-written `ExternType`s.
fn container_impls(d: &Domain) -> TokenStream {
    let mut unique = Vec::new();
    let mut vecs = Vec::new();
    for f in d.fns {
        match &f.ret {
            RetKind::UniquePtr(n) | RetKind::ResultUniquePtr(n) => unique.push(*n),
            RetKind::Vec(n) | RetKind::ResultVec(n) if is_extern(n) => vecs.push(*n),
            _ => {}
        }
    }
    unique.sort_unstable();
    unique.dedup();
    vecs.sort_unstable();
    vecs.dedup();
    let unique = unique.into_iter().map(|n| {
        let id = format_ident!("{n}");
        quote!(impl UniquePtr<#id> {})
    });
    let vecs = vecs.into_iter().map(|n| {
        let id = format_ident!("{n}");
        quote!(impl Vec<#id> {})
    });
    quote! { #(#unique)* #(#vecs)* }
}

/// One `extern "Rust"` opaque-visitor sub-bridge: a sink trait plus the opaque visitor that
/// forwards every call into it. [`visitor_spec::VISITOR_BRIDGE`] pairs two of these (ctree,
/// tinfo type walk) into one shared bridge module.
pub struct VisitorSink {
    /// The sink trait's name, e.g. `"CtreeSink"`.
    pub sink_name: &'static str,
    /// The sink trait's doc comment.
    pub sink_doc: &'static str,
    /// The opaque visitor's name, e.g. `"CtreeVisitor"`.
    pub visitor_name: &'static str,
    /// The opaque visitor's doc comment.
    pub visitor_doc: &'static str,
    /// The sink's methods, in declaration order.
    pub methods: &'static [VisitorMethod],
}

/// One sink-trait method, emitted three times from this one spec: the trait declaration, the
/// opaque visitor's forwarding `impl`, and the bridge's `extern "Rust"` fn decl.
pub struct VisitorMethod {
    pub name: &'static str,
    pub doc: &'static str,
    pub args: &'static [Arg],
    pub ret: RetKind,
    /// Emits `#[allow(clippy::too_many_arguments)]` on all three faces.
    pub too_many_args: bool,
}

/// One `extern "C++"` driver fn in the visitor bridge's shared block: a hand-written entry point
/// (`facade/ctree_cxx.cc` / `facade/typewalk_cxx.cc`) that drives a visitor over a ctree or tinfo.
pub struct VisitorDriverFn {
    pub name: &'static str,
    pub doc: &'static str,
    pub args: &'static [Arg],
    pub ret: RetKind,
    /// Whether the caller must uphold an invariant `cxx` can't check (surfaces as `unsafe fn` plus
    /// a `#[allow(clippy::missing_safety_doc)]`, since the obligation is documented on the
    /// hand-written shim, not regenerated per call).
    pub unsafe_: bool,
}

/// The whole visitor bridge: its shared structs, its sink/visitor pairs, and the `extern "C++"`
/// driver block that shares the `CFunc` extern type with the `idakit_gen` bridge's `hexrays`
/// domain.
pub struct VisitorBridge {
    pub structs: &'static [SharedStruct],
    pub sinks: &'static [VisitorSink],
    pub drivers: &'static [VisitorDriverFn],
}

/// One sink trait: a `pub trait <sink_name> { fn method(&mut self, ...) -> ret; ... }`. Slice
/// arguments name their struct with the `ffi::` prefix (the trait sits outside `mod ffi`).
fn sink_trait_tokens(s: &VisitorSink) -> TokenStream {
    let name = format_ident!("{}", s.sink_name);
    let doc = s.sink_doc;
    let methods = s.methods.iter().map(|m| {
        let mname = format_ident!("{}", m.name);
        let args = m.args.iter().map(|a| {
            let an = format_ident!("{}", a.name);
            let at = visitor_arg_rust(&a.ty, true);
            quote!(#an: #at)
        });
        let ret = m.ret.rust();
        let mdoc = m.doc;
        let allow = m
            .too_many_args
            .then(|| quote!(#[allow(clippy::too_many_arguments)]));
        quote! {
            #[doc = #mdoc]
            #allow
            fn #mname(&mut self, #(#args),*) #ret;
        }
    });
    quote! {
        #[doc = #doc]
        pub trait #name {
            #(#methods)*
        }
    }
}

/// The opaque visitor struct plus its forwarding `impl`: a `sink: NonNull<dyn Sink>` field, a
/// private `sink()` reborrow, and one forwarder per method that calls straight into it. `NonNull`
/// resolves bare because this token stream is spliced (via `include!`) into a file that already
/// `use`s it.
fn visitor_impl_tokens(s: &VisitorSink) -> TokenStream {
    let vname = format_ident!("{}", s.visitor_name);
    let sname = format_ident!("{}", s.sink_name);
    let vdoc = s.visitor_doc;
    let methods = s.methods.iter().map(|m| {
        let mname = format_ident!("{}", m.name);
        let args = m.args.iter().map(|a| {
            let an = format_ident!("{}", a.name);
            let at = visitor_arg_rust(&a.ty, true);
            quote!(#an: #at)
        });
        let arg_names = m.args.iter().map(|a| format_ident!("{}", a.name));
        let ret = m.ret.rust();
        let allow = m
            .too_many_args
            .then(|| quote!(#[allow(clippy::too_many_arguments)]));
        quote! {
            #allow
            fn #mname(&mut self, #(#args),*) #ret {
                self.sink().#mname(#(#arg_names),*)
            }
        }
    });
    quote! {
        #[doc = #vdoc]
        pub struct #vname {
            sink: NonNull<dyn #sname>,
        }

        impl #vname {
            /// Reborrow the erased sink for one callback.
            ///
            /// # Safety
            /// The pointer is valid and unaliased for the walk (single-threaded, non-reentrant,
            /// the walk holds the only borrow).
            fn sink(&mut self) -> &mut dyn #sname {
                unsafe { self.sink.as_mut() }
            }

            #(#methods)*
        }
    }
}

/// The bridge's `extern "Rust" { type <visitor>; fn method(self: &mut <visitor>, ...) -> ret; ... }`
/// block. Slice arguments here name their struct bare (already inside `mod ffi`).
fn visitor_extern_rust_tokens(s: &VisitorSink) -> TokenStream {
    let vname = format_ident!("{}", s.visitor_name);
    let methods = s.methods.iter().map(|m| {
        let mname = format_ident!("{}", m.name);
        let args = m.args.iter().map(|a| {
            let an = format_ident!("{}", a.name);
            let at = visitor_arg_rust(&a.ty, false);
            quote!(#an: #at)
        });
        let ret = m.ret.rust();
        let allow = m
            .too_many_args
            .then(|| quote!(#[allow(clippy::too_many_arguments)]));
        quote! {
            #allow
            fn #mname(self: &mut #vname, #(#args),*) #ret;
        }
    });
    quote! {
        extern "Rust" {
            type #vname;
            #(#methods)*
        }
    }
}

/// One driver fn's `extern "C++"` decl inside `mod ffi`.
fn visitor_driver_tokens(f: &VisitorDriverFn) -> TokenStream {
    let name = format_ident!("{}", f.name);
    let args = f.args.iter().map(|a| {
        let an = format_ident!("{}", a.name);
        let at = a.ty.rust();
        quote!(#an: #at)
    });
    let ret = f.ret.rust();
    let doc = f.doc;
    if f.unsafe_ {
        quote! {
            #[doc = #doc]
            #[allow(clippy::missing_safety_doc)]
            unsafe fn #name(#(#args),*) #ret;
        }
    } else {
        quote! {
            #[doc = #doc]
            fn #name(#(#args),*) #ret;
        }
    }
}

/// The visitor bridge's `#[cxx::bridge] mod ffi { ... }`: its shared structs, both sink pairs'
/// `extern "Rust"` blocks, and the shared `extern "C++"` driver block. The driver block reuses the
/// `idakit_gen` bridge's `CFunc` extern type (the `hexrays` domain's `cfuncptr_t` alias) by cross-
/// bridge Rust path rather than redeclaring it, so the two bridges agree on one type without a
/// conversion at the call site.
fn visitor_bridge_mod_tokens(vb: &VisitorBridge) -> TokenStream {
    let structs = vb.structs.iter().map(struct_tokens);
    let sink_blocks = vb.sinks.iter().map(visitor_extern_rust_tokens);
    let driver_fns = vb.drivers.iter().map(visitor_driver_tokens);
    quote! {
        #[cxx::bridge(namespace = "idakit_cxx")]
        mod ffi {
            #(#structs)*

            #(#sink_blocks)*

            unsafe extern "C++" {
                include!("ctree_cxx.h");
                include!("typewalk_cxx.h");

                /// The same `cfuncptr_t` the `idakit_gen` bridge's `hexrays` domain bound; this is
                /// a type alias, not a fresh opaque type, so a decompiled function feeds
                /// `cfunc_walk_ctree` with no conversion.
                #[namespace = ""]
                #[cxx_name = "cfuncptr_t"]
                type CFunc = crate::bridge_gen::CFunc;

                #(#driver_fns)*
            }
        }
    }
}

/// The whole visitor-bridge token stream: every sink's trait + opaque-visitor impl, then the
/// bridge module. Fed to both the Rust side (written out and `include!`d by `bridge_visitors.rs`)
/// and `cxx-gen` (C++ side), so the two stay in lockstep, mirroring [`bridge_tokens`].
fn visitor_bridge_tokens(vb: &VisitorBridge) -> TokenStream {
    let sinks = vb.sinks.iter().map(|s| {
        let sink_trait = sink_trait_tokens(s);
        let visitor_impl = visitor_impl_tokens(s);
        quote! { #sink_trait #visitor_impl }
    });
    let bridge_mod = visitor_bridge_mod_tokens(vb);
    quote! {
        #(#sinks)*
        #bridge_mod
    }
}

/// Build the whole `#[cxx::bridge] mod` token stream from every domain. Fed to both the Rust side
/// (written out and `include!`d) and `cxx-gen` (C++ side), so the two stay in lockstep.
fn bridge_tokens() -> TokenStream {
    let extern_types = domains()
        .iter()
        .flat_map(|d| d.externs.iter())
        .map(extern_type_tokens);
    let domain_toks = domains().iter().map(|d| domain_ffi_tokens(d));
    quote! {
        #(#extern_types)*

        #[cxx::bridge(namespace = #NAMESPACE)]
        mod ffi {
            #(#domain_toks)*
        }
    }
}

/// The C++ signature `RET name(ARGS)` shared by a domain header decl and a templated body.
fn cxx_signature(f: &FnSpec) -> String {
    let mut args: Vec<String> = Vec::new();
    if let Some(recv) = f.receiver {
        args.push(format!("const ::{}& self", extern_cxx_name(recv)));
    }
    for a in f.args {
        args.push(a.ty.cxx(a.name));
    }
    format!("{} {}({})", f.ret.cxx(), f.name, args.join(", "))
}

/// One domain's C++ header: SDK includes, forward decls for its shared structs, and every function
/// declaration (all body kinds contribute a decl).
fn header_source(d: &Domain) -> String {
    let mut s = String::new();
    s.push_str("#pragma once\n\n");
    s.push_str("#include <cstddef>\n#include <cstdint>\n#include <memory>\n\n");
    s.push_str("#include <pro.h>\n#include <ida.hpp>\n");
    for inc in d.sdk_includes {
        s.push_str(&format!("#include {inc}\n"));
    }
    // The custom trycatch (an idalib interr or a non-std throw becomes a Rust Err, not a terminate)
    // must be in scope in the generated .cc, which includes this header, so cxx's default is
    // disabled; it pulls in rust/cxx.h itself.
    s.push_str("\n#include \"idakit_trycatch.h\"\n\n");
    s.push_str(&format!("namespace {NAMESPACE} {{\n\n"));
    // Shared body helpers, `inline` so the generated body TU and the custom_tu can both call them.
    if let Some(helpers) = d.body_helpers {
        s.push_str(helpers);
        s.push('\n');
    }
    // Shared structs are defined by the cxx-generated header; forward-declare so a decl may name
    // one by value (the body TU includes the generated header for the full definition).
    for st in d.structs {
        s.push_str(&format!("struct {};\n", st.name));
    }
    if !d.structs.is_empty() {
        s.push('\n');
    }
    for f in d.fns {
        // A `self:`-member fn binds the SDK member directly (cxx calls `self.member()`), so it
        // has no free-function declaration or body here.
        if f.receiver.is_some() {
            continue;
        }
        s.push_str(&cxx_signature(f));
        s.push_str(";\n");
    }
    s.push_str(&format!("\n}} // namespace {NAMESPACE}\n"));
    s
}

/// The C++ body for one templated (non-`Custom`) spec, or `None` for `Custom`.
fn body_source(f: &FnSpec) -> Option<String> {
    let sig = cxx_signature(f);
    let body = match &f.body {
        BodyKind::ScalarCall { call } => format!("  return ({}){};\n", f.ret.cxx(), call),
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
        BodyKind::Rendered(body) => (*body).to_string(),
        BodyKind::Custom => return None,
    };
    Some(format!("{sig} {{\n{body}}}\n\n"))
}

/// One domain's templated-bodies TU: SDK includes, the shared header, and every templated body.
/// Returns `None` when the domain has no templated bodies (all `Custom`).
fn bodies_source(d: &Domain) -> Option<String> {
    if !d.has_templated_body() {
        return None;
    }
    let mut s = String::new();
    s.push_str(&format!(
        "// GENERATED from build_support/gen.rs {} -- do not edit.\n",
        d.name
    ));
    s.push_str("#include <pro.h>\n#include <ida.hpp>\n");
    for inc in d.sdk_includes {
        s.push_str(&format!("#include {inc}\n"));
    }
    s.push_str(&format!("\n#include \"{}\"\n\n", d.header()));
    s.push_str(&format!("namespace {NAMESPACE} {{\n\n"));
    for f in d.fns {
        if let Some(body) = body_source(f) {
            s.push_str(&body);
        }
    }
    s.push_str(&format!("}} // namespace {NAMESPACE}\n"));
    Some(s)
}

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
    // unformatted) Rust; OUT_DIR files are never formatted, so that is fine. The aliased netnode
    // re-exports are appended here only, outside the bridge module, so cxx-gen never sees them.
    let mut rust = tokens.to_string();
    rust.push('\n');
    rust.push_str(&netnode::reexport_tokens().to_string());
    std::fs::write(out_dir.join("gen_bridge.rs"), rust).expect("write gen_bridge.rs");

    // C++ side: same tokens => matching shim symbol names on both sides.
    let opt = cxx_gen::Opt::default();
    let code = cxx_gen::generate_header_and_cc(tokens, &opt)
        .expect("cxx-gen rejected the generated bridge tokens");
    std::fs::write(out_dir.join("gen_bridge.h"), &code.header).expect("write gen_bridge.h");
    std::fs::write(out_dir.join("gen_bridge.cc"), &code.implementation)
        .expect("write gen_bridge.cc");

    for d in domains() {
        std::fs::write(out_dir.join(d.header()), header_source(d))
            .unwrap_or_else(|e| panic!("write {}: {e}", d.header()));
        if let Some(bodies) = bodies_source(d) {
            std::fs::write(out_dir.join(d.bodies_file()), bodies)
                .unwrap_or_else(|e| panic!("write {}: {e}", d.bodies_file()));
        }
    }

    // The ctree/tinfo extern "Rust" opaque-visitor bridge, generated the same way as the domain
    // bridge above: one token stream feeds both the Rust side (include!d by bridge_visitors.rs)
    // and cxx-gen (the C++ shim glue, compiled alongside the domain bodies in build.rs).
    let visitor_tokens = visitor_bridge_tokens(&visitor_spec::VISITOR_BRIDGE);
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
