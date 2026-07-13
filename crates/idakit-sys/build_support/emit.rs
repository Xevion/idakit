//! The token/string emitters: methods that turn the [`super::model`] spec vocabulary into the
//! Rust bridge `TokenStream`, the C++ header/body `String`s, and the visitor bridge's tokens.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::model::*;
use super::spec::domains;

impl FieldTy {
    pub(crate) fn rust(&self) -> TokenStream {
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
    pub(crate) fn rust(&self) -> TokenStream {
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
    pub(crate) fn cxx(&self, arg_name: &str) -> String {
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

    /// `self`'s Rust token, `ffi_qualified` prefixing a [`ArgTy::SliceStruct`]'s struct name with
    /// `ffi::` for use outside `mod ffi` (the sink trait and the visitor's forwarding impl); inside
    /// `mod ffi` the bare name already resolves, so callers there pass `false`.
    pub(crate) fn visitor_rust(&self, ffi_qualified: bool) -> TokenStream {
        if let (true, ArgTy::SliceStruct(name)) = (ffi_qualified, self) {
            let id = format_ident!("{name}");
            return quote!(&[ffi::#id]);
        }
        self.rust()
    }
}

impl RetKind {
    pub(crate) fn rust(&self) -> TokenStream {
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
    pub(crate) fn cxx(&self) -> String {
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

impl ExternTy {
    /// The module-level `#[repr(C)]` mirror + `unsafe impl ExternType` for one `Trivial`/`Opaque`
    /// `ExternType`. These sit outside `mod ffi`, in the same file `bridge_gen.rs` `include!`s.
    pub(crate) fn tokens(&self) -> TokenStream {
        let rust_id = format_ident!("{}", self.rust_name);
        let type_id_str = self.cxx_name;
        let doc = self.doc;
        let safety = self.safety;
        match &self.kind {
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
}

impl SharedStruct {
    /// This shared struct's declaration inside `mod ffi`, shared by the domain bridge and the
    /// visitor bridge.
    pub(crate) fn tokens(&self) -> TokenStream {
        let sid = format_ident!("{}", self.name);
        let doc = self.doc;
        let fields = self.fields.iter().map(|f| {
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
}

impl Domain {
    /// This domain's items inside `mod ffi`: its shared structs, extern-type aliases, its
    /// `extern "C++"` block (including the domain header + its fn decls), and any container `impl`
    /// blocks.
    pub(crate) fn ffi_tokens(&self) -> TokenStream {
        let structs = self.structs.iter().map(SharedStruct::tokens);

        let extern_aliases = self.externs.iter().map(|e| {
            let rust_id = format_ident!("{}", e.rust_name);
            let cxx_name = e.cxx_name;
            quote! {
                #[namespace = ""]
                #[cxx_name = #cxx_name]
                type #rust_id = super::#rust_id;
            }
        });

        let header = self.header();
        let fns = self.fns.iter().map(|f| {
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

        // Container glue for hand-written ExternTypes: cxx auto-generates UniquePtr/Vec support
        // only for an in-bridge `type X;`, so force it for each opaque/trivial extern this domain
        // returns.
        let impls = self.container_impls();

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

    /// The `impl UniquePtr<T> {}` / `impl Vec<T> {}` blocks this domain needs to force `cxx` to
    /// instantiate container glue for its hand-written `ExternType`s.
    pub(crate) fn container_impls(&self) -> TokenStream {
        let mut unique = Vec::new();
        let mut vecs = Vec::new();
        for f in self.fns {
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

    /// This domain's C++ header: SDK includes, forward decls for its shared structs, and every
    /// function declaration (all body kinds contribute a decl).
    pub(crate) fn header_source(&self) -> String {
        let mut s = String::new();
        s.push_str("#pragma once\n\n");
        s.push_str("#include <cstddef>\n#include <cstdint>\n#include <memory>\n\n");
        s.push_str("#include <pro.h>\n#include <ida.hpp>\n");
        for inc in self.sdk_includes {
            s.push_str(&format!("#include {inc}\n"));
        }
        // The custom trycatch (an idalib interr or a non-std throw becomes a Rust Err, not a
        // terminate) must be in scope in the generated .cc, which includes this header, so cxx's
        // default is disabled; it pulls in rust/cxx.h itself.
        s.push_str("\n#include \"idakit_trycatch.h\"\n\n");
        s.push_str(&format!("namespace {NAMESPACE} {{\n\n"));
        // Shared body helpers, `inline` so the generated body TU and the custom_tu can both call
        // them.
        if let Some(helpers) = self.body_helpers {
            s.push_str(helpers);
            s.push('\n');
        }
        // Shared structs are defined by the cxx-generated header; forward-declare so a decl may
        // name one by value (the body TU includes the generated header for the full definition).
        for st in self.structs {
            s.push_str(&format!("struct {};\n", st.name));
        }
        if !self.structs.is_empty() {
            s.push('\n');
        }
        for f in self.fns {
            // A `self:`-member fn binds the SDK member directly (cxx calls `self.member()`), so it
            // has no free-function declaration or body here.
            if f.receiver.is_some() {
                continue;
            }
            s.push_str(&f.cxx_signature());
            s.push_str(";\n");
        }
        s.push_str(&format!("\n}} // namespace {NAMESPACE}\n"));
        s
    }

    /// This domain's templated-bodies TU: SDK includes, the shared header, and every templated
    /// body. Returns `None` when the domain has no templated bodies (all `Custom`).
    pub(crate) fn bodies_source(&self) -> Option<String> {
        if !self.has_templated_body() {
            return None;
        }
        let mut s = String::new();
        s.push_str(&format!(
            "// GENERATED from build_support/gen.rs {} -- do not edit.\n",
            self.name
        ));
        s.push_str("#include <pro.h>\n#include <ida.hpp>\n");
        for inc in self.sdk_includes {
            s.push_str(&format!("#include {inc}\n"));
        }
        s.push_str(&format!("\n#include \"{}\"\n\n", self.header()));
        s.push_str(&format!("namespace {NAMESPACE} {{\n\n"));
        for f in self.fns {
            if let Some(body) = f.body_source() {
                s.push_str(&body);
            }
        }
        s.push_str(&format!("}} // namespace {NAMESPACE}\n"));
        Some(s)
    }
}

impl FnSpec {
    /// The C++ signature `RET name(ARGS)` shared by a domain header decl and a templated body.
    pub(crate) fn cxx_signature(&self) -> String {
        let mut args: Vec<String> = Vec::new();
        if let Some(recv) = self.receiver {
            args.push(format!("const ::{}& self", extern_cxx_name(recv)));
        }
        for a in self.args {
            args.push(a.ty.cxx(a.name));
        }
        format!("{} {}({})", self.ret.cxx(), self.name, args.join(", "))
    }

    /// The C++ body for this templated (non-`Custom`) spec, or `None` for `Custom`.
    pub(crate) fn body_source(&self) -> Option<String> {
        let sig = self.cxx_signature();
        let body = match &self.body {
            BodyKind::ScalarCall { call } => format!("  return ({}){};\n", self.ret.cxx(), call),
            BodyKind::SegScalar {
                accessor,
                null_sentinel,
            } => {
                let cast = self.ret.cxx();
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
}

impl VisitorMethod {
    /// `#[allow(clippy::too_many_arguments)]` on all three faces once the arg count crosses
    /// clippy's default threshold of 7 (the visitor's `&mut self` receiver doesn't count).
    pub(crate) fn too_many_args_allow(&self) -> Option<TokenStream> {
        (self.args.len() > 7).then(|| quote!(#[allow(clippy::too_many_arguments)]))
    }
}

impl VisitorSink {
    /// One sink trait: a `pub trait <sink_name> { fn method(&mut self, ...) -> ret; ... }`. Slice
    /// arguments name their struct with the `ffi::` prefix (the trait sits outside `mod ffi`).
    pub(crate) fn sink_trait_tokens(&self) -> TokenStream {
        let name = format_ident!("{}", self.sink_name);
        let doc = self.sink_doc;
        let methods = self.methods.iter().map(|m| {
            let mname = format_ident!("{}", m.name);
            let args = m.args.iter().map(|a| {
                let an = format_ident!("{}", a.name);
                let at = a.ty.visitor_rust(true);
                quote!(#an: #at)
            });
            let ret = m.ret.rust();
            let mdoc = m.doc;
            let allow = m.too_many_args_allow();
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
    /// private `sink()` reborrow, and one forwarder per method that calls straight into it.
    /// `NonNull` resolves bare because this token stream is spliced (via `include!`) into a file
    /// that already `use`s it.
    pub(crate) fn visitor_impl_tokens(&self) -> TokenStream {
        let vname = format_ident!("{}", self.visitor_name);
        let sname = format_ident!("{}", self.sink_name);
        let vdoc = self.visitor_doc;
        let methods = self.methods.iter().map(|m| {
            let mname = format_ident!("{}", m.name);
            let args = m.args.iter().map(|a| {
                let an = format_ident!("{}", a.name);
                let at = a.ty.visitor_rust(true);
                quote!(#an: #at)
            });
            let arg_names = m.args.iter().map(|a| format_ident!("{}", a.name));
            let ret = m.ret.rust();
            let allow = m.too_many_args_allow();
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

    /// The bridge's `extern "Rust" { type <visitor>; fn method(self: &mut <visitor>, ...) -> ret;
    /// ... }` block. Slice arguments here name their struct bare (already inside `mod ffi`).
    pub(crate) fn extern_rust_tokens(&self) -> TokenStream {
        let vname = format_ident!("{}", self.visitor_name);
        let methods = self.methods.iter().map(|m| {
            let mname = format_ident!("{}", m.name);
            let args = m.args.iter().map(|a| {
                let an = format_ident!("{}", a.name);
                let at = a.ty.visitor_rust(false);
                quote!(#an: #at)
            });
            let ret = m.ret.rust();
            let allow = m.too_many_args_allow();
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
}

impl VisitorDriverFn {
    /// This driver fn's `extern "C++"` decl inside `mod ffi`.
    pub(crate) fn tokens(&self) -> TokenStream {
        let name = format_ident!("{}", self.name);
        let args = self.args.iter().map(|a| {
            let an = format_ident!("{}", a.name);
            let at = a.ty.rust();
            quote!(#an: #at)
        });
        let ret = self.ret.rust();
        let doc = self.doc;
        if self.unsafe_ {
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
}

impl VisitorBridge {
    /// The visitor bridge's `#[cxx::bridge] mod ffi { ... }`: its shared structs, both sink pairs'
    /// `extern "Rust"` blocks, and the shared `extern "C++"` driver block. The driver block reuses
    /// the `idakit_gen` bridge's `CFunc` extern type (the `hexrays` domain's `cfuncptr_t` alias) by
    /// cross-bridge Rust path rather than redeclaring it, so the two bridges agree on one type
    /// without a conversion at the call site.
    pub(crate) fn mod_tokens(&self) -> TokenStream {
        let structs = self.structs.iter().map(SharedStruct::tokens);
        let sink_blocks = self.sinks.iter().map(VisitorSink::extern_rust_tokens);
        let driver_fns = self.drivers.iter().map(VisitorDriverFn::tokens);
        quote! {
            #[cxx::bridge(namespace = "idakit_cxx")]
            mod ffi {
                #(#structs)*

                #(#sink_blocks)*

                unsafe extern "C++" {
                    include!("ctree_cxx.h");
                    include!("typewalk_cxx.h");

                    /// The same `cfuncptr_t` the `idakit_gen` bridge's `hexrays` domain bound; this
                    /// is a type alias, not a fresh opaque type, so a decompiled function feeds
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
    /// bridge module. Fed to both the Rust side (written out and `include!`d by
    /// `bridge_visitors.rs`) and `cxx-gen` (C++ side), so the two stay in lockstep, mirroring
    /// [`bridge_tokens`](super::bridge_tokens).
    pub(crate) fn tokens(&self) -> TokenStream {
        let sinks = self.sinks.iter().map(|s| {
            let sink_trait = s.sink_trait_tokens();
            let visitor_impl = s.visitor_impl_tokens();
            quote! { #sink_trait #visitor_impl }
        });
        let bridge_mod = self.mod_tokens();
        quote! {
            #(#sinks)*
            #bridge_mod
        }
    }
}

/// Build the whole `#[cxx::bridge] mod` token stream from every domain. Fed to both the Rust side
/// (written out and `include!`d) and `cxx-gen` (C++ side), so the two stay in lockstep.
pub(crate) fn bridge_tokens() -> TokenStream {
    let extern_types = domains().iter().flat_map(|d| d.externs.iter()).map(ExternTy::tokens);
    let domain_toks = domains().iter().map(|d| d.ffi_tokens());
    quote! {
        #(#extern_types)*

        #[cxx::bridge(namespace = #NAMESPACE)]
        mod ffi {
            #(#domain_toks)*
        }
    }
}
