//! The token/string emitters: methods that turn the [`super::model`] spec vocabulary into the
//! Rust bridge `TokenStream`, the C++ header/body `String`s, and the visitor bridge's tokens.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::domains::domains;
use super::model::*;

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
            ArgTy::Extern(name) => format!("::{}", ExternTy::cxx_name_of(name)),
            ArgTy::ExternRef(name) => format!("const ::{}&", ExternTy::cxx_name_of(name)),
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

impl RetShape {
    /// This shape's plain Rust type (no `Result` wrapper); [`RetKind::rust`] adds that.
    fn rust(&self) -> TokenStream {
        fn named(name: &str) -> TokenStream {
            let id = format_ident!("{name}");
            quote!(#id)
        }
        match self {
            RetShape::Unit => quote!(()),
            RetShape::Bool => quote!(bool),
            RetShape::I32 => quote!(i32),
            RetShape::U8 => quote!(u8),
            RetShape::U16 => quote!(u16),
            RetShape::U32 => quote!(u32),
            RetShape::U64 => quote!(u64),
            RetShape::Usize => quote!(usize),
            RetShape::String => quote!(String),
            RetShape::Extern(n) | RetShape::Shared(n) => named(n),
            RetShape::UniquePtr(n) => {
                let t = named(n);
                quote!(UniquePtr<#t>)
            }
            RetShape::Vec(n) => {
                let t = named(n);
                quote!(Vec<#t>)
            }
            RetShape::VecU32 => quote!(Vec<u32>),
            RetShape::VecU8 => quote!(Vec<u8>),
        }
    }

    /// The C++ return type, shared by [`RetKind::Value`] and [`RetKind::Fallible`] (`cxx` maps a
    /// throwing fn's C++ type straight to the `Ok` payload's type).
    fn cxx(&self) -> String {
        match self {
            RetShape::Unit => "void".into(),
            RetShape::Bool => "bool".into(),
            RetShape::I32 => "int32_t".into(),
            RetShape::U8 => "uint8_t".into(),
            RetShape::U16 => "uint16_t".into(),
            RetShape::U32 => "uint32_t".into(),
            RetShape::U64 => "uint64_t".into(),
            RetShape::Usize => "size_t".into(),
            RetShape::String => "rust::String".into(),
            RetShape::Extern(n) => format!("::{}", ExternTy::cxx_name_of(n)),
            RetShape::Shared(n) => (*n).into(),
            RetShape::UniquePtr(n) => format!("std::unique_ptr<::{}>", ExternTy::cxx_name_of(n)),
            RetShape::Vec(n) => format!("rust::Vec<{}>", ExternTy::vec_elem_cxx(n)),
            RetShape::VecU32 => "rust::Vec<uint32_t>".into(),
            RetShape::VecU8 => "rust::Vec<uint8_t>".into(),
        }
    }
}

impl RetKind {
    pub(crate) fn rust(&self) -> TokenStream {
        match self {
            RetKind::Value(RetShape::Unit) => quote!(),
            RetKind::Value(shape) => {
                let t = shape.rust();
                quote!(-> #t)
            }
            RetKind::Fallible(shape) => {
                let t = shape.rust();
                quote!(-> Result<#t>)
            }
        }
    }
    /// The C++ return type; both variants share [`RetShape::cxx`].
    pub(crate) fn cxx(&self) -> String {
        self.shape().cxx()
    }
}

impl ExternTy {
    /// Find the domain-declared `ExternTy` a Rust name refers to, the shared lookup behind
    /// [`Self::cxx_name_of`] and [`Self::exists`].
    fn find(rust_name: &str) -> Option<&'static Self> {
        domains()
            .iter()
            .flat_map(|d| d.externs.iter())
            .find(|e| e.rust_name == rust_name)
    }

    /// The C++ symbol behind an `ExternType`'s Rust name, e.g. `RangeT` -> `range_t`.
    fn cxx_name_of(rust_name: &str) -> &'static str {
        Self::find(rust_name)
            .unwrap_or_else(|| panic!("unknown ExternType `{rust_name}` referenced in a spec"))
            .cxx_name
    }

    fn exists(rust_name: &str) -> bool {
        Self::find(rust_name).is_some()
    }

    /// Resolve a `Vec<Name>` element's C++ spelling: a `Trivial` `ExternType` becomes
    /// `::cxx_name`, a shared struct keeps its own name.
    fn vec_elem_cxx(name: &str) -> String {
        if Self::exists(name) {
            format!("::{}", Self::cxx_name_of(name))
        } else {
            name.to_string()
        }
    }

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
        // for a type declared directly in the bridge (`type X;`), not one merely aliased in from
        // outside (the extern_aliases above), so force it here for each extern this domain returns.
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
            match f.ret.shape() {
                RetShape::UniquePtr(n) => unique.push(*n),
                RetShape::Vec(n) if ExternTy::exists(n) => vecs.push(*n),
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
            "// GENERATED by idakit-sys-codegen from the {} domain spec; do not edit.\n",
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
            args.push(format!("const ::{}& self", ExternTy::cxx_name_of(recv)));
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
    let extern_types = domains()
        .iter()
        .flat_map(|d| d.externs.iter())
        .map(ExternTy::tokens);
    let domain_toks = domains().iter().map(|d| d.ffi_tokens());
    quote! {
        #(#extern_types)*

        #[cxx::bridge(namespace = #NAMESPACE)]
        mod ffi {
            #(#domain_toks)*
        }
    }
}

/// The crate-root re-exports carrying a `#[doc(alias)]` for every [`FnSpec::sdk_alias`] set across
/// every domain, so a reader of the IDA SDK can find the flat binding by its SDK member name. `cxx`
/// rejects `#[doc(alias)]` inside the bridge (only `#[doc = ...]` and `#[doc(hidden)]` pass), so the
/// alias rides a second, named `pub use` instead; it coexists with `bridge_gen.rs`'s glob re-export
/// (an explicit import shadows a glob one for the same name, so this is not a duplicate-item error)
/// and survives into rustdoc search. A domain with no aliased fns contributes nothing here, since
/// the glob re-export already exposes its names.
pub(crate) fn reexport_tokens() -> TokenStream {
    let uses = domains().iter().flat_map(|d| d.fns.iter()).filter_map(|f| {
        let alias = f.sdk_alias?;
        let name = format_ident!("{}", f.name);
        Some(quote! {
            #[doc(alias = #alias)]
            pub use ffi::#name;
        })
    });
    quote! { #(#uses)* }
}
