//! The token/string emitters: methods that turn the [`super::model`] spec vocabulary into the
//! Rust bridge `TokenStream`, the C++ header/body `String`s, and the visitor bridge's tokens.

use std::fmt::Write as _;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::domains::domains;
use super::model::*;

/// Group a non-negative decimal digit string into underscore-separated triples from the right
/// (`18446744073709551615` -> `18_446_744_073_709_551_615`), so a wide generated literal reads
/// like a hand-written one and never trips `clippy::unreadable_literal`.
fn group_digits(digits: &str) -> String {
    let n = digits.len();
    let mut out = String::with_capacity(n + n / 3);
    for (i, c) in digits.char_indices() {
        if i > 0 && (n - i).is_multiple_of(3) {
            out.push('_');
        }
        out.push(c);
    }
    out
}

impl ConstTy {
    pub(crate) fn rust(self) -> TokenStream {
        match self {
            Self::U8 => quote!(u8),
            Self::U16 => quote!(u16),
            Self::U32 => quote!(u32),
            Self::U64 => quote!(u64),
            Self::Usize => quote!(usize),
            Self::I32 => quote!(i32),
            Self::I64 => quote!(i64),
        }
    }
    pub(crate) fn cxx(self) -> &'static str {
        match self {
            Self::U8 => "uint8_t",
            Self::U16 => "uint16_t",
            Self::U32 => "uint32_t",
            Self::U64 => "uint64_t",
            Self::Usize => "size_t",
            Self::I32 => "int32_t",
            Self::I64 => "int64_t",
        }
    }
}

impl ConstDef {
    /// This const's Rust value expression: the magnitude's grouped-digit literal, prefixed with a
    /// unary `-` token when negative (a bare literal token can't be negative, so the sign rides
    /// ahead of the always-non-negative magnitude). The `: ty` annotation on the emitted item
    /// pins the width, so an unsuffixed literal suffices.
    fn rust_value_tokens(&self) -> TokenStream {
        let grouped = group_digits(&self.value.unsigned_abs().to_string());
        let magnitude: TokenStream = grouped.parse().expect("grouped digit literal parses");
        if self.value < 0 {
            quote!(-#magnitude)
        } else {
            magnitude
        }
    }

    /// This const's crate-root Rust item: `#[doc = ...] pub const NAME: ty = value;`.
    fn rust_item_tokens(&self) -> TokenStream {
        self.rust_item_tokens_impl(false)
    }

    /// Like [`Self::rust_item_tokens`], but adds `#[doc(hidden)]` -- for a sentinel that exists
    /// only for test-only fault injection and must stay off the public API, matching the
    /// hand-written const it replaced.
    fn rust_item_tokens_hidden(&self) -> TokenStream {
        self.rust_item_tokens_impl(true)
    }

    fn rust_item_tokens_impl(&self, hidden: bool) -> TokenStream {
        let name = format_ident!("{}", self.name);
        let ty = self.ty.rust();
        let value = self.rust_value_tokens();
        let doc = self.doc;
        let hidden = hidden.then(|| quote!(#[doc(hidden)]));
        quote! {
            #[doc = #doc]
            #hidden
            pub const #name: #ty = #value;
        }
    }

    /// This const's C++ literal: a `ULL` suffix on `U64` (plain decimal overflows `int` in C++
    /// otherwise), plain decimal for every narrower width. A negative value's `-` prints as part
    /// of `i128`'s `Display`, valid C++ as a unary minus applied to the magnitude literal.
    fn cxx_literal(&self) -> String {
        match self.ty {
            ConstTy::U64 => format!("{}ULL", self.value),
            _ => self.value.to_string(),
        }
    }

    /// This const's lines in a generated C++ header: a `//` doc comment, then the `constexpr`
    /// declaration.
    fn cxx_lines(&self) -> String {
        format!(
            "// {}\nconstexpr {} {} = {};\n",
            self.doc,
            self.ty.cxx(),
            self.name,
            self.cxx_literal()
        )
    }
}

impl FieldTy {
    pub(crate) fn rust(&self) -> TokenStream {
        match self {
            Self::U8 => quote!(u8),
            Self::U16 => quote!(u16),
            Self::U32 => quote!(u32),
            Self::U64 => quote!(u64),
            Self::I32 => quote!(i32),
            Self::I64 => quote!(i64),
            Self::Usize => quote!(usize),
            Self::Bool => quote!(bool),
            Self::Str => quote!(String),
            Self::Extern(name) | Self::Struct(name) => {
                let id = format_ident!("{name}");
                quote!(#id)
            }
            Self::VecStruct(name) => {
                let id = format_ident!("{name}");
                quote!(Vec<#id>)
            }
        }
    }
}

impl ArgTy {
    pub(crate) fn rust(&self) -> TokenStream {
        match self {
            Self::I32 => quote!(i32),
            Self::U32 => quote!(u32),
            Self::U64 => quote!(u64),
            Self::Usize => quote!(usize),
            Self::Bool => quote!(bool),
            Self::Str => quote!(&str),
            Self::String => quote!(String),
            Self::Bytes => quote!(&[u8]),
            Self::Extern(name) => {
                let id = format_ident!("{name}");
                quote!(#id)
            }
            Self::ExternRef(name) => {
                let id = format_ident!("{name}");
                quote!(&#id)
            }
            Self::F64 => quote!(f64),
            Self::I64 => quote!(i64),
            Self::SliceU32 => quote!(&[u32]),
            Self::SliceU64 => quote!(&[u64]),
            Self::SliceStruct(name) => {
                let id = format_ident!("{name}");
                quote!(&[#id])
            }
            Self::VisitorMut(name) => {
                let id = format_ident!("{name}");
                quote!(&mut #id)
            }
        }
    }
    pub(crate) fn cxx(&self, arg_name: &str) -> String {
        let ty = match self {
            Self::I32 => "int32_t".into(),
            Self::U32 => "uint32_t".into(),
            Self::U64 => "uint64_t".into(),
            Self::Usize => "size_t".into(),
            Self::Bool => "bool".into(),
            Self::Str => "rust::Str".into(),
            Self::String => "rust::String".into(),
            Self::Bytes => "rust::Slice<const uint8_t>".into(),
            Self::Extern(name) => format!("::{}", ExternTy::cxx_name_of(name)),
            Self::ExternRef(name) => format!("const ::{}&", ExternTy::cxx_name_of(name)),
            Self::F64 => "double".into(),
            Self::I64 => "int64_t".into(),
            Self::SliceU32 => "rust::Slice<const uint32_t>".into(),
            Self::SliceU64 => "rust::Slice<const uint64_t>".into(),
            Self::SliceStruct(name) => format!("rust::Slice<const {name}>"),
            Self::VisitorMut(name) => format!("{name} &"),
        };
        format!("{ty} {arg_name}")
    }

    /// `self`'s Rust token, `ffi_qualified` prefixing a [`ArgTy::SliceStruct`]'s struct name with
    /// `ffi::` for use outside `mod ffi` (the sink trait and the visitor's forwarding impl); inside
    /// `mod ffi` the bare name already resolves, so callers there pass `false`.
    pub(crate) fn visitor_rust(&self, ffi_qualified: bool) -> TokenStream {
        if let (true, Self::SliceStruct(name)) = (ffi_qualified, self) {
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
            Self::Unit => quote!(()),
            Self::Bool => quote!(bool),
            Self::I32 => quote!(i32),
            Self::U8 => quote!(u8),
            Self::U16 => quote!(u16),
            Self::U32 => quote!(u32),
            Self::U64 => quote!(u64),
            Self::Usize => quote!(usize),
            Self::String => quote!(String),
            Self::Extern(n) | Self::Shared(n) => named(n),
            Self::UniquePtr(n) => {
                let t = named(n);
                quote!(UniquePtr<#t>)
            }
            Self::Vec(n) => {
                let t = named(n);
                quote!(Vec<#t>)
            }
            Self::VecU32 => quote!(Vec<u32>),
            Self::VecU8 => quote!(Vec<u8>),
        }
    }

    /// The C++ return type, shared by [`RetKind::Value`] and [`RetKind::Fallible`] (`cxx` maps a
    /// throwing fn's C++ type straight to the `Ok` payload's type).
    fn cxx(&self) -> String {
        match self {
            Self::Unit => "void".into(),
            Self::Bool => "bool".into(),
            Self::I32 => "int32_t".into(),
            Self::U8 => "uint8_t".into(),
            Self::U16 => "uint16_t".into(),
            Self::U32 => "uint32_t".into(),
            Self::U64 => "uint64_t".into(),
            Self::Usize => "size_t".into(),
            Self::String => "rust::String".into(),
            Self::Extern(n) => format!("::{}", ExternTy::cxx_name_of(n)),
            Self::Shared(n) => (*n).into(),
            Self::UniquePtr(n) => format!("std::unique_ptr<::{}>", ExternTy::cxx_name_of(n)),
            Self::Vec(n) => format!("rust::Vec<{}>", ExternTy::vec_elem_cxx(n)),
            Self::VecU32 => "rust::Vec<uint32_t>".into(),
            Self::VecU8 => "rust::Vec<uint8_t>".into(),
        }
    }
}

impl RetKind {
    pub(crate) fn rust(&self) -> TokenStream {
        match self {
            Self::Value(RetShape::Unit) => quote!(),
            Self::Value(shape) => {
                let t = shape.rust();
                quote!(-> #t)
            }
            Self::Fallible(shape) => {
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
            let must_use = f.ret.is_must_use().then(|| quote!(#[must_use]));
            quote! {
                #[doc = #doc]
                #must_use
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
            let _ = writeln!(s, "#include {inc}");
        }
        // The custom trycatch (an idalib interr or a non-std throw becomes a Rust Err, not a
        // terminate) must be in scope in the generated .cc, which includes this header, so cxx's
        // default is disabled; it pulls in rust/cxx.h itself. gen_helpers.h carries the shared
        // qstring/byte marshalling helpers every body and custom_tus TU may call.
        s.push_str("\n#include \"trycatch.h\"\n");
        s.push_str("#include \"gen_helpers.h\"\n\n");
        let _ = writeln!(s, "namespace {NAMESPACE} {{\n");
        for c in self.consts {
            s.push_str(&c.cxx_lines());
        }
        if !self.consts.is_empty() {
            s.push('\n');
        }
        // Shared structs are defined by the cxx-generated header; forward-declare so a decl may
        // name one by value (the body TU includes the generated header for the full definition).
        for st in self.structs {
            let _ = writeln!(s, "struct {};", st.name);
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
        let _ = write!(s, "\n}} // namespace {NAMESPACE}\n");
        s
    }

    /// This domain's templated-bodies TU: SDK includes, the shared header, and every templated
    /// body. Returns `None` when the domain has no templated bodies (all `Custom`).
    pub(crate) fn bodies_source(&self) -> Option<String> {
        if !self.has_templated_body() {
            return None;
        }
        let mut s = String::new();
        let _ = writeln!(
            s,
            "// GENERATED by idakit-sys-codegen from the {} domain spec; do not edit.",
            self.name
        );
        s.push_str("#include <pro.h>\n#include <ida.hpp>\n");
        for inc in self.sdk_includes {
            let _ = writeln!(s, "#include {inc}");
        }
        let _ = writeln!(s, "\n#include \"{}\"\n", self.header());
        let _ = writeln!(s, "namespace {NAMESPACE} {{\n");
        for f in self.fns {
            if let Some(body) = f.body_source() {
                s.push_str(&body);
            }
        }
        let _ = writeln!(s, "}} // namespace {NAMESPACE}");
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
                    let _ = writeln!(
                        b,
                        "  if ({getter}(&out, s) <= 0)\n    \
                         throw std::runtime_error(\"segment has no class\");"
                    );
                } else {
                    let _ = writeln!(b, "  {getter}(&out, s);");
                }
                b.push_str("  return to_rust_string(out);\n");
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
    /// the `gen` bridge's `CFunc` extern type (the `hexrays` domain's `cfuncptr_t` alias) by
    /// cross-bridge Rust path rather than redeclaring it, so the two bridges agree on one type
    /// without a conversion at the call site.
    pub(crate) fn mod_tokens(&self) -> TokenStream {
        let structs = self.structs.iter().map(SharedStruct::tokens);
        let sink_blocks = self.sinks.iter().map(VisitorSink::extern_rust_tokens);
        let driver_fns = self.drivers.iter().map(VisitorDriverFn::tokens);
        quote! {
            #[cxx::bridge(namespace = "bridge")]
            mod ffi {
                #(#structs)*

                #(#sink_blocks)*

                unsafe extern "C++" {
                    include!("ctree_bridge.h");
                    include!("typewalk_bridge.h");

                    /// The same `cfuncptr_t` the `gen` bridge's `hexrays` domain bound; this
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

/// The crate-root `pub const`s for every domain's [`Domain::consts`], one bare Rust item per
/// spec'd sentinel. Lives outside the bridge module (`cxx` bridges can't hold `const` items),
/// appended to `gen_bridge.rs` alongside [`reexport_tokens`].
pub(crate) fn consts_tokens() -> TokenStream {
    let consts = domains()
        .iter()
        .flat_map(|d| d.consts.iter())
        .map(ConstDef::rust_item_tokens);
    quote! { #(#consts)* }
}

/// The crate-root `pub const`s for [`super::facade_consts::FACADE_CONSTS`] and
/// [`super::facade_consts::HIDDEN_FACADE_CONSTS`], the sentinels that belong to no single domain
/// (the visitor bridge's absent-child marker, the fatal-exit trap). The hidden list's items carry
/// `#[doc(hidden)]`; the C++ face (`facade_consts_header_source`) makes no such distinction.
/// Appended to `gen_bridge.rs` alongside [`consts_tokens`].
pub(crate) fn facade_consts_tokens() -> TokenStream {
    let public = super::facade_consts::FACADE_CONSTS
        .iter()
        .map(ConstDef::rust_item_tokens);
    let hidden = super::facade_consts::HIDDEN_FACADE_CONSTS
        .iter()
        .map(ConstDef::rust_item_tokens_hidden);
    quote! { #(#public)* #(#hidden)* }
}

/// The shared marshalling helpers, `inline` so every TU that includes a domain header defines
/// them at most once yet links to one body. Both the generated bodies and the hand-written
/// `custom_tus` TUs call these to copy a filled `qstring` / byte buffer out as its owning Rust type.
const HELPERS: &str = "\
// Copy a filled qstring / C string out as an owning Rust String in one crossing, decoding
// leniently: IDA emits UTF-8, and get_strlit_contents already replaces any undecodable unit with
// U+FFFD, so `lossy` never rejects yet a stray bad byte degrades instead of unwinding across the
// extern \"C\"/cxx boundary (the throwing rust::String ctor would std::terminate here).
inline rust::String to_rust_string(const char *s, size_t n) { return rust::String::lossy(s, n); }
inline rust::String to_rust_string(const char *s) { return rust::String::lossy(s); }
inline rust::String to_rust_string(const qstring &s) { return to_rust_string(s.c_str(), s.length()); }

inline rust::Vec<uint8_t> to_rust_bytes(const uint8_t *data, size_t n) {
  rust::Vec<uint8_t> out;
  out.reserve(n);
  for (size_t i = 0; i < n; i++)
    out.push_back(data[i]);
  return out;
}
";

/// The standalone `gen_helpers.h`: the shared [`HELPERS`] in the `gen` namespace, included
/// by every domain header (so every generated body and `custom_tus` TU gets them without a per-domain
/// opt-in). Self-contained: pulls in `qstring` and the `rust::` types it names.
pub(crate) fn helpers_header_source() -> String {
    let mut s = String::from("#pragma once\n\n#include <cstddef>\n#include <cstdint>\n\n");
    s.push_str("#include <pro.h>\n\n#include \"rust/cxx.h\"\n\n");
    let _ = writeln!(s, "namespace {NAMESPACE} {{\n");
    s.push_str(HELPERS);
    let _ = write!(s, "\n}} // namespace {NAMESPACE}\n");
    s
}

/// The standalone `gen_facade_consts.h`: every [`super::facade_consts::FACADE_CONSTS`] and
/// [`super::facade_consts::HIDDEN_FACADE_CONSTS`] sentinel as a `constexpr` in the `gen`
/// namespace, for the raw (non-domain) facade TUs that need one (`runtime.cpp`, `testonly_probe.cpp`,
/// the visitor bridge's `ctree_bridge.cpp`/`typewalk_bridge.cpp`).
pub(crate) fn facade_consts_header_source() -> String {
    let mut s = String::new();
    s.push_str("#pragma once\n\n#include <cstdint>\n\n");
    let _ = writeln!(s, "namespace {NAMESPACE} {{\n");
    for c in super::facade_consts::FACADE_CONSTS
        .iter()
        .chain(super::facade_consts::HIDDEN_FACADE_CONSTS)
    {
        s.push_str(&c.cxx_lines());
    }
    let _ = write!(s, "\n}} // namespace {NAMESPACE}\n");
    s
}
