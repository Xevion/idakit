//! Registration attributes for the warm-kernel harness in `idakit-test`.
//!
//! Both attributes emit an `inventory::submit!` that registers a niladic case fn as an
//! `idakit_test::KernelTest`, so the harness binary discovers cases at runtime rather than through
//! libtest. They generate references to `::idakit_test`, so a test crate depends only on
//! `idakit-test` (which re-exports these) and never names this crate directly.
//!
//! [`register`] is the target of upstream rstest's `#[test_attr(idakit_test::register)]`: rstest
//! expands `#[rstest]` plus `#[case]`/fixtures into one niladic case fn per row and injects this
//! attribute onto each, so the already-generated case registers without rstest knowing the harness
//! exists. [`kernel_test`] is the plain path for a hand-written case, carrying an optional `weight`
//! for the daemon's admission scheduler.

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::{Expr, ItemFn, Lit, Meta, Token, parse_macro_input};

/// Registers the annotated case at weight 1, the target of rstest's `#[test_attr(...)]`.
///
/// rstest emits one niladic fn per parametrized row and applies this attribute to each, so a full
/// `#[rstest]` (case expansion, fixtures) registers with the harness through the generated fns.
#[proc_macro_attribute]
pub fn register(_attr: TokenStream, item: TokenStream) -> TokenStream {
    emit(&parse_macro_input!(item as ItemFn), 1)
}

/// Registers a hand-written case with an optional weight: `#[kernel_test]` or
/// `#[kernel_test(weight = 3)]`.
///
/// The weight is the case's admission cost in the daemon's token pool; a heavier case reserves more
/// of the pool, so heavy cases serialize while light ones pack in around them.
#[proc_macro_attribute]
pub fn kernel_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let weight = parse_weight(attr).unwrap_or(1);
    emit(&parse_macro_input!(item as ItemFn), weight)
}

/// Emits `func` unchanged plus the `inventory::submit!` that registers it under its fully-qualified
/// name (`module_path!()::ident`, unique within the binary).
fn emit(func: &ItemFn, weight: u32) -> TokenStream {
    let ident = func.sig.ident.clone();
    quote! {
        #func
        ::idakit_test::inventory::submit! {
            ::idakit_test::KernelTest {
                name: ::core::concat!(::core::module_path!(), "::", ::core::stringify!(#ident)),
                run: #ident,
                weight: #weight,
            }
        }
    }
    .into()
}

/// Pulls `weight = <int>` out of the attribute args, or `None` when absent.
fn parse_weight(attr: TokenStream) -> Option<u32> {
    let metas = Punctuated::<Meta, Token![,]>::parse_terminated
        .parse(attr)
        .ok()?;
    for meta in metas {
        if let Meta::NameValue(nv) = meta
            && nv.path.is_ident("weight")
            && let Expr::Lit(lit) = nv.value
            && let Lit::Int(int) = lit.lit
        {
            return int.base10_parse().ok();
        }
    }
    None
}
