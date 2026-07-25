//! The `#[kernel_test]` attribute, which registers a kernel-touching test with the warm-worker
//! harness instead of with libtest.
//!
//! A registered test is an ordinary zero-argument function. The attribute leaves it untouched and
//! adds an [`inventory`](https://docs.rs/inventory) submission beside it, so the harness binary can
//! enumerate every test that linked in without a central list to keep in sync.
//!
//! The submission names `crate::common::registry::KernelTest`, so the attribute only works inside a
//! test binary that has `common` in scope. That coupling is deliberate: the registry has to know
//! about `Database`, which the runner crate is generic over and must not depend on.

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::{Error, Expr, ExprLit, ItemFn, Lit, Meta, Token, parse_macro_input};

/// Registers the annotated test with the warm-worker harness.
///
/// Bare `#[kernel_test]` declares that the test writes to the database, so the harness gives it a
/// freshly reopened one. `#[kernel_test(read_only)]` declares that it does not, letting it share
/// one open database with its neighbours, which is where the harness saves most of its time. The
/// default is the safe direction: a test wrongly marked `read_only` corrupts the ones that follow
/// it, while a read-only test left unmarked only costs a reopen.
///
/// `#[kernel_test(should_panic)]` inverts the verdict, and `should_panic = "substring"` also
/// requires the panic message to contain that text, mirroring libtest's own attribute. Both compose
/// with `read_only` in either order.
///
/// Because the annotated function takes no arguments, this composes with `rstest`'s
/// `#[test_attr(kernel_test)]` seam, which applies it to each generated case.
#[proc_macro_attribute]
pub fn kernel_test(args: TokenStream, item: TokenStream) -> TokenStream {
    let options = match Options::parse(args) {
        Ok(options) => options,
        Err(err) => return err.to_compile_error().into(),
    };
    let func = parse_macro_input!(item as ItemFn);
    let name = &func.sig.ident;

    if !func.sig.inputs.is_empty() {
        return Error::new_spanned(
            &func.sig,
            "a #[kernel_test] takes no arguments; reach the database through with_canonical_db",
        )
        .to_compile_error()
        .into();
    }

    let isolation = syn::Ident::new(options.isolation, proc_macro2::Span::call_site());
    let should_panic = options.should_panic.map_or_else(
        || quote!(::core::option::Option::None),
        |expected| quote!(::core::option::Option::Some(#expected)),
    );
    quote! {
        #func

        ::inventory::submit! {
            crate::common::registry::KernelTest {
                module: ::core::module_path!(),
                name: ::core::stringify!(#name),
                isolation: crate::common::registry::Isolation::#isolation,
                should_panic: #should_panic,
                run: #name,
            }
        }
    }
    .into()
}

/// What the attribute's arguments declared.
struct Options {
    /// The `Isolation` variant to register.
    isolation: &'static str,
    /// The required panic message, empty for any panic, or `None` if the test must not panic.
    should_panic: Option<String>,
}

impl Options {
    fn parse(args: TokenStream) -> Result<Self, Error> {
        let mut options = Self {
            isolation: "Writes",
            should_panic: None,
        };
        if args.is_empty() {
            return Ok(options);
        }

        for meta in Punctuated::<Meta, Token![,]>::parse_terminated.parse(args)? {
            match &meta {
                Meta::Path(path) if path.is_ident("read_only") => options.isolation = "ReadOnly",
                Meta::Path(path) if path.is_ident("should_panic") => {
                    options.should_panic = Some(String::new());
                }
                Meta::NameValue(pair) if pair.path.is_ident("should_panic") => {
                    let Expr::Lit(ExprLit {
                        lit: Lit::Str(text),
                        ..
                    }) = &pair.value
                    else {
                        return Err(Error::new_spanned(
                            &pair.value,
                            "should_panic takes a string literal, as in should_panic = \"boom\"",
                        ));
                    };
                    options.should_panic = Some(text.value());
                }
                _ => {
                    return Err(Error::new_spanned(
                        meta,
                        "expected read_only, should_panic, or should_panic = \"substring\"",
                    ));
                }
            }
        }
        Ok(options)
    }
}
