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
use syn::{Error, ItemFn, parse_macro_input};

/// Registers the annotated test with the warm-worker harness.
///
/// Bare `#[kernel_test]` declares that the test writes to the database, so the harness gives it a
/// freshly reopened one. `#[kernel_test(read_only)]` declares that it does not, letting it share
/// one open database with its neighbours, which is where the harness saves most of its time. The
/// default is the safe direction: a test wrongly marked `read_only` corrupts the ones that follow
/// it, while a read-only test left unmarked only costs a reopen.
///
/// Because the annotated function takes no arguments, this composes with `rstest`'s
/// `#[test_attr(kernel_test)]` seam, which applies it to each generated case.
#[proc_macro_attribute]
pub fn kernel_test(args: TokenStream, item: TokenStream) -> TokenStream {
    let isolation = match isolation(args) {
        Ok(isolation) => isolation,
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

    let isolation = syn::Ident::new(isolation, proc_macro2::Span::call_site());
    quote! {
        #func

        ::inventory::submit! {
            crate::common::registry::KernelTest {
                module: ::core::module_path!(),
                name: ::core::stringify!(#name),
                isolation: crate::common::registry::Isolation::#isolation,
                run: #name,
            }
        }
    }
    .into()
}

/// The `Isolation` variant named by the attribute's arguments.
fn isolation(args: TokenStream) -> Result<&'static str, Error> {
    if args.is_empty() {
        return Ok("Writes");
    }
    let ident = syn::parse::<syn::Ident>(args).map_err(|e| {
        Error::new(
            e.span(),
            "expected #[kernel_test] or #[kernel_test(read_only)]",
        )
    })?;
    if ident == "read_only" {
        Ok("ReadOnly")
    } else {
        Err(Error::new_spanned(
            ident,
            "unknown argument; the only one is `read_only`",
        ))
    }
}
