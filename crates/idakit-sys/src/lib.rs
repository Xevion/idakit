//! Raw FFI bindings to IDA's idalib runtime and the idakit C++ facade.
//!
//! The declarations are split into per-domain source modules (`runtime`, `function`, `bytes`,
//! `hexrays`, ...) that mirror the facade's translation units, but every item is re-exported
//! flat at the crate root, so the public surface is a single namespace
//! (`idakit_sys::idakit_func_qty`, `idakit_sys::InstructionRaw`), not a module hierarchy. There are
//! no safe wrappers here; those belong in `idakit`.
//!
//! # Buffer conventions
//!
//! Functions that accept `(*mut c_char, cap: usize)` copy the value into the
//! caller-supplied buffer and NUL-terminate within `cap` bytes. The return value
//! is the full source length, which may exceed `cap` when the output was
//! truncated. A negative return value means the query failed (missing symbol,
//! null handle, etc.).
//!
//! # Owned handles
//!
//! `idakit_decompile` returns an opaque `*mut c_void` handle owned by the caller,
//! released with its matching `*_dispose` function (`idakit_cfunc_dispose`); the reference
//! cursor from `idakit_xref_open` is released with `idakit_xref_close` instead.
//! Passing a handle to any other function after release is undefined behaviour.
#![deny(
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::invalid_rust_codeblocks,
    rustdoc::bare_urls,
    rustdoc::unescaped_backticks,
    rustdoc::redundant_explicit_links
)]

/// IDA's effective address (`ea_t`), compiled `__EA64__`.
pub type Address = u64;
/// The invalid-address sentinel (`BADADDR`); every `Address`-returning facade call uses it for
/// "no address".
pub const BADADDR: Address = u64::MAX;

mod bridge;
mod bridge_cfg;
mod bridge_cfg2;
#[cfg(feature = "test-shims")]
mod bridge_cfunc;
mod bridge_gen;
#[cfg(feature = "test-shims")]
mod bridge_probe;
#[cfg(feature = "test-shims")]
mod bridge_probe_ext;
mod bridge_qvec;
mod bridge_range;
mod bridge_typewalk;
mod bytes;
mod cfg;
mod export;
mod frame;
mod function;
mod hexrays;
mod import;
mod instruction;
mod meta;
mod name;
mod reference;
mod runtime;
mod segment;
mod strings;
mod ty;
mod ty_build;

pub use bridge::*;
pub use bridge_cfg::*;
pub use bridge_cfg2::*;
#[cfg(feature = "test-shims")]
pub use bridge_cfunc::*;
pub use bridge_gen::*;
#[cfg(feature = "test-shims")]
pub use bridge_probe::*;
#[cfg(feature = "test-shims")]
pub use bridge_probe_ext::*;
pub use bridge_qvec::*;
pub use bridge_range::*;
pub use bridge_typewalk::*;
pub use bytes::*;
pub use cfg::*;
pub use export::*;
pub use frame::*;
pub use function::*;
pub use hexrays::*;
pub use import::*;
pub use instruction::*;
pub use meta::*;
pub use name::*;
pub use reference::*;
pub use runtime::*;
pub use segment::*;
pub use strings::*;
pub use ty::*;
pub use ty_build::*;
