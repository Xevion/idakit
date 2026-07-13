//! Raw FFI bindings to IDA's idalib runtime and the idakit C++ facade.
//!
//! The declarations are split into per-domain source modules (`runtime`, `function`, `bytes`,
//! `bridge_visitors`, ...) that mirror the facade's translation units, but every item is re-exported
//! flat at the crate root, so the public surface is a single namespace
//! (`idakit_sys::idakit_get_bytes`, `idakit_sys::CtreeVisitor`), not a module hierarchy. There are
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
//! Opaque owned handles cross as cxx `UniquePtr<T>` (`CompiledBinpat`, `CFunc`, `TInfo`), freed by
//! cxx's deleter on drop. Any handle still passed as a raw `*mut c_void` is paired with an explicit
//! dispose call; using one after disposal is undefined behaviour.
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

mod bridge_cfg_check;
mod bridge_cfunc;
mod bridge_gen;
mod bridge_probe;
mod bridge_probe_ext;
mod bridge_qvec;
mod bridge_visitors;
mod bytes;
mod cfg_flags;
mod frame_flags;
mod function_flags;
mod instruction;
mod name;
mod runtime;
mod segment_flags;
mod strings;
mod ty_build;

#[doc(hidden)]
pub use bridge_cfg_check::*;
#[doc(hidden)]
pub use bridge_cfunc::*;
pub use bridge_gen::*;
#[doc(hidden)]
pub use bridge_probe::*;
#[doc(hidden)]
pub use bridge_probe_ext::*;
#[doc(hidden)]
pub use bridge_qvec::*;
pub use bridge_visitors::*;
pub use bytes::*;
pub use cfg_flags::*;
pub use frame_flags::*;
pub use function_flags::*;
pub use instruction::*;
pub use name::*;
pub use runtime::*;
pub use segment_flags::*;
pub use strings::*;
pub use ty_build::*;
