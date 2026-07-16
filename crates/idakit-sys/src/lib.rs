//! <p align="center">
//!   <a href="https://github.com/Xevion/idakit/actions/workflows/ci.yml"><img src="https://github.com/Xevion/idakit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
//!   <a href="https://crates.io/crates/idakit-sys"><img src="https://img.shields.io/crates/v/idakit-sys.svg" alt="crates.io"></a>
//!   <a href="https://docs.rs/idakit-sys"><img src="https://img.shields.io/docsrs/idakit-sys" alt="docs.rs"></a>
//!   <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
//!   <img src="https://img.shields.io/badge/MSRV-1.88-blue.svg" alt="MSRV">
//! </p>
//!
//! Raw FFI bindings to IDA's idalib runtime and the idakit C++ facade.
//!
//! `idakit-sys` is the unsafe foundation under [`idakit`](https://docs.rs/idakit), which most users
//! want instead: it wraps these bindings in a safe, idiomatic API. Reach here directly only to call
//! a raw symbol the higher layer does not yet expose.
//!
//! # Surface
//!
//! The declarations are split into per-domain source modules (`runtime`, `bytes`, `function_flags`,
//! `instruction`, `bridge_visitors`, ...) that mirror the facade's translation units, but every item
//! is re-exported flat at the crate root, so the public surface is a single namespace
//! (`idakit_sys::guarded_open`, `idakit_sys::CtreeVisitor`), not a module hierarchy. Three kinds
//! of item live here:
//!
//! - **Raw C bindings**: `extern "C"` declarations of the facade's own functions (`guarded_open`,
//!   `get_bytes_into`, ...) sharing the flat namespace with the idalib/IDA symbols they sit beside
//!   (`open_database`, `set_name`), plus the `#[repr(C)]` structs and sentinel constants they
//!   exchange.
//! - **`cxx` bridges**: the spec-generated bridge (from the `idakit-sys-codegen` engine) and its
//!   hand-written companions, returning structured values, owning handles as `UniquePtr<T>`, or
//!   driving a walk through an opaque visitor ([`CtreeVisitor`], [`TypeWalkVisitor`]).
//! - **A typed flag layer**: the one deliberate exception to "raw declarations only". OR-able bit
//!   masks that also cross as FFI fields become `bitflags` types ([`SegPerm`], [`FlowFlags`],
//!   [`FrameVarFlags`], [`FlowChartFlags`], [`BinSearchFlags`]), and closed return-code sets become
//!   validated `num_enum` enums ([`SigWriteCode`], [`TypeApplyCode`]); both stay sound at the
//!   boundary and spare every caller a hand-rolled bit test. Safe idiomatic wrappers still belong in
//!   [`idakit`](https://docs.rs/idakit).
//!
//! # SDK-name aliases
//!
//! Every binding carries `#[doc(alias)]` tags for its IDA SDK spelling, so a rustdoc search on this
//! page resolves a name like `SEGPERM_READ`, `FC_NOEXT`, or `open_database` to the binding. Aliases
//! are per crate: search here for raw-binding and SDK names, and the
//! [`idakit`](https://docs.rs/idakit) page for the idiomatic wrappers.
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
//!
//! # License
//!
//! MIT. The IDA SDK and runtime are proprietary to Hex-Rays; these bindings link against your own
//! install and redistribute none of it.

/// IDA's effective address (`ea_t`), compiled `__EA64__`.
pub type Address = u64;
/// The invalid-address sentinel (`BADADDR`); every `Address`-returning facade call uses it for
/// "no address".
pub const BADADDR: Address = u64::MAX;

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
mod name_flags;
mod runtime;
mod segment_flags;
mod strings;
mod ty_build;

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
pub use name_flags::*;
pub use runtime::*;
pub use segment_flags::*;
pub use strings::*;
pub use ty_build::*;
