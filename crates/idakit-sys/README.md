<!-- cargo-rdme start -->

<p align="center">
  <a href="https://github.com/Xevion/idakit/actions/workflows/ci.yml"><img src="https://github.com/Xevion/idakit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/idakit-sys"><img src="https://img.shields.io/crates/v/idakit-sys.svg" alt="crates.io"></a>
  <a href="https://docs.rs/idakit-sys"><img src="https://img.shields.io/docsrs/idakit-sys" alt="docs.rs"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-blue.svg" alt="MSRV">
</p>

Raw FFI bindings to IDA's idalib runtime and the idakit C++ facade.

`idakit-sys` is the unsafe foundation under [`idakit`](https://docs.rs/idakit), which most users
want instead: it wraps these bindings in a safe, idiomatic API. Reach here directly only to call
a raw symbol the higher layer does not yet expose.

## Surface

The declarations are split into per-domain source modules (`runtime`, `bytes`, `function_flags`,
`instruction`, `bridge_visitors`, ...) that mirror the facade's translation units, but every item
is re-exported flat at the crate root, so the public surface is a single namespace
(`idakit_sys::guarded_open`, `idakit_sys::CtreeVisitor`), not a module hierarchy. Three kinds
of item live here:

- **Raw C bindings**: `extern "C"` declarations of the facade's own functions (`guarded_open`,
  `get_bytes_into`, ...) sharing the flat namespace with the idalib/IDA symbols they sit beside
  (`open_database`, `set_name`), plus the `#[repr(C)]` structs and sentinel constants they
  exchange.
- **`cxx` bridges**: the spec-generated bridge (from the `idakit-sys-codegen` engine) and its
  hand-written companions, returning structured values, owning handles as `UniquePtr<T>`, or
  driving a walk through an opaque visitor ([`CtreeVisitor`](https://docs.rs/idakit-sys/latest/idakit_sys/bridge_visitors/struct.CtreeVisitor.html), [`TypeWalkVisitor`](https://docs.rs/idakit-sys/latest/idakit_sys/bridge_visitors/struct.TypeWalkVisitor.html)).
- **A typed flag layer**: the one deliberate exception to "raw declarations only". OR-able bit
  masks that also cross as FFI fields become `bitflags` types ([`SegPerm`](https://docs.rs/idakit-sys/latest/idakit_sys/segment_flags/struct.SegPerm.html), [`FlowFlags`](https://docs.rs/idakit-sys/latest/idakit_sys/instruction/struct.FlowFlags.html),
  [`FrameVarFlags`](https://docs.rs/idakit-sys/latest/idakit_sys/frame_flags/struct.FrameVarFlags.html), [`FlowChartFlags`](https://docs.rs/idakit-sys/latest/idakit_sys/cfg_flags/struct.FlowChartFlags.html), [`BinSearchFlags`](https://docs.rs/idakit-sys/latest/idakit_sys/bytes/struct.BinSearchFlags.html)), and closed return-code sets become
  validated `num_enum` enums ([`SigWriteCode`](https://docs.rs/idakit-sys/latest/idakit_sys/ty_build/enum.SigWriteCode.html), [`TypeApplyCode`](https://docs.rs/idakit-sys/latest/idakit_sys/ty_build/enum.TypeApplyCode.html)); both stay sound at the
  boundary and spare every caller a hand-rolled bit test. Safe idiomatic wrappers still belong in
  [`idakit`](https://docs.rs/idakit).

## SDK-name aliases

Every binding carries `#[doc(alias)]` tags for its IDA SDK spelling, so a rustdoc search
resolves a name like `SEGPERM_READ`, `FC_NOEXT`, or `open_database` to the binding. Aliases
are per crate: `idakit_sys` carries the raw-binding and SDK names, [`idakit`](https://docs.rs/idakit)
carries the idiomatic wrappers.

## Buffer conventions

Functions that accept `(*mut c_char, cap: usize)` copy the value into the
caller-supplied buffer and NUL-terminate within `cap` bytes. The return value
is the full source length, which may exceed `cap` when the output was
truncated. A negative return value means the query failed (missing symbol,
null handle, etc.).

## Owned handles

Opaque owned handles cross as cxx `UniquePtr<T>` (`CompiledBinpat`, `CFunc`, `TInfo`), freed by
cxx's deleter on drop. Any handle still passed as a raw `*mut c_void` is paired with an explicit
dispose call; using one after disposal is undefined behaviour.

## License

MIT. The IDA SDK and runtime are proprietary to Hex-Rays; these bindings link against your own
install and redistribute none of it.

<!-- cargo-rdme end -->
