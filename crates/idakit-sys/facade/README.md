# idakit-sys facade

A hand-written C++ facade over the IDA SDK, compiled by `build.rs` and bound by the
`idakit-sys` Rust crate. It gives `idakit-sys` a clean surface to declare bindings against
instead of the SDK's own C++ types and macros.

Half of each domain is generated: `idakit-sys-codegen` reads a declarative spec and emits, into
`OUT_DIR`, the `#[cxx::bridge]` Rust module, the cxx shim glue, and templated C++ bridge bodies.
This directory holds the other half: the hand-written bodies those generated bridges call into,
plus the bridges that are entirely hand-written because no spec fits them.

## Layout

- **Lifecycle and the fatal-exit trap** (`runtime.cpp`): `init_headless`, `guarded_open`/
  `guarded_auto_wait`/`guarded_close`, and the ELF-GOT rewrite that turns a kernel `exit()`/
  `abort()` into a caught error instead of a dead process. `internal.h` holds the shared
  `guarded<>` wrapper and trap state; only `runtime.cpp` and `hexrays.cpp` need it.
- **C ABI and shared headers**: `abi.h` (the plain `extern "C"` declarations `idakit-sys` binds
  by hand), `internal.h`, `trycatch.h` (the `rust::behavior::trycatch` override every production
  bridge routes through), `type_walker.h` (the opaque tinfo-walker handle shared by the ctree
  and type-write bridges).
- **Per-domain bodies**, namespace `gen`: one `<domain>.cpp` per generated bridge, mirroring the
  matching `src/<domain>.rs` in the idakit crate (`bytes.cpp`, `name.cpp`, `function.cpp`,
  `instruction.cpp`, `import.cpp`, `export.cpp`, `meta.cpp`, `range.cpp`, `reference.cpp`,
  `strings.cpp`, `netnode.cpp`, `local_types.cpp`, `cfg.cpp`, `hexrays.cpp`). The type-write
  domain is large enough to split across several files sharing one namespace: `type_apply.cpp`,
  `type_define.cpp`, `udt_edit.cpp`, `enum_edit.cpp`, `func_sig.cpp`, `tinfo_build.cpp`, with
  common helpers factored into `type_write_common.h`/`.cpp`.
- **cxx bridges**, namespace `bridge` (`*_bridge.cpp`/`.h`): hand-written bridges with no
  generated counterpart, such as `ctree_bridge.cpp` (the ctree walk) and `typewalk_bridge.cpp`
  (the tinfo walker `type_walker.h` declares). `cfunc_shims.cpp`/`.h` are a different thing: raw
  placement shims backing moveit's construction traits over `cfuncptr_t`, not a cxx bridge.
- **Test-only fault injection**: `testonly_probe.cpp`/`.h` and `testonly_probe_ext.cpp`/`.h`
  probe the trap and the cxx error-mapping boundary. Their Rust bindings are `#[doc(hidden)]`
  and compiled unconditionally, but never used outside the test suite.

## Naming

- `<domain>.cpp` maps to the matching Rust module in the idakit crate.
- `_bridge` names a cxx bridge (`ctree_bridge`, `typewalk_bridge`, `qvec_bridge`).
- `_shims` names raw placement shims, not a cxx bridge (`cfunc_shims`).
- `testonly_` marks a file that exists only for the test suite.

## Include order

Within a translation unit: `pro.h`, then `ida.hpp`, then the SDK domain headers the body
actually needs, then std headers, then the generated `gen_*.h` headers last. Keep each block
sorted internally so a diff shows only the header that changed.

## Error channel

The `gen::` bodies signal failure by throwing: `std::runtime_error` or `std::out_of_range`,
which cxx catches at the bridge boundary (via `trycatch.h`) and turns into a Rust `Err`. A body
with no failure mode just returns its value directly; there is no separate error-code
out-parameter to thread through.

Two facade C symbols would collide with a name `libida`/`libidalib` already exports, so they
keep an `idakit_`-prefixed name on the C side only; the Rust binding stays clean via
`#[link_name]`: `get_bytes_into` binds `idakit_get_bytes`, `reg_read_int` binds
`idakit_reg_read_int`. Every other facade symbol is unprefixed.
