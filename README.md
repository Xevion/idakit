<!-- cargo-rdme start -->

<p align="center">
  <img src="https://raw.githubusercontent.com/Xevion/idakit/master/assets/idakit-banner.png" alt="idakit" width="820">
</p>

<p align="center">
  <a href="https://github.com/Xevion/idakit/actions/workflows/ci.yml"><img src="https://github.com/Xevion/idakit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/idakit"><img src="https://img.shields.io/crates/v/idakit.svg" alt="crates.io"></a>
  <a href="https://docs.rs/idakit"><img src="https://img.shields.io/docsrs/idakit" alt="docs.rs"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-blue.svg" alt="MSRV">
</p>

Access, extend, and automate IDA through a first-class Rust API.

`idakit` drives IDA's analysis kernel from safe Rust:

```rust
const SINKS: &[&str] = &["strcpy", "system", "memcpy", "sprintf"];

for function in db.functions().take(300) {
    // Decompile to a C syntax tree; skip anything that won't decompile.
    let Some(tree) = function.decompile().ok().and_then(|d| d.ctree().ok()) else { continue };

    for (_, callee, _) in tree.calls() {
        // Resolve the call target to a name, then match it against the list.
        let Some((_, Some(name))) = tree.kind(callee).as_obj() else { continue };
        if SINKS.iter().any(|s| name.contains(s)) {
            println!("{} calls {name}", function.name());
        }
    }
}
```

## Core types

- [`Ida`](https://docs.rs/idakit/latest/idakit/kernel/struct.Ida.html): brings the kernel up and marshals work onto its thread.
- [`Database`](https://docs.rs/idakit/latest/idakit/struct.Database.html): the open database, and the root of every read and write.
- [`Function`](https://docs.rs/idakit/latest/idakit/function/struct.Function.html): a function's name, bytes, chunks, instructions, and decompilation.
- [`Segment`](https://docs.rs/idakit/latest/idakit/segment/struct.Segment.html): a segment's range, permissions, and class.
- [`Type`](https://docs.rs/idakit/latest/idakit/types/resolved/struct.Type.html): an owned type snapshot, comparable across databases via [`types::diff`](https://docs.rs/idakit/latest/idakit/types/diff/).
- [`Ctree`](https://docs.rs/idakit/latest/idakit/decompiler/ctree/tree/struct.Ctree.html): a decompiled function's syntax tree, walkable off the kernel thread.
- [`Xref`](https://docs.rs/idakit/latest/idakit/xref/struct.Xref.html): a cross-reference edge between two addresses.

## Usage

IDA's kernel initializes once per process and runs on a single thread. The example above
used [`Ida::here`](https://docs.rs/idakit/latest/idakit/kernel/struct.Ida.html#method.here), which initializes it on the current thread and hands
the database back directly, a good fit for a tool or test that owns its thread.

When the current thread must stay free, such as a GUI event loop or an async runtime,
[`Ida::run`](https://docs.rs/idakit/latest/idakit/kernel/struct.Ida.html#method.run) hosts the kernel on its own dedicated thread instead. It hands
your closure an [`Ida`](https://docs.rs/idakit/latest/idakit/kernel/struct.Ida.html) handle whose [`Ida::call`](https://docs.rs/idakit/latest/idakit/kernel/struct.Ida.html#method.call) marshals work onto the
kernel from any thread:

```rust
use idakit::prelude::*;

Ida::run(|ida| {
    ida.call(|db: &mut Database| -> Result<()> {
        db.open("path/to/database.i64").call()?;
        for function in db.functions() {
            println!("{:#x} {}", function.address().get(), function.name());
        }
        db.close(false);
        Ok(())
    })?
})??;
```

The open database stays on the kernel thread ([`Database`](https://docs.rs/idakit/latest/idakit/struct.Database.html) is `!Send`). Reads borrow it and
return lightweight views like [`Function`](https://docs.rs/idakit/latest/idakit/function/struct.Function.html) and [`Segment`](https://docs.rs/idakit/latest/idakit/segment/struct.Segment.html); writes take it by mutable
reference, so a read can't outlive a mutation.

Only one database is live at a time. [`Ida::here`](https://docs.rs/idakit/latest/idakit/kernel/struct.Ida.html#method.here) and
[`Ida::run`](https://docs.rs/idakit/latest/idakit/kernel/struct.Ida.html#method.run) return [`InitError::AlreadyRunning`](https://docs.rs/idakit/latest/idakit/error/enum.InitError.html#variant.AlreadyRunning)
while one is already open; drop it and you can start another.

For lower-level control, [`idakit_sys`](https://docs.rs/idakit_sys/latest/idakit_sys/) exposes IDA's raw C bindings directly.

Both crates carry `#[doc(alias)]` tags mapping items to their IDA SDK names, so a rustdoc search
resolves an SDK spelling like `SEGPERM_READ` or `netnode::altval` to the binding. Aliases are
per crate: search the [`idakit_sys`](https://docs.rs/idakit_sys/latest/idakit_sys/) page for raw-binding names and this page for the
idiomatic wrappers.

## Conventions

A handful of shapes recur across every domain:

- A **borrowed view** ([`Function`](https://docs.rs/idakit/latest/idakit/function/struct.Function.html), [`Segment`](https://docs.rs/idakit/latest/idakit/segment/struct.Segment.html)) is a cheap `Copy` handle that borrows the
  [`Database`](https://docs.rs/idakit/latest/idakit/struct.Database.html) and re-queries the kernel per accessor.
- A **lazy iterator** ([`Segments`](https://docs.rs/idakit/latest/idakit/segment/struct.Segments.html), [`function::Functions`](https://docs.rs/idakit/latest/idakit/function/struct.Functions.html)) walks a domain without collecting.
- An **owned snapshot** ([`Type`](https://docs.rs/idakit/latest/idakit/types/resolved/struct.Type.html), [`StackFrame`](https://docs.rs/idakit/latest/idakit/stack/struct.StackFrame.html), [`Ctree`](https://docs.rs/idakit/latest/idakit/decompiler/ctree/tree/struct.Ctree.html)) is a `Send` value detached from
  the kernel and analyzable on any thread; a `Snapshot` suffix
  ([`function::FunctionSnapshot`](https://docs.rs/idakit/latest/idakit/function/struct.FunctionSnapshot.html)) marks one taken from a view.
- A **kernel-handle owner** ([`Pattern`](https://docs.rs/idakit/latest/idakit/search/struct.Pattern.html), [`decompiler::DecompiledFunction`](https://docs.rs/idakit/latest/idakit/decompiler/struct.DecompiledFunction.html)) holds an IDA
  resource it frees on [`Drop`](https://doc.rust-lang.org/stable/core/ops/drop/trait.Drop.html), so it stays `!Send` on the kernel thread.

## Requirements

- IDA Pro 9.3. A local install is needed to build, since idakit links its libraries, and a
  valid license to run, since IDA checks it when the kernel initializes.
- A 64-bit host running Linux, macOS, or Windows.
- Rust 1.88 or newer.
- A C++17 compiler for the build: g++ or Clang on Linux and macOS, MSVC on Windows.
- `git`, to fetch the SDK headers that match your install, unless you supply a local SDK
  checkout with `IDA_SDK_DIR`.
- 64-bit databases. idakit works with `.i64` and can't open a 32-bit `.idb`.
  - You don't have to bring one, though: it can analyze a binary from scratch.
  - A 32-bit binary is fine, since the limitation is the database format, not the target.

## Building

idakit locates your IDA install automatically, in order:

1. `IDADIR`, if set.
2. `idat64` on your `PATH`.
3. The platform's default install locations: `~/ida-pro-*` and `/opt/` on Linux,
   `/Applications/` on macOS, `Program Files` on Windows.

If none match, set `IDADIR` to the directory holding IDA's runtime library.

The SDK headers are fetched to match your installed IDA version, so a normal build needs no
extra flags. Two variables override that:

- `IDA_SDK_DIR` builds against a local SDK checkout instead of fetching.
- `IDA_SDK_CACHE_DIR` relocates the fetch cache.

Databases must be 64-bit `.i64`, since the facade is compiled `__EA64__`.

## License

The bindings are MIT licensed. The IDA SDK and runtime are proprietary to Hex-Rays; idakit
links against your own install and redistributes none of it.

<!-- cargo-rdme end -->
