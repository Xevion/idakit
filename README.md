<p align="center">
  <img src="https://raw.githubusercontent.com/Xevion/idakit/master/assets/idakit-banner.png" alt="idakit" width="820">
</p>

<p align="center">
  <a href="https://github.com/Xevion/idakit/actions/workflows/ci.yml"><img src="https://github.com/Xevion/idakit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-blue.svg" alt="MSRV">
</p>

Access, extend, and automate IDA through a first-class Rust API.

idakit drives IDA's analysis engine from safe Rust:

```rust
use idakit::prelude::*;

// Open a database and flag every call into a risky C API.
let mut db = Ida::here()?;
db.open("path/to/database.i64").call()?;

const SINKS: &[&str] = &["strcpy", "system", "memcpy", "sprintf"];

for function in db.functions() {
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

db.close(false);
```

## Usage

IDA's engine initializes once per process and runs on a single thread. The example above
used `Ida::here`, which initializes it on the current thread and hands the database back
directly, a good fit for a tool or test that owns its thread.

When the current thread must stay free, such as a GUI event loop or an async runtime,
`Ida::run` hosts the engine on its own dedicated thread instead. It hands your closure an
`Ida` handle whose `Ida::call` marshals work onto the engine from any thread:

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

The open database stays on the engine's thread (it is `!Send`). Reads borrow it and return
lightweight views like `Function` and `Segment`; writes take it by mutable reference, so a
read can't outlive a mutation.

Only one database is live at a time. `Ida::here` and `Ida::run` return
`InitError::AlreadyRunning` while one is already open; drop it and you can start another.

For lower-level control, `idakit-sys` exposes IDA's raw C bindings directly.

## Requirements

- IDA Pro 9.3. A local install is needed to build, since idakit links its libraries, and a
  valid license to run, since IDA checks it when the engine initializes.
- A 64-bit host running Linux, macOS, or Windows.
- Rust 1.88 or newer.
- A C++17 compiler for the build: g++ or Clang on Linux and macOS, MSVC on Windows.
- `git`, to fetch the SDK headers that match your install, unless you supply a local SDK
  checkout with `IDA_SDK_DIR`.
- 64-bit databases. idakit works with `.i64` and can't open a 32-bit `.idb`.
  - You don't have to bring one, though: it can analyze a binary from scratch
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

## License

The bindings are MIT licensed. The IDA SDK and runtime are proprietary to Hex-Rays; idakit
links against your own install and redistributes none of it.
