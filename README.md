# idakit

Idiomatic Rust bindings for IDA Pro's `idalib` (9.x).

> **Status:** work in progress, pre-1.0. The API will change.

`idakit` wraps the IDA Pro kernel so you can drive analysis from safe Rust. It is two
crates:

- **`idakit-sys`** -- the raw FFI: a small C++ facade (`facade/idakit_facade.{cpp,h}`)
  over the C++ SDK exposed as a clean C ABI, plus direct `extern "C"` bindings to the
  symbols `libida.so` / `libidalib.so` already export unmangled.
- **`idakit`** -- the idiomatic layer: `Ida::here` brings the kernel up on the current
  thread for direct, closure-free use; `Ida::run` + `Ida::call` instead host it on a
  dedicated thread for GUI/async/multi-threaded callers. `Idb` (the open database) is
  `!Send`, so it stays on the thread that owns the kernel.

## The model

The IDA kernel is single-threaded and thread-affine -- it must be driven from the one
thread that initialized it. The open database `Idb` is `!Send + !Sync`: reads borrow
`&Idb` and return lightweight views (`Func`, `Segment`, ...), writes take `&mut Idb`, so the
borrow checker keeps a read view from outliving a mutation.

If your program owns its thread -- a script, a test, a CLI -- `Ida::here` brings the kernel
up on the current thread and hands back the database directly. No kernel thread, no
closures:

```rust
let mut idb = idakit::Ida::here()?;
idb.open("/path/to/db.i64").call()?;
for func in idb.functions() {
    println!("{:#x} {}", func.ea().get(), func.name().unwrap_or_default());
}
idb.close(false);
```

When the current thread must stay free (a GUI event loop, an async runtime) or many
threads must drive the kernel, `Ida::run` spawns a dedicated kernel thread and runs your
app on the calling thread; any thread marshals work onto the kernel with `Ida::call`:

```rust
use idakit::{Ida, Idb};

Ida::run(|ida| {
    ida.call(|idb: &mut Idb| -> idakit::Result<()> {
        idb.open("/path/to/db.i64").call()?;
        for func in idb.functions() {
            println!("{:#x} {}", func.ea().get(), func.name().unwrap_or_default());
        }
        idb.close(false);
        Ok(())
    })?
})??;
```

The kernel is a process global, so the two are mutually exclusive: one `Idb` may be live
at a time (a second `here`/`run` returns `InitError::AlreadyRunning` until the first is
dropped).

## Building

You bring your own licensed IDA install -- `idakit` links it, it is never shipped here.

- **`IDADIR`** -- your IDA install directory, holding `libida.so` (defaults to
  `~/ida-pro-9.3`).
- **SDK headers** -- the build compiles the facade against the public IDA SDK headers
  ([`HexRaysSA/ida-sdk`](https://github.com/HexRaysSA/ida-sdk)). It detects your installed
  IDA version and fetches the matching release tag into a cache (`git` required). No flags
  needed; the headers always match the runtime you link against.
- **`IDA_SDK_DIR`** *(optional)* -- point at a local SDK checkout to skip the fetch
  (offline builds, CI). **`IDA_SDK_CACHE_DIR`** *(optional)* -- redirect the fetch cache.

Databases must be 64-bit `.i64` -- the facade is compiled `__EA64__`.

The minimum supported Rust version is **1.88**.

## License

MIT (the bindings). The IDA SDK and runtime are proprietary to Hex-Rays and are not
included or redistributed; the build fetches public SDK headers from the upstream repo at
your request.
