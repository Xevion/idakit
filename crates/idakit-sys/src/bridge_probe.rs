//! `cxx` fault-injection probes for the trap tests (`test-shims` only).
//!
//! A separate `#[cxx::bridge]` from the production [`bridge`](crate::bridge) so nothing here
//! reaches a normal build: the module is `mod`-gated in `lib.rs` and its C++ side is compiled
//! only when `build.rs` sees the feature. A per-function `#[cfg]` on the production bridge would
//! not do: `cxx-build`'s cfg evaluator matches feature names case-insensitively but not across
//! `-`/`_`, so it never sees the hyphenated `test-shims` and would drop the C++ shim, leaving the
//! symbol undefined at link. Gating the whole module sidesteps that.
//!
//! Shares the `idakit_cxx` namespace with the production bridge, so the generated shim symbols
//! sit in the same family; the hand-written bodies and the `guarded<>` entry live in
//! `facade/probe_cxx.cc`.

#[cxx::bridge(namespace = "idakit_cxx")]
mod ffi {
    unsafe extern "C++" {
        include!("probe_cxx.h");

        /// Its C++ body triggers a guarded fatal (`kind` = `IDAKIT_FATAL_*`), so a test can drive
        /// a `longjmp` across this `Result`-returning shim's `try/catch` landing-pad frame. Never
        /// returns on the `exit`/`abort` kinds.
        fn probe_fatal_through_cxx(kind: i32) -> Result<String>;

        /// Throws the C++ exception selected by `kind` (`0` = `runtime_error`, `1` =
        /// `out_of_range`, `2` = a non-`std::exception`), so a test can observe how `cxx` surfaces
        /// (or fails to surface) each as a Rust `Err`.
        fn probe_throw(kind: i32) -> Result<String>;

        /// A trivial opaque C++ type whose destructor bumps a process-global counter, so a test
        /// can prove that dropping a [`UniquePtr`](cxx::UniquePtr) runs the C++ deleter (the same
        /// generated glue that backs `FlowChart` in the cfg bridge).
        type DropProbe;

        /// Allocate a [`DropProbe`] and hand ownership to Rust as a `UniquePtr`.
        fn drop_probe_make() -> UniquePtr<DropProbe>;
        /// How many [`DropProbe`] destructors have run in this process so far.
        fn drop_probe_count() -> u32;
    }
}

pub use ffi::{drop_probe_count, drop_probe_make, probe_fatal_through_cxx, probe_throw};
