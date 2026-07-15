//! `cxx` fault-injection probes for the trap tests.
//!
//! A separate `#[cxx::bridge]` from the production bridges, kept off the public API by
//! `#[doc(hidden)]` on its re-export in `lib.rs`. Shares the `bridge` namespace with them, so
//! the generated shim symbols sit in the same family; the hand-written bodies and the `guarded<>`
//! entry live in `facade/testonly_probe.cpp`.

// cxx::bridge's own expansion mis-attributes a missing_errors_doc warning to this attribute's
// own span, though every Result-returning fn below already documents its `Err` condition.
#![expect(
    clippy::missing_errors_doc,
    reason = "false positive misattributed to the #[cxx::bridge] attribute by its own expansion"
)]

#[cxx::bridge(namespace = "bridge")]
mod ffi {
    unsafe extern "C++" {
        include!("testonly_probe.h");

        /// Throws the C++ exception selected by `kind` (`0` = `runtime_error`, `1` =
        /// `out_of_range`, `2` = a non-`std::exception`), so a test can observe how `cxx` surfaces
        /// (or fails to surface) each as a Rust `Err`.
        ///
        /// # Errors
        /// `Err` for every `kind` `cxx` can surface as one (a non-`std::exception` throw instead
        /// aborts the process).
        fn probe_throw(kind: i32) -> Result<String>;

        /// A trivial opaque C++ type whose destructor bumps a process-global counter, so a test
        /// can prove that dropping a [`UniquePtr`](cxx::UniquePtr) runs the C++ deleter (the same
        /// generated glue that backs `FlowChart` in the cfg bridge).
        type DropProbe;

        /// Allocate a [`DropProbe`] and hand ownership to Rust as a `UniquePtr`.
        #[must_use]
        fn drop_probe_make() -> UniquePtr<DropProbe>;
        /// How many [`DropProbe`] destructors have run in this process so far.
        #[must_use]
        fn drop_probe_count() -> u32;
    }
}

pub use ffi::{drop_probe_count, drop_probe_make, probe_throw};
