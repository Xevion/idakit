//! `cxx` fault-injection probes for the trap tests.
//!
//! A separate `#[cxx::bridge]` from the production bridges, kept off the public API by
//! `#[doc(hidden)]` on its re-export in `lib.rs`. Shares the `idakit_cxx` namespace with them, so
//! the generated shim symbols sit in the same family; the hand-written bodies and the `guarded<>`
//! entry live in `facade/testonly_probe.cpp`.

// cxx::bridge's own expansion mis-attributes a missing_errors_doc warning to this attribute's
// own span, though every Result-returning fn below already documents its `Err` condition.
#![expect(
    clippy::missing_errors_doc,
    reason = "false positive misattributed to the #[cxx::bridge] attribute by its own expansion"
)]

#[cxx::bridge(namespace = "idakit_cxx")]
mod ffi {
    unsafe extern "C++" {
        include!("testonly_probe.h");

        /// Its C++ body triggers a guarded fatal (`kind` = `crate::FATAL_*`), so a test can drive
        /// a `longjmp` across this `Result`-returning shim's `try/catch` landing-pad frame. Never
        /// returns on the `exit`/`abort` kinds.
        ///
        /// # Errors
        /// `Err` when the trap catches an `interr` (a `std::exception`) instead of longjmp-ing.
        // Never called from Rust: `facade/testonly_probe.cpp`'s test_fatal_through_cxx reaches the
        // cxx-generated shim by its mangled symbol directly, bypassing this binding. The
        // declaration must still exist so cxx generates that shim in the first place. cxx's
        // foreign-block attribute parser only recognizes allow/warn/deny/forbid (not expect), so
        // this stays a plain allow.
        #[allow(dead_code)]
        fn probe_fatal_through_cxx(kind: i32) -> Result<String>;

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
