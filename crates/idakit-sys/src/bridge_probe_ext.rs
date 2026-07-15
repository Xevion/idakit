//! `cxx` spike bridge proving a custom `trycatch` widens the bridge's exception boundary
//! (`idakit_cxx::ext_*`).
//!
//! A hand-written `cxx_build` bridge (not the `cxx-gen` one, which inlines the `trycatch`
//! definition and complicates the override): a custom
//! [`rust::behavior::trycatch`](https://docs.rs/cxx) in `facade/testonly_probe_ext.h` makes this
//! bridge's shims catch more than cxx's stock `std::exception`. A non-`std::exception` throw
//! ([`ext_throw_plain_int`]) becomes an `Err` instead of a `std::terminate`, and an `interr_exc_t`
//! ([`ext_throw_interr`]) carries its code in the message rather than the base `what()`'s
//! uninformative `"std::exception"`.
//!
//! The C++ side (custom `trycatch`, probe bodies) is `facade/testonly_probe_ext.{h,cpp}`. Kept off the
//! public API by `#[doc(hidden)]` like [`bridge_probe`](crate::bridge_probe) and
//! [`bridge_cfunc`](crate::bridge_cfunc).

// cxx::bridge's own expansion mis-attributes a missing_errors_doc warning to this attribute's
// own span, though every Result-returning fn below already documents its `Err` condition.
#![expect(
    clippy::missing_errors_doc,
    reason = "false positive misattributed to the #[cxx::bridge] attribute by its own expansion"
)]

// The custom trycatch here is also productionized as the shared `facade/trycatch.h`, which
// every production bridge includes (plus a scoped `set_interr_throws` arm). This spike keeps its own
// inline copy so its throwing probes stay self-contained.
#[cxx::bridge(namespace = "idakit_cxx")]
mod ffi {
    unsafe extern "C++" {
        include!("testonly_probe_ext.h");

        /// Throw a non-`std::exception` (`throw 42`). With the custom `trycatch`'s `catch (...)`
        /// arm this returns `Err`; cxx's default would `std::terminate`. Never returns `Ok`.
        ///
        /// # Errors
        /// Always `Err`, carrying the custom `trycatch`'s message for a non-`std::exception` throw.
        fn ext_throw_plain_int() -> Result<String>;
        /// Throw an `interr_exc_t` carrying `code`; the custom `catch (const interr_exc_t&)` arm
        /// formats the code into the `Err` message. Never returns `Ok`.
        ///
        /// # Errors
        /// Always `Err`, its message formatted from `code`.
        fn ext_throw_interr(code: i32) -> Result<String>;
        /// Throw a `std::runtime_error` whose message encodes `code` (`idakit:qerrno=<code>`), so
        /// the Rust side can re-parse it. The string channel is the only one a `cxx::Exception`
        /// has. Never returns `Ok`.
        ///
        /// # Errors
        /// Always `Err`, its message encoding `code`.
        fn ext_throw_coded(code: i32) -> Result<String>;
    }
}

pub use ffi::{ext_throw_coded, ext_throw_interr, ext_throw_plain_int};
