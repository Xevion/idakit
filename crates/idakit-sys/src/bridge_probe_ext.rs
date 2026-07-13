//! `cxx` spike bridge proving three findings about the bridge boundary (`idakit_cxx::ext_*`).
//!
//! A hand-written `cxx_build` bridge (not the `cxx-gen` one, which inlines the `trycatch`
//! definition and complicates the override) carrying three probes:
//!
//! - A custom [`rust::behavior::trycatch`](https://docs.rs/cxx) in `facade/probe_ext_cxx.h`
//!   makes this bridge's shims catch more than cxx's stock `std::exception`: a non-`std::exception`
//!   throw ([`ext_throw_plain_int`]) becomes an `Err` instead of a `std::terminate`, and an
//!   `interr_exc_t` ([`ext_throw_interr`]) carries its code in the message rather than the base
//!   `what()`'s uninformative `"std::exception"`.
//! - [`AddrCursor::advance`] / [`AddrCursor::seek`] take `self: Pin<&mut AddrCursor>` and bind to
//!   the **non-const** C++ members, mutating state that [`AddrCursor::pos`] (a `&self` const
//!   member) reads back. The real-database writes [`ext_set_name`] / [`ext_set_cmt`] cross the
//!   same boundary into implicit-current-DB libida calls.
//! - [`WriteOutcome`] is a cxx **shared enum**, returned by value from [`ext_classify`]; cxx emits
//!   its own C++ enum and (because the type can hold any `repr`) a Rust match over it needs a
//!   wildcard arm.
//!
//! The C++ side (custom `trycatch`, cursor, bodies) is `facade/probe_ext_cxx.{h,cc}`. Kept off the
//! public API by `#[doc(hidden)]` like [`bridge_probe`](crate::bridge_probe) and
//! [`bridge_cfunc`](crate::bridge_cfunc).

// cxx::bridge's own expansion mis-attributes a missing_errors_doc warning to this attribute's
// own span, though every Result-returning fn below already documents its `Err` condition.
#![expect(
    clippy::missing_errors_doc,
    reason = "false positive misattributed to the #[cxx::bridge] attribute by its own expansion"
)]

// The custom trycatch here is also productionized as the shared `facade/idakit_trycatch.h`, which
// every production bridge includes (plus a scoped `set_interr_throws` arm). This spike keeps its own
// inline copy so its throwing probes stay self-contained.
#[cxx::bridge(namespace = "idakit_cxx")]
mod ffi {
    /// How a database write turned out, a cxx **shared enum** generated into both languages.
    ///
    /// cxx emits its own C++ `enum class` here rather than binding an existing SDK enum, and the
    /// generated Rust type can hold any `i32`, so a `match` over it must carry a wildcard arm.
    #[repr(i32)]
    enum WriteOutcome {
        /// The write landed.
        Applied,
        /// The kernel rejected the write.
        Rejected,
        /// The value already matched; nothing changed.
        NoChange,
    }

    unsafe extern "C++" {
        include!("probe_ext_cxx.h");

        /// A mutable-address cursor, a cxx opaque type owned behind [`UniquePtr`](cxx::UniquePtr).
        ///
        /// The mutating members take `self: Pin<&mut AddrCursor>` (mapping to non-const C++
        /// members); [`pos`](Self::pos) reads back through `&self`.
        type AddrCursor;

        /// Build a cursor positioned at `init`, owned by a [`UniquePtr`](cxx::UniquePtr).
        #[must_use]
        fn make_addr_cursor(init: u64) -> UniquePtr<AddrCursor>;
        /// The cursor's current address (const member, `&self` receiver).
        fn pos(self: &AddrCursor) -> u64;
        /// Advance the cursor by `delta` (non-const member, `Pin<&mut Self>` receiver).
        fn advance(self: Pin<&mut AddrCursor>, delta: u64);
        /// Move the cursor to `value` (non-const member, `Pin<&mut Self>` receiver).
        fn seek(self: Pin<&mut AddrCursor>, value: u64);

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

        /// Rename the item at `ea` via libida `set_name`; `Err` (a bare failure signal) on
        /// rejection. Implicit-current-DB, so it needs an open database.
        ///
        /// # Errors
        /// `Err` when libida's `set_name` rejects the rename.
        fn ext_set_name(ea: u64, name: &str) -> Result<()>;
        /// Set the comment at `ea` via libida `set_cmt`; `Err` on rejection. Implicit-current-DB.
        ///
        /// # Errors
        /// `Err` when libida's `set_cmt` rejects the write.
        fn ext_set_cmt(ea: u64, comment: &str, repeatable: bool) -> Result<()>;

        /// Map a small integer code to a [`WriteOutcome`], returned by value across the bridge
        /// (`0` = `Applied`, `1` = `Rejected`, else `NoChange`); the shared-enum mechanics probe.
        #[must_use]
        fn ext_classify(code: i32) -> WriteOutcome;
    }
}

pub use ffi::{
    AddrCursor, WriteOutcome, ext_classify, ext_set_cmt, ext_set_name, ext_throw_coded,
    ext_throw_interr, ext_throw_plain_int, make_addr_cursor,
};
