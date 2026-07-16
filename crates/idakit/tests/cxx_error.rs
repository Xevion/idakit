//! Turning a `cxx::Exception` into a structured `idakit` snafu error.
//!
//! `cxx`'s `Result<T>` gives back a `cxx::Exception` whose only datum is `what()`, a flat string,
//! the C++ `std::exception::what()`. That alone does not match idakit's house style, where an
//! [`Error`] variant is struct-style and carries context (`op`, `address`, `qerrno`, `reason`).
//! These tests exercise a real `cxx::Exception` (from the `probe_throw` shim, which needs no
//! kernel) and show the two conversion strategies the spike weighed:
//!
//!   * fold `what()` in as the `reason` of a structured variant (shown here, since it runs without
//!     a database), and
//!   * the recommended production path: treat the C++ `throw` as a bare failure *signal* and
//!     re-derive `qerrno` + `reason` on the Rust side from `Database::last_reason()`, exactly as
//!     the raw facade path already does. The C++ body then needs no message at all.
//!
//! `probe_throw`'s third kind (a bare `throw 42`, not a `std::exception`) escapes `cxx`'s
//! `catch (std::exception const&)` shim and calls `std::terminate()`: a real, documented
//! containment gap in `cxx` itself, not exercised here since provoking it would abort this test
//! process along with every other test sharing it.

use assert2::assert;
use idakit::error::{Error, Qerrno};
use idakit_sys as sys;

/// Illustrative conversion: the message from a `cxx::Exception` (a segment-index read that threw),
/// mapped to a structured variant carrying the offending index and the C++ message. The variant
/// here is only a stand-in (idakit has no segment-by-index error today); the point is the *shape*,
/// a flat `what()` becoming a struct-style snafu error with call-site context. In a real kernel
/// path `qerrno` and `reason` would come from `Database::last_reason()` rather than from `what()`.
fn to_structured(op: &'static str, index: i32, what: &str) -> Error {
    Error::WriteRejected {
        op,
        address: index as u64,
        qerrno: Qerrno::Ok,
        reason: Some(what.to_owned()),
    }
}

/// Every field the conversion is supposed to carry, checked directly rather than through a
/// stringified message: `op` and `address` come from the call site, `reason` from the caught
/// exception's `what()`, and `qerrno` is the stand-in's fixed `Ok` (a real kernel path would
/// re-derive it from `Database::last_reason()` instead).
#[test]
fn cxx_exception_becomes_structured_error() {
    // A real cxx::Exception, caught from the throwing probe body (no kernel needed).
    let err = sys::probe_throw(0).unwrap_err();
    assert!(err.what() == "probe_throw: runtime_error from C++");

    let structured = to_structured("seg_class", 7, err.what());
    assert!(
        structured
            == Error::WriteRejected {
                op: "seg_class",
                address: 7,
                qerrno: Qerrno::Ok,
                reason: Some("probe_throw: runtime_error from C++".to_owned()),
            }
    );
    // Display composes the same fields; checked as a secondary, not a replacement for the above.
    assert!(
        structured.to_string() == "seg_class failed at 0x7: probe_throw: runtime_error from C++"
    );
}

/// The limitation, made explicit: everything `cxx` hands back for a caught exception is the one
/// `what()` string. There is no `qerrno`, index, or typed reason to read off the `Exception`
/// itself; any structure has to be supplied by the Rust call site (context, as
/// [`cxx_exception_becomes_structured_error`] shows) or re-derived from the kernel
/// (`last_reason()`).
#[test]
fn cxx_exception_is_a_flat_string_only() {
    let err = sys::probe_throw(1).unwrap_err();
    assert!(err.what() == "probe_throw: out_of_range from C++");
}

/// A `kind` that matches none of the throwing arms is the containment baseline: the bridge call
/// returns `Ok` with no exception involved at all, not merely "didn't crash".
#[test]
fn probe_throw_returns_ok_for_an_unrecognized_kind() {
    let ok = sys::probe_throw(99).unwrap();
    assert!(ok == "probe_throw: no throw");
}
