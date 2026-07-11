//! Question B (the spike): turning a `cxx::Exception` into a structured `idakit` snafu error.
//!
//! `cxx`'s `Result<T>` gives back a `cxx::Exception` whose only datum is `what()` -- a flat string,
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

use idakit::error::{Error, Qerrno};
use idakit_sys as sys;

/// Illustrative conversion: the message from a `cxx::Exception` (a segment-index read that threw),
/// mapped to a structured variant carrying the offending index and the C++ message. The variant
/// here is only a stand-in (idakit has no segment-by-index error today); the point is the *shape*
/// -- a flat `what()` becoming a struct-style snafu error with call-site context. In a real kernel
/// path `qerrno` and `reason` would come from `Database::last_reason()` rather than from `what()`.
fn to_structured(op: &'static str, index: i32, what: &str) -> Error {
    Error::WriteRejected {
        op,
        address: index as u64,
        qerrno: Qerrno::Ok,
        reason: Some(what.to_owned()),
    }
}

#[test]
fn cxx_exception_becomes_structured_error() {
    // A real cxx::Exception, caught from the throwing probe body (no kernel needed).
    let err = sys::probe_throw(0).unwrap_err();
    assert_eq!(err.what(), "probe_throw: runtime_error from C++");

    let structured = to_structured("seg_class", 7, err.what());
    // The context survives into the structured variant and renders through Display.
    assert!(matches!(
        structured,
        Error::WriteRejected {
            op: "seg_class",
            address: 7,
            ..
        }
    ));
    assert_eq!(
        structured.to_string(),
        "seg_class failed at 0x7: probe_throw: runtime_error from C++"
    );
}

#[test]
fn cxx_exception_is_a_flat_string_only() {
    // The limitation, made explicit: everything cxx hands back is the one what() string. There is
    // no qerrno, index, or typed reason to read off the Exception itself -- any structure has to be
    // supplied by the Rust call site (context) or re-derived from the kernel (last_reason()).
    let err = sys::probe_throw(1).unwrap_err();
    assert!(err.what().contains("out_of_range"));
}
