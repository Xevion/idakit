//! Shared assertion macros for the kernel-touching integration tests.

/// Asserts `result` is `Err(Error::TypeWrite { source: <pattern> })`, the shape most
/// `TypeWriteError` rejections take.
macro_rules! assert_type_write_err {
    ($result:expr, $pattern:pat) => {
        assert2::assert!(let Err(idakit::error::Error::TypeWrite { source: $pattern }) = $result)
    };
}
pub(crate) use assert_type_write_err;
