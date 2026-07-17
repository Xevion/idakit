//! [`NetnodeBytes`], the validated byte domain shared by every netnode value/supval/hash write.
//!
//! The SDK's `set`/`supset`/`hashset` read a `length` of `0` as "measure the value with
//! `strlen`", which would walk an empty slice's dangling pointer, and silently truncate past
//! `MAXSPECSIZE` rather than reject the write. Building a [`NetnodeBytes`] is the one place that
//! `1..=MAXSPECSIZE` domain is checked, and every setter takes `impl TryInto<NetnodeBytes<'_>>`,
//! so neither case reaches the facade.

use std::convert::Infallible;

use snafu::Snafu;

/// A byte slice validated against the SDK's `1..=MAXSPECSIZE` object-size domain.
///
/// Accepted by every netnode byte setter, on both [`NetnodeMut`](super::NetnodeMut) and its
/// [`Tag`](super::Tag)-scoped twin [`TaggedNetnodeMut`](super::TaggedNetnodeMut).
///
/// ```
/// use idakit::netnode::{NetnodeBytes, NetnodeBytesError};
///
/// assert!(matches!(
///     NetnodeBytes::try_from(b"".as_slice()),
///     Err(NetnodeBytesError::Empty)
/// ));
///
/// let over_cap = vec![0u8; NetnodeBytes::MAX_SIZE + 1];
/// assert!(matches!(
///     NetnodeBytes::try_from(&over_cap),
///     Err(NetnodeBytesError::TooLarge { len, cap })
///         if len == over_cap.len() && cap == NetnodeBytes::MAX_SIZE
/// ));
///
/// let ok = NetnodeBytes::try_from(b"hi".as_slice()).unwrap();
/// assert_eq!(ok.as_bytes(), b"hi");
/// ```
#[derive(Clone, Copy)]
pub struct NetnodeBytes<'a>(&'a [u8]);

impl<'a> NetnodeBytes<'a> {
    /// The largest number of bytes the SDK accepts for one value/supval/hash object.
    #[doc(alias("MAXSPECSIZE"))]
    pub const MAX_SIZE: usize = idakit_sys::MAXSPECSIZE;

    /// The validated bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    /// Validate `value` against the `1..=MAX_SIZE` domain.
    fn validate(value: &'a [u8]) -> Result<Self, NetnodeBytesError> {
        match value.len() {
            0 => Err(NetnodeBytesError::Empty),
            len if len > Self::MAX_SIZE => Err(NetnodeBytesError::TooLarge {
                len,
                cap: Self::MAX_SIZE,
            }),
            _ => Ok(Self(value)),
        }
    }
}

impl std::fmt::Debug for NetnodeBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("NetnodeBytes").field(&self.0).finish()
    }
}

impl<'a> TryFrom<&'a [u8]> for NetnodeBytes<'a> {
    type Error = NetnodeBytesError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::validate(value)
    }
}

impl<'a, const N: usize> TryFrom<&'a [u8; N]> for NetnodeBytes<'a> {
    type Error = NetnodeBytesError;

    fn try_from(value: &'a [u8; N]) -> Result<Self, Self::Error> {
        Self::validate(value.as_slice())
    }
}

impl<'a> TryFrom<&'a Vec<u8>> for NetnodeBytes<'a> {
    type Error = NetnodeBytesError;

    fn try_from(value: &'a Vec<u8>) -> Result<Self, Self::Error> {
        Self::validate(value.as_slice())
    }
}

// The std blanket `impl<T, U: From<T>> TryFrom<T> for U` already gives the reflexive
// `TryFrom<NetnodeBytes<'a>> for NetnodeBytes<'a>` (via `impl<T> From<T> for T`), with
// `Error = Infallible`. Setters bound on `Error: Into<NetnodeBytesError>` need this to close
// that path, so an already-validated `NetnodeBytes` can be reused across several writes.
impl From<Infallible> for NetnodeBytesError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

/// Why a byte slice failed to become a validated [`NetnodeBytes`].
///
/// `?` flattens it into [`Error::InvalidNetnodeBytes`](crate::Error::InvalidNetnodeBytes).
#[derive(Debug, Snafu, PartialEq, Eq)]
pub enum NetnodeBytesError {
    /// The value was empty, which the SDK cannot store.
    #[snafu(display("netnode byte objects cannot be empty"))]
    Empty,

    /// The value exceeded `cap`, past which the kernel truncates silently.
    #[snafu(display("netnode value is {len} bytes, exceeding the {cap}-byte cap"))]
    TooLarge {
        /// The value's actual length in bytes.
        len: usize,
        /// The enforced cap ([`NetnodeBytes::MAX_SIZE`]).
        cap: usize,
    },
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    #[test]
    fn empty_slice_is_rejected() {
        let err = NetnodeBytes::try_from(b"".as_slice()).unwrap_err();
        assert!(err == NetnodeBytesError::Empty);
    }

    #[test]
    fn oversized_slice_is_rejected() {
        let over = vec![0u8; NetnodeBytes::MAX_SIZE + 1];
        let err = NetnodeBytes::try_from(over.as_slice()).unwrap_err();
        assert!(
            err == NetnodeBytesError::TooLarge {
                len: NetnodeBytes::MAX_SIZE + 1,
                cap: NetnodeBytes::MAX_SIZE,
            }
        );
    }

    #[test]
    fn at_cap_is_accepted() {
        let at_cap = vec![0u8; NetnodeBytes::MAX_SIZE];
        let bytes = NetnodeBytes::try_from(at_cap.as_slice()).unwrap();
        assert!(bytes.as_bytes() == at_cap.as_slice());
    }

    #[test]
    fn debug_renders_the_validated_bytes() {
        let bytes = NetnodeBytes::try_from(b"hi".as_slice()).unwrap();
        assert!(format!("{bytes:?}") == "NetnodeBytes([104, 105])");
    }

    #[test]
    fn accepts_array_and_vec_refs() {
        assert!(NetnodeBytes::try_from(b"hi").is_ok());
        assert!(NetnodeBytes::try_from(&vec![1u8, 2, 3]).is_ok());
    }

    #[rstest]
    #[case::empty_display(NetnodeBytesError::Empty, "netnode byte objects cannot be empty")]
    #[case::too_large_display(
        NetnodeBytesError::TooLarge { len: 1025, cap: 1024 },
        "netnode value is 1025 bytes, exceeding the 1024-byte cap",
    )]
    fn error_displays(#[case] err: NetnodeBytesError, #[case] expect: &str) {
        assert!(err.to_string() == expect);
    }
}
