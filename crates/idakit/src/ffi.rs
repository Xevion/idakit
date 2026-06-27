//! C-string helpers for the facade ABI. Facade getters fill a `(buf, cap)` and
//! return the value's full length (`<0` = absent); [`read_string`] drives the
//! size-then-fill retry, [`with_cstr`] is the send direction.

use std::ffi::{CString, c_char};

use crate::error::{Error, Result};

const STACK_CAP: usize = 256;

/// Read a facade string getter into a [`String`] (`None` if absent; lossy UTF-8).
pub(crate) fn read_string(f: impl Fn(*mut c_char, usize) -> i64) -> Option<String> {
    let mut stack = [0u8; STACK_CAP];
    let r = f(stack.as_mut_ptr().cast(), STACK_CAP);
    if r < 0 {
        return None;
    }
    let len = r as usize;
    if len < STACK_CAP {
        return Some(String::from_utf8_lossy(&stack[..len]).into_owned());
    }
    // Truncated; re-call with an exact buffer (+1 for the NUL).
    let mut heap = vec![0u8; len + 1];
    let r2 = f(heap.as_mut_ptr().cast(), heap.len());
    if r2 < 0 {
        return None;
    }
    let len2 = (r2 as usize).min(len);
    Some(String::from_utf8_lossy(&heap[..len2]).into_owned())
}

/// Pass `s` to `f` as a C string, or [`Error::InteriorNul`] if it has a NUL.
pub(crate) fn with_cstr<R>(
    s: &str,
    arg: &'static str,
    f: impl FnOnce(*const c_char) -> R,
) -> Result<R> {
    let c = CString::new(s).map_err(|_| Error::InteriorNul { arg })?;
    Ok(f(c.as_ptr()))
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    /// Facade-getter stand-in: `qstrncpy` into the buffer, return the full length.
    fn getter(src: &[u8]) -> impl Fn(*mut c_char, usize) -> i64 + '_ {
        move |buf, cap| {
            if cap > 0 {
                let n = src.len().min(cap - 1);
                // SAFETY: test-only; buf has cap bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(src.as_ptr(), buf.cast::<u8>(), n);
                    *buf.add(n) = 0;
                }
            }
            src.len() as i64
        }
    }

    #[rstest]
    #[case::empty(b"")]
    #[case::short(b"main")]
    #[case::exact255(&[b'a'; 255])]
    #[case::exact256(&[b'b'; 256])]
    #[case::long(&[b'c'; 4096])]
    fn round_trips_through_regrow(#[case] src: &[u8]) {
        let got = read_string(getter(src)).expect("present");
        assert!(got.as_bytes() == src);
    }

    #[test]
    fn negative_length_is_absent() {
        let r = read_string(|buf, cap| {
            if cap > 0 {
                // SAFETY: test-only.
                unsafe { *buf = 0 };
            }
            -1
        });
        assert!(r.is_none());
    }

    #[test]
    fn invalid_utf8_decodes_lossy() {
        let got = read_string(getter(&[0xff, 0xfe, b'a'])).expect("present");
        assert!(got.contains('\u{fffd}'));
    }

    #[test]
    fn with_cstr_rejects_interior_nul() {
        let r = with_cstr("ab\0cd", "name", |_| ());
        assert!(r == Err(Error::InteriorNul { arg: "name" }));
    }

    #[test]
    fn with_cstr_passes_valid_string() {
        let len = with_cstr("hello", "name", |p| {
            // SAFETY: p is a valid C string for the call.
            unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes().len()
        })
        .expect("valid");
        assert!(len == 5);
    }
}
