//! C-string helpers for the facade ABI. Facade getters fill a `(buf, cap)` and
//! return the value's full length (`<0` = absent); [`read_string`] drives the
//! size-then-fill retry, [`with_cstr`] is the send direction.

use std::ffi::{CStr, CString, c_char};

use crate::error::{Error, Result};

const STACK_CAP: usize = 256;

/// Copy a borrowed, kernel-owned C string into an owned [`String`] (empty if null;
/// lossy UTF-8).
///
/// # Safety
/// `p` must be null or a valid NUL-terminated string that stays alive for this call.
pub(crate) unsafe fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: non-null and valid per the caller's contract.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

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

/// The facade's captured reason if it left one (trimmed), else `fallback`.
///
/// Not every apply path emits a message, and the captured text carries a trailing newline from
/// the msg channel, so it is trimmed before use.
pub(crate) fn reason_or(reason: &str, fallback: &str) -> String {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        fallback.to_owned()
    } else {
        trimmed.to_owned()
    }
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

/// Reject `s` for an interior NUL before it crosses a `&str` FFI boundary, returning it unchanged
/// when clean.
///
/// A cxx `&str` does not reject an embedded NUL and the C++ side truncates at `.c_str()`, so a
/// name or declaration bound for a generated `&str` fn is guarded here to keep the
/// [`Error::InteriorNul`] contract that [`with_cstr`] gave the raw pointer path.
pub(crate) fn nul_checked<'a>(s: &'a str, arg: &'static str) -> Result<&'a str> {
    if s.bytes().any(|b| b == 0) {
        Err(Error::InteriorNul { arg })
    } else {
        Ok(s)
    }
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

    /// Any negative length, not just `-1`, signals absence.
    #[rstest]
    #[case::minus_one(-1)]
    #[case::minus_two(-2)]
    #[case::i64_min(i64::MIN)]
    fn negative_length_is_absent(#[case] rc: i64) {
        let r = read_string(|buf, cap| {
            if cap > 0 {
                // SAFETY: test-only.
                unsafe { *buf = 0 };
            }
            rc
        });
        assert!(r.is_none());
    }

    #[test]
    fn invalid_utf8_decodes_lossy() {
        let got = read_string(getter(&[0xff, 0xfe, b'a'])).expect("present");
        assert!(got.contains('\u{fffd}'));
    }

    /// The regrow path trusts only the length observed on the *sizing* call: a second call
    /// that reports a larger length (the value grew between calls) is clamped down to it
    /// rather than read past the heap buffer sized for the first length.
    #[test]
    fn regrow_clamps_to_the_first_observed_length_when_it_grew() {
        let grown = vec![b'x'; 400];
        let calls = std::cell::Cell::new(0u32);
        let got = read_string(|buf, cap| {
            let call = calls.get();
            calls.set(call + 1);
            if call == 0 {
                // Sizing call: report 300, too large for the stack buffer.
                if cap > 0 {
                    // SAFETY: test-only; buf has cap bytes.
                    unsafe { *buf = 0 };
                }
                300
            } else {
                // Fill call: the heap buffer is sized for 300 (301 bytes), but the getter now
                // reports 400 as if the source grew between calls.
                let n = grown.len().min(cap.saturating_sub(1));
                // SAFETY: test-only; buf has cap bytes and n < cap.
                unsafe {
                    std::ptr::copy_nonoverlapping(grown.as_ptr(), buf.cast::<u8>(), n);
                    *buf.add(n) = 0;
                }
                400
            }
        })
        .expect("present");
        assert!(got.len() == 300);
    }

    /// The inverse: a second call that reports a *smaller* length (the value shrank) is
    /// trusted, since it is still within the heap buffer's capacity.
    #[test]
    fn regrow_trusts_a_second_call_that_shrank() {
        let shrunk = [b'y'; 100];
        let calls = std::cell::Cell::new(0u32);
        let got = read_string(|buf, cap| {
            let call = calls.get();
            calls.set(call + 1);
            if call == 0 {
                if cap > 0 {
                    // SAFETY: test-only.
                    unsafe { *buf = 0 };
                }
                300
            } else {
                let n = shrunk.len().min(cap.saturating_sub(1));
                // SAFETY: test-only; buf has cap bytes and n < cap.
                unsafe {
                    std::ptr::copy_nonoverlapping(shrunk.as_ptr(), buf.cast::<u8>(), n);
                    *buf.add(n) = 0;
                }
                100
            }
        })
        .expect("present");
        assert!(got.len() == 100);
    }

    /// A fill call reporting `0` is a legitimate empty value, not absence: only a
    /// negative length signals absence.
    #[test]
    fn regrow_fill_call_reporting_zero_yields_empty_string() {
        let calls = std::cell::Cell::new(0u32);
        let got = read_string(|buf, cap| {
            let call = calls.get();
            calls.set(call + 1);
            if cap > 0 {
                // SAFETY: test-only; buf has cap bytes.
                unsafe { *buf = 0 };
            }
            if call == 0 { 300 } else { 0 }
        })
        .expect("present");
        assert!(got.is_empty());
    }

    /// A failure that appears only on the regrow's fill call, after a valid sizing
    /// call, still signals absence.
    #[test]
    fn regrow_fill_call_failure_is_absent() {
        let calls = std::cell::Cell::new(0u32);
        let r = read_string(|buf, cap| {
            let call = calls.get();
            calls.set(call + 1);
            if cap > 0 {
                // SAFETY: test-only; buf has cap bytes.
                unsafe { *buf = 0 };
            }
            if call == 0 { 300 } else { -1 }
        });
        assert!(r.is_none());
    }

    #[rstest]
    #[case::clean("hello", None)]
    #[case::interior_nul("ab\0cd", Some("name"))]
    #[case::leading_nul("\0abc", Some("name"))]
    #[case::trailing_nul("abc\0", Some("name"))]
    #[case::all_nul("\0\0\0", Some("name"))]
    #[case::empty("", None)]
    fn with_cstr_nul_boundary(#[case] s: &str, #[case] rejected_arg: Option<&'static str>) {
        let r = with_cstr(s, "name", |_| ());
        match rejected_arg {
            Some(arg) => assert!(r == Err(Error::InteriorNul { arg })),
            None => assert!(r.is_ok()),
        }
    }

    #[test]
    fn with_cstr_passes_valid_string() {
        let len = with_cstr("hello", "name", |p| {
            // SAFETY: p is a valid C string for the call.
            unsafe { CStr::from_ptr(p) }.to_bytes().len()
        })
        .expect("valid");
        assert!(len == 5);
    }

    #[rstest]
    #[case::clean("clean")]
    #[case::empty("")]
    fn nul_checked_passes_clean_input(#[case] s: &str) {
        assert!(nul_checked(s, "name") == Ok(s));
    }

    #[rstest]
    #[case::interior("a\0b")]
    #[case::leading("\0abc")]
    #[case::trailing("abc\0")]
    fn nul_checked_rejects_any_nul(#[case] s: &str) {
        assert!(nul_checked(s, "name") == Err(Error::InteriorNul { arg: "name" }));
    }

    #[rstest]
    #[case::empty("", "fallback", "fallback")]
    #[case::whitespace_only("   ", "fallback", "fallback")]
    #[case::newline_only("\n\n", "fallback", "fallback")]
    #[case::trimmed("actual reason\n", "fallback", "actual reason")]
    #[case::interior_whitespace_kept(
        "  leading and trailing  ",
        "fallback",
        "leading and trailing"
    )]
    fn reason_or_trims_or_falls_back(
        #[case] reason: &str,
        #[case] fallback: &str,
        #[case] expect: &str,
    ) {
        assert!(reason_or(reason, fallback) == expect);
    }

    #[test]
    fn cstr_null_is_empty() {
        // SAFETY: null is explicitly allowed by cstr's contract.
        let s = unsafe { cstr(std::ptr::null()) };
        assert!(s.is_empty());
    }

    #[test]
    fn cstr_reads_a_valid_c_string() {
        let c = CString::new("hello").unwrap();
        // SAFETY: c stays alive for the call.
        let s = unsafe { cstr(c.as_ptr()) };
        assert!(s == "hello");
    }

    #[test]
    fn cstr_decodes_invalid_utf8_lossily() {
        let c = CString::new(vec![0xff, 0xfe, b'a']).unwrap();
        // SAFETY: c stays alive for the call.
        let s = unsafe { cstr(c.as_ptr()) };
        assert!(s.contains('\u{fffd}'));
    }
}
