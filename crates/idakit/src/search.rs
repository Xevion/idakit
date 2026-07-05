//! [`Pattern`]: a compiled binary search pattern, and [`Matches`], the lazy iterator over
//! its occurrences. A `Pattern` owns a kernel handle freed on [`Drop`]; being `!Send`, it
//! (like [`TypeInfo`](crate::TypeInfo)/[`DecompiledFunction`](crate::DecompiledFunction)) stays on the kernel thread.
//!
//! Four constructors name their grammar so intent is explicit at the call site:
//! [`hex`](Pattern::hex) (`"48 8B 4? ? 90"`, nibble + byte wildcards, parsed here),
//! [`bytes`](Pattern::bytes) (raw bytes + mask), [`code_mask`](Pattern::code_mask)
//! (`\x`-bytes + an `x`/`?` mask string), and [`ida`](Pattern::ida) (IDA's own lenient
//! parser, opt-in). The first three are matched under a per-byte bit mask, so a `0xF0`/`0x0F`
//! mask nibble is a genuine half-byte wildcard.

use std::ffi::{c_int, c_void};
use std::marker::PhantomData;
use std::ops::Range;
use std::ptr;

use idakit_sys as sys;

use crate::Idb;
use crate::address::{Address, Offset};
use crate::error::{Error, PatternRejection, Result};
use crate::ffi::{cstr, with_cstr};

impl Idb {
    /// Search the whole image ([`address_range`](Self::address_range)) for `pattern`,
    /// lazily yielding each match address in ascending order.
    #[must_use]
    pub fn search<'p, 'db>(&self, pattern: &'p Pattern<'db>) -> Matches<'p, 'db> {
        match self.address_range() {
            Some(range) => self.search_in(range, pattern),
            None => Matches::empty(pattern),
        }
    }

    /// Search `range` (end exclusive) for `pattern`, lazily yielding each match address in
    /// ascending order. Each hit advances the scan one byte past it, so overlapping
    /// occurrences are all reported.
    #[must_use]
    pub fn search_in<'p, 'db>(
        &self,
        range: Range<Address>,
        pattern: &'p Pattern<'db>,
    ) -> Matches<'p, 'db> {
        Matches {
            pat: pattern,
            cur: Some(range.start),
            end: range.end,
        }
    }
}

/// A compiled binary search pattern. Frees its kernel handle on drop.
///
/// `handle` is the safety invariant for the searches below: non-null (checked at
/// construction), from a facade `idakit_binpat_*` builder, freed exactly once on [`Drop`].
/// The raw pointer makes `Pattern` `!Send`, so it lives only on the kernel thread; it borrows
/// the [`Idb`] it was built against, so that database stays open while the pattern exists.
pub struct Pattern<'db> {
    handle: *mut c_void,
    /// `BIN_SEARCH_*` flags applied per search: `BITMASK` for the byte/mask forms (so mask
    /// nibbles work), `CASE`-or-nothing for [`ida`](Pattern::ida).
    flags: c_int,
    _db: PhantomData<&'db Idb>,
}

impl<'db> Pattern<'db> {
    /// Compile an IDA-style hex signature: whitespace-separated tokens, each a hex byte
    /// (`48`), a byte wildcard (`?` or `??`), or a nibble pattern with one wildcard half
    /// (`4?`, `?B`). `Err` with a [`PatternRejection::BadToken`] naming the first token that
    /// is none of these, or [`NoAnchor`](PatternRejection::NoAnchor) if every byte is a
    /// wildcard.
    ///
    /// This grammar is parsed here, not by IDA -- a mistyped byte is a hard error, never the
    /// silent ASCII fallback [`ida`](Self::ida) would give it.
    pub fn hex(db: &'db Idb, pattern: impl AsRef<str>) -> Result<Self> {
        let pattern = pattern.as_ref();
        let (bytes, mask) = parse_hex(pattern).map_err(|kind| Error::PatternRejected {
            pattern: pattern.to_owned(),
            kind,
        })?;
        Self::from_parts(db, pattern.to_owned(), &bytes, Some(&mask))
    }

    /// Compile from a code byte sequence and a parallel mask string: `x`/`X` matches the
    /// byte, `?`/`.` wildcards it (the `\x..`+mask convention of shared sig dumps). `Err`
    /// on a mask character outside that set ([`BadMaskChar`](PatternRejection::BadMaskChar)),
    /// a length mismatch ([`MaskMismatch`](PatternRejection::MaskMismatch)), or an
    /// all-wildcard mask ([`NoAnchor`](PatternRejection::NoAnchor)).
    pub fn code_mask(db: &'db Idb, code: &[u8], mask: impl AsRef<str>) -> Result<Self> {
        let mask = mask.as_ref();
        let repr = render(code);
        let mask_bytes = parse_mask(mask).map_err(|kind| Error::PatternRejected {
            pattern: repr.clone(),
            kind,
        })?;
        if mask_bytes.len() != code.len() {
            return Err(Error::PatternRejected {
                pattern: repr,
                kind: PatternRejection::MaskMismatch {
                    bytes: code.len(),
                    mask: mask_bytes.len(),
                },
            });
        }
        Self::from_parts(db, repr, code, Some(&mask_bytes))
    }

    /// Build a pattern from raw bytes plus a per-byte bit mask, or from `bytes.len()` bytes
    /// checked in full. Shared by the parsing constructors and [`bytes`](Self::bytes).
    fn from_parts(db: &'db Idb, repr: String, bytes: &[u8], mask: Option<&[u8]>) -> Result<Self> {
        let _ = db; // borrow only: ties the pattern's lifetime to the open database.
        let anchors = match mask {
            Some(m) => m.iter().filter(|&&b| b != 0).count(),
            None => bytes.len(),
        };
        if anchors == 0 {
            return Err(Error::PatternRejected {
                pattern: repr,
                kind: PatternRejection::NoAnchor { total: bytes.len() },
            });
        }
        let mask_ptr = mask.map_or(ptr::null(), <[u8]>::as_ptr);
        // SAFETY: `bytes` and (when present) `mask` are valid for `bytes.len()`; the facade
        // copies them out and never returns null (it aborts on allocation failure).
        let handle =
            unsafe { sys::idakit_binpat_from_bytes(bytes.as_ptr(), mask_ptr, bytes.len()) };
        Ok(Self {
            handle,
            flags: sys::BIN_SEARCH_BITMASK,
            _db: PhantomData,
        })
    }
}

#[bon::bon]
impl<'db> Pattern<'db> {
    /// Build a pattern from raw bytes. Without `mask`, every byte must match; with one (same
    /// length), a mask byte is applied bitwise -- `0xFF` full byte, `0x00` wildcard, `0xF0`
    /// high nibble, `0x0F` low nibble. `Err` on a length mismatch or an all-wildcard mask.
    #[builder]
    pub fn bytes<'a>(
        #[builder(start_fn)] db: &'db Idb,
        #[builder(start_fn)] data: &'a [u8],
        mask: Option<&'a [u8]>,
    ) -> Result<Self> {
        if let Some(m) = mask
            && m.len() != data.len()
        {
            return Err(Error::PatternRejected {
                pattern: render(data),
                kind: PatternRejection::MaskMismatch {
                    bytes: data.len(),
                    mask: m.len(),
                },
            });
        }
        Self::from_parts(db, render(data), data, mask)
    }

    /// Compile via IDA's own parser -- the full grammar (`"..."` string literals, `'c'` char
    /// constants, radix-`radix` numbers) including its lenient ASCII fallback for bare
    /// tokens. `case_sensitive` matches string literals exactly (default insensitive). `Err`
    /// is [`Unparseable`](PatternRejection::Unparseable) when IDA rejects it outright or
    /// [`NoAnchor`](PatternRejection::NoAnchor) when it compiles to only wildcards.
    #[builder]
    pub fn ida(
        #[builder(start_fn)] db: &'db Idb,
        #[builder(start_fn)] pattern: impl AsRef<str>,
        #[builder(default = 16)] radix: u32,
        #[builder(default)] case_sensitive: bool,
    ) -> Result<Self> {
        let pattern = pattern.as_ref();
        let flags = if case_sensitive {
            sys::BIN_SEARCH_CASE
        } else {
            0
        };
        // parse_binpat_str needs an address for byte-width context; the image floor is valid,
        // and every processor idakit targets is a flat 8-bit byte anyway.
        let ctx = db.min_ea();
        let mut err = [0u8; 256];
        // SAFETY: `err` is a writable buffer of `err.len()`; the facade NUL-terminates within
        // it and writes the parse reason there when it returns null.
        let handle = with_cstr(pattern, "pattern", |p| unsafe {
            sys::idakit_binpat_compile(ctx, p, radix as c_int, err.as_mut_ptr().cast(), err.len())
        })?;
        if handle.is_null() {
            // SAFETY: `err` holds a NUL-terminated string written by the facade.
            let detail = unsafe { cstr(err.as_ptr().cast()) };
            return Err(Error::PatternRejected {
                pattern: pattern.to_owned(),
                kind: PatternRejection::Unparseable {
                    detail: (!detail.is_empty()).then_some(detail),
                },
            });
        }
        // IDA's parser reports success even when it dropped tokens to nothing; a pattern with
        // no concrete byte can only ever match nothing, so reject it here too.
        let (mut total, mut anchors) = (0usize, 0usize);
        // SAFETY: `handle` is the live pattern just compiled; the out-params are valid locals.
        unsafe { sys::idakit_binpat_stats(handle, &mut total, &mut anchors) };
        if anchors == 0 {
            // SAFETY: live handle; freed exactly once here, since we do not return it.
            unsafe { sys::idakit_binpat_free(handle) };
            return Err(Error::PatternRejected {
                pattern: pattern.to_owned(),
                kind: PatternRejection::NoAnchor { total },
            });
        }
        Ok(Self {
            handle,
            flags,
            _db: PhantomData,
        })
    }
}

impl Drop for Pattern<'_> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: live handle (see type docs); freed exactly once, here.
        unsafe { sys::idakit_binpat_free(self.handle) };
    }
}

impl std::fmt::Debug for Pattern<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pattern")
            .field("flags", &self.flags)
            .finish()
    }
}

/// Parse an [`hex`](Pattern::hex) signature into parallel byte and bit-mask vectors.
fn parse_hex(s: &str) -> std::result::Result<(Vec<u8>, Vec<u8>), PatternRejection> {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    for (index, tok) in s.split_whitespace().enumerate() {
        let (b, m) = parse_hex_token(tok).ok_or_else(|| PatternRejection::BadToken {
            token: tok.to_owned(),
            index,
        })?;
        bytes.push(b);
        mask.push(m);
    }
    Ok((bytes, mask))
}

/// One hex-signature token to `(byte, mask)`; `None` if it is not a byte, nibble, or
/// wildcard. A single hex digit is its low-nibble byte value (`3` -> `0x03`), matching IDA.
fn parse_hex_token(tok: &str) -> Option<(u8, u8)> {
    let mut chars = tok.chars();
    let a = chars.next()?;
    match chars.next() {
        None => match nibble(a)? {
            (_, 0) => Some((0, 0)),    // lone `?`: a full wildcard byte
            (v, _) => Some((v, 0xFF)), // lone hex digit: a fully-defined byte
        },
        Some(b) => {
            if chars.next().is_some() {
                return None; // more than two characters
            }
            let (hv, hm) = nibble(a)?;
            let (lv, lm) = nibble(b)?;
            Some(((hv << 4) | lv, (hm << 4) | lm))
        }
    }
}

/// One nibble character to `(value, mask)`: a hex digit is `(d, 0xF)`, `?` is `(0, 0)`.
fn nibble(c: char) -> Option<(u8, u8)> {
    if c == '?' {
        Some((0, 0))
    } else {
        c.to_digit(16).map(|d| (d as u8, 0xF))
    }
}

/// Parse a [`code_mask`](Pattern::code_mask) mask string to per-byte masks: `x`/`X` -> full
/// match (`0xFF`), `?`/`.` -> wildcard (`0x00`).
fn parse_mask(mask: &str) -> std::result::Result<Vec<u8>, PatternRejection> {
    mask.chars()
        .enumerate()
        .map(|(index, ch)| match ch {
            'x' | 'X' => Ok(0xFF),
            '?' | '.' => Ok(0x00),
            _ => Err(PatternRejection::BadMaskChar { ch, index }),
        })
        .collect()
}

/// Space-separated uppercase hex, for the `pattern` field of a rejection built from bytes.
fn render(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Lazy iterator over a [`Pattern`]'s matches; see [`Idb::search`]/[`Idb::search_in`].
///
/// `'p` borrows the [`Pattern`] (keeping its handle alive); `'db` is the database that
/// pattern belongs to, kept open for the walk.
pub struct Matches<'p, 'db> {
    pat: &'p Pattern<'db>,
    /// Next address to search from; `None` once the range is exhausted.
    cur: Option<Address>,
    end: Address,
}

impl<'p, 'db> Matches<'p, 'db> {
    /// An iterator that yields nothing, for a database with no address range.
    #[inline]
    fn empty(pat: &'p Pattern<'db>) -> Self {
        Self {
            pat,
            cur: None,
            end: Address::new_const(0),
        }
    }
}

impl Iterator for Matches<'_, '_> {
    type Item = Address;

    fn next(&mut self) -> Option<Address> {
        let start = self.cur?;
        if start >= self.end {
            self.cur = None;
            return None;
        }
        // SAFETY: live pattern handle (see `Pattern` docs); `!Send` keeps us on the kernel
        // thread, and the borrowed pattern holds the compiled-against database open.
        let hit = unsafe {
            sys::idakit_bin_search(start.get(), self.end.get(), self.pat.handle, self.pat.flags)
        };
        match Address::try_new(hit) {
            Some(address) => {
                self.cur = Some(address + Offset::new(1));
                Some(address)
            }
            None => {
                self.cur = None;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("48 8B 90", &[0x48, 0x8B, 0x90], &[0xFF, 0xFF, 0xFF])]
    #[case("48 ? 90", &[0x48, 0x00, 0x90], &[0xFF, 0x00, 0xFF])]
    #[case("48 ?? 90", &[0x48, 0x00, 0x90], &[0xFF, 0x00, 0xFF])]
    #[case("4? ?B", &[0x40, 0x0B], &[0xF0, 0x0F])]
    #[case("?? ??", &[0x00, 0x00], &[0x00, 0x00])]
    #[case("3", &[0x03], &[0xFF])]
    #[case("  0A\t0b ", &[0x0A, 0x0B], &[0xFF, 0xFF])]
    fn hex_parses(#[case] input: &str, #[case] bytes: &[u8], #[case] mask: &[u8]) {
        assert!(let Ok((b, m)) = parse_hex(input));
        assert!(b == bytes);
        assert!(m == mask);
    }

    #[rstest]
    #[case("48 GG 90", "GG", 1)]
    #[case("xyz", "xyz", 0)]
    #[case("48 8BB 90", "8BB", 1)] // three characters
    #[case("Z", "Z", 0)]
    #[case("4G", "4G", 0)] // bad low nibble
    fn hex_rejects_bad_token(#[case] input: &str, #[case] token: &str, #[case] index: usize) {
        assert!(let Err(PatternRejection::BadToken { token: t, index: i }) = parse_hex(input));
        assert!(t == token);
        assert!(i == index);
    }

    #[rstest]
    #[case("xx?x", &[0xFF, 0xFF, 0x00, 0xFF])]
    #[case("X.X", &[0xFF, 0x00, 0xFF])]
    fn mask_parses(#[case] input: &str, #[case] expect: &[u8]) {
        assert!(let Ok(m) = parse_mask(input));
        assert!(m == expect);
    }

    #[rstest]
    #[case("xx_x", '_', 2)]
    #[case("?y", 'y', 1)]
    fn mask_rejects_bad_char(#[case] input: &str, #[case] ch: char, #[case] index: usize) {
        assert!(let Err(PatternRejection::BadMaskChar { ch: c, index: i }) = parse_mask(input));
        assert!(c == ch);
        assert!(i == index);
    }
}
