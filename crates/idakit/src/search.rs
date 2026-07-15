//! A compiled binary search pattern ([`Pattern`]) and the lazy iterator over its occurrences
//! ([`Matches`]). A `Pattern` owns a kernel handle freed on [`Drop`]; being `!Send`, it
//! (like [`DecompiledFunction`](crate::decompiler::DecompiledFunction)) stays on the kernel thread.
//!
//! Four constructors name their grammar so intent is explicit at the call site:
//! [`hex`](Pattern::hex) (`"48 8B 4? ? 90"`, nibble + byte wildcards, parsed here),
//! [`bytes`](Pattern::bytes) (raw bytes + mask), [`code_mask`](Pattern::code_mask)
//! (`\x`-bytes + an `x`/`?` mask string), and [`ida`](Pattern::ida) (IDA's own lenient
//! parser, opt-in). The first three are matched under a per-byte bit mask, so a `0xF0`/`0x0F`
//! mask nibble is a genuine half-byte wildcard.

use std::marker::PhantomData;
use std::ops::Range;

use idakit_sys as sys;

use crate::Database;
use crate::address::Address;
use crate::error::{Error, PatternRejection, Result};

impl Database {
    /// Search the whole image ([`address_range`](Self::address_range)) for `pattern`,
    /// lazily yielding each match address in ascending order.
    #[must_use]
    #[doc(alias("bin_search"))]
    pub fn search<'p, 'db>(&self, pattern: &'p Pattern<'db>) -> Matches<'p, 'db> {
        match self.address_range() {
            Some(range) => self.search_in(range, pattern),
            None => Matches::empty(pattern),
        }
    }

    /// Search `range` (end exclusive) for `pattern`, lazily yielding each match address in
    /// ascending order.
    ///
    /// Each hit advances the scan one byte past it, so overlapping occurrences are all reported.
    #[must_use]
    #[doc(alias("bin_search"))]
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

/// A compiled binary search pattern that frees its kernel handle on [`Drop`].
///
/// `handle` is a [`UniquePtr`](cxx::UniquePtr) of [`CompiledBinpat`](sys::CompiledBinpat),
/// non-null by construction; cxx's deleter frees the `compiled_binpat_vec_t` on drop. `UniquePtr`
/// over an opaque type is `!Send`, so `Pattern` lives only on the kernel thread. It borrows
/// `&Database`, so it can't coexist with a write.
#[doc(alias("compiled_binpat_t"))]
pub struct Pattern<'db> {
    handle: cxx::UniquePtr<sys::CompiledBinpat>,
    /// Per-search match flags: bitmask matching for the byte/mask forms (so mask nibbles
    /// work), or plain case-sensitivity for [`ida`](Pattern::ida).
    flags: sys::BinSearchFlags,
    _db: PhantomData<&'db Database>,
}

impl<'db> Pattern<'db> {
    /// Compile an IDA-style hex signature.
    ///
    /// Each whitespace-separated token is a hex byte (`48`), a byte wildcard (`?` or `??`), or a
    /// nibble pattern with one wildcard half (`4?`, `?B`). This grammar is parsed here, not by
    /// IDA, so a mistyped byte is a hard error rather than the silent ASCII fallback
    /// [`ida`](Self::ida) would give it.
    ///
    /// # Errors
    /// [`Error::PatternRejected`] with [`PatternRejection::BadToken`] naming the first token
    /// that is none of these, or [`PatternRejection::NoAnchor`] if every byte is a wildcard.
    pub fn hex(db: &'db Database, pattern: impl AsRef<str>) -> Result<Self> {
        let pattern = pattern.as_ref();
        let (bytes, mask) = parse_hex(pattern).map_err(|kind| Error::PatternRejected {
            pattern: pattern.to_owned(),
            kind,
        })?;
        Self::from_parts(db, pattern.to_owned(), &bytes, Some(&mask))
    }

    /// Compile from a code byte sequence and a parallel mask string.
    ///
    /// `x`/`X` matches the byte and `?`/`.` wildcards it, the `\x..`-plus-mask convention of
    /// shared sig dumps.
    ///
    /// # Errors
    /// [`Error::PatternRejected`] with [`PatternRejection::BadMaskChar`] for a mask character
    /// outside that set, [`PatternRejection::MaskMismatch`] for a length mismatch, or
    /// [`PatternRejection::NoAnchor`] for an all-wildcard mask.
    pub fn code_mask(db: &'db Database, code: &[u8], mask: impl AsRef<str>) -> Result<Self> {
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
    /// checked in full.
    ///
    /// Shared by the parsing constructors and [`bytes`](Self::bytes).
    fn from_parts(
        db: &'db Database,
        repr: String,
        bytes: &[u8],
        mask: Option<&[u8]>,
    ) -> Result<Self> {
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
        // An empty mask slice tells the facade every byte is concrete.
        let handle = sys::binpat_from_bytes(bytes, mask.unwrap_or(&[]));
        Ok(Self {
            handle,
            flags: sys::BinSearchFlags::BITMASK,
            _db: PhantomData,
        })
    }
}

#[bon::bon]
impl<'db> Pattern<'db> {
    /// Build a pattern from raw bytes.
    ///
    /// Without `mask`, every byte must match. With one (same length), a mask byte is applied
    /// bitwise: `0xFF` full byte, `0x00` wildcard, `0xF0` high nibble, `0x0F` low nibble.
    ///
    /// # Errors
    /// [`Error::PatternRejected`] on a length mismatch or an all-wildcard mask.
    #[builder]
    pub fn bytes<'a>(
        #[builder(start_fn)] db: &'db Database,
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

    /// Compile via IDA's own parser: the full grammar (`"..."` string literals, `'c'` char
    /// constants, radix-`radix` numbers) including its lenient ASCII fallback for bare tokens.
    ///
    /// `case_sensitive` matches string literals exactly (default insensitive).
    ///
    /// # Errors
    /// [`Error::PatternRejected`] with [`PatternRejection::Unparseable`] when IDA rejects it
    /// outright, or [`PatternRejection::NoAnchor`] when it compiles to only wildcards.
    #[builder]
    #[doc(alias("parse_binpat_str"))]
    pub fn ida(
        #[builder(start_fn)] db: &'db Database,
        #[builder(start_fn)] pattern: impl AsRef<str>,
        #[builder(default = 16)] radix: u32,
        #[builder(default)] case_sensitive: bool,
    ) -> Result<Self> {
        let pattern = pattern.as_ref();
        let flags = if case_sensitive {
            sys::BinSearchFlags::CASE
        } else {
            sys::BinSearchFlags::empty()
        };
        // IDA's pattern compiler needs an address for byte-width context; the image floor is
        // valid, and every processor idakit targets is a flat 8-bit byte anyway.
        let ctx = db.min_ea();
        let handle = sys::binpat_compile(ctx, pattern, radix as i32).map_err(|e| {
            let detail = e.what().to_owned();
            Error::PatternRejected {
                pattern: pattern.to_owned(),
                kind: PatternRejection::Unparseable {
                    detail: (!detail.is_empty()).then_some(detail),
                },
            }
        })?;
        // IDA's parser reports success even when it dropped tokens to nothing; a pattern with
        // no concrete byte can only ever match nothing, so reject it here too.
        let stats = sys::binpat_stats(handle.as_ref().expect("live pattern"));
        if stats.anchors == 0 {
            return Err(Error::PatternRejected {
                pattern: pattern.to_owned(),
                kind: PatternRejection::NoAnchor { total: stats.total },
            });
        }
        Ok(Self {
            handle,
            flags,
            _db: PhantomData,
        })
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

/// One hex-signature token to `(byte, mask)`, or `None` if it is not a byte, nibble, or
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

/// A lazy iterator over a [`Pattern`]'s matches, from [`Database::search`]/[`Database::search_in`].
///
/// `'p` borrows the [`Pattern`] (keeping its handle alive); `'db` is the database that
/// pattern belongs to, kept open for the walk.
#[doc(alias("bin_search"))]
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

impl std::fmt::Debug for Matches<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Matches")
            .field("cur", &self.cur)
            .field("end", &self.end)
            .finish_non_exhaustive()
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
        // The borrowed pattern holds the compiled-against database open, and `!Send` keeps us
        // on the kernel thread.
        let hit = sys::bin_search(
            start.get(),
            self.end.get(),
            self.pat.handle.as_ref().expect("live pattern"),
            self.pat.flags.bits(),
        );
        if let Some(address) = Address::try_new(hit) {
            self.cur = Some(address + 1);
            Some(address)
        } else {
            self.cur = None;
            None
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
