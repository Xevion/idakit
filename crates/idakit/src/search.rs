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
        if let Err(kind) = require_matching_length(code.len(), mask_bytes.len()) {
            return Err(Error::PatternRejected {
                pattern: repr,
                kind,
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
        let anchors = count_anchors(bytes.len(), mask);
        require_anchor(anchors, bytes.len()).map_err(|kind| Error::PatternRejected {
            pattern: repr,
            kind,
        })?;
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
            && let Err(kind) = require_matching_length(data.len(), m.len())
        {
            return Err(Error::PatternRejected {
                pattern: render(data),
                kind,
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
                    detail: non_empty(detail),
                },
            }
        })?;
        // IDA's parser reports success even when it dropped tokens to nothing; a pattern with
        // no concrete byte can only ever match nothing, so reject it here too.
        let stats = sys::binpat_stats(handle.as_ref().expect("live pattern"));
        require_anchor(stats.anchors, stats.total).map_err(|kind| Error::PatternRejected {
            pattern: pattern.to_owned(),
            kind,
        })?;
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

/// Count concrete (non-wildcard) bytes: non-zero mask bytes, or every byte when there is no
/// mask (a raw all-bytes-match pattern).
fn count_anchors(bytes_len: usize, mask: Option<&[u8]>) -> usize {
    match mask {
        Some(m) => m.iter().filter(|&&b| b != 0).count(),
        None => bytes_len,
    }
}

/// Reject a pattern with no concrete byte to match on.
fn require_anchor(anchors: usize, total: usize) -> std::result::Result<(), PatternRejection> {
    if anchors == 0 {
        return Err(PatternRejection::NoAnchor { total });
    }
    Ok(())
}

/// Reject a mask whose length doesn't match the data it covers.
fn require_matching_length(
    data_len: usize,
    mask_len: usize,
) -> std::result::Result<(), PatternRejection> {
    if mask_len != data_len {
        return Err(PatternRejection::MaskMismatch {
            bytes: data_len,
            mask: mask_len,
        });
    }
    Ok(())
}

/// `None` for an empty detail string; IDA's parser sometimes fails with no message at all.
fn non_empty(detail: String) -> Option<String> {
    (!detail.is_empty()).then_some(detail)
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

    #[rstest]
    #[case(Some(&[0xFF, 0x00, 0xFF][..]), 3, 2)] // one wildcard mask byte
    #[case(Some(&[0x00, 0x00, 0x00][..]), 3, 0)] // all-wildcard mask
    #[case(None, 4, 4)] // no mask: every byte anchors
    fn count_anchors_counts_non_zero_mask_bytes_or_every_byte(
        #[case] mask: Option<&[u8]>,
        #[case] bytes_len: usize,
        #[case] expected: usize,
    ) {
        assert!(count_anchors(bytes_len, mask) == expected);
    }

    #[test]
    fn require_anchor_accepts_at_least_one_anchor() {
        assert!(let Ok(()) = require_anchor(1, 3));
    }

    #[test]
    fn require_anchor_rejects_zero_anchors() {
        assert!(let Err(PatternRejection::NoAnchor { total: 3 }) = require_anchor(0, 3));
    }

    #[test]
    fn require_matching_length_accepts_equal_lengths() {
        assert!(let Ok(()) = require_matching_length(4, 4));
    }

    #[rstest]
    #[case(4, 3)]
    #[case(3, 4)]
    fn require_matching_length_rejects_a_mismatch(
        #[case] data_len: usize,
        #[case] mask_len: usize,
    ) {
        assert!(
            let Err(PatternRejection::MaskMismatch { bytes, mask }) =
                require_matching_length(data_len, mask_len)
        );
        assert!(bytes == data_len);
        assert!(mask == mask_len);
    }

    #[test]
    fn non_empty_keeps_a_real_message() {
        assert!(non_empty("bad pattern".to_owned()) == Some("bad pattern".to_owned()));
    }

    #[test]
    fn non_empty_drops_an_empty_message() {
        assert!(non_empty(String::new()) == None);
    }

    mod proptests {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            // For any byte sequence, rendering it as space-separated uppercase hex (Pattern's own
            // `render`) and parsing it back through `parse_hex` recovers the exact bytes with a
            // fully-defined mask (every byte is a concrete two-digit token, never a wildcard).
            #[test]
            fn hex_round_trips_through_render(bytes in proptest::collection::vec(any::<u8>(), 1..32)) {
                let (parsed, mask) = parse_hex(&render(&bytes)).expect("rendered hex always parses");
                prop_assert_eq!(&parsed, &bytes);
                prop_assert!(mask.iter().all(|&m| m == 0xFF));
            }

            // A mask string built only from 'x'/'?' characters always parses, one byte per
            // character, 'x' as a full match (0xFF) and '?' as a wildcard (0x00).
            #[test]
            fn mask_parses_every_x_and_wildcard_string(
                bits in proptest::collection::vec(any::<bool>(), 0..32)
            ) {
                let s: String = bits.iter().map(|&full| if full { 'x' } else { '?' }).collect();
                let mask = parse_mask(&s).expect("an x/? string always parses");
                let expect: Vec<u8> = bits.iter().map(|&full| if full { 0xFF } else { 0x00 }).collect();
                prop_assert_eq!(mask, expect);
            }
        }
    }
}
