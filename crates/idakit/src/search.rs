//! [`Pattern`]: a compiled binary search pattern, and [`Matches`], the lazy iterator over
//! its occurrences. A `Pattern` owns a kernel handle freed on [`Drop`]; being `!Send`, it
//! (like [`TypeInfo`](crate::TypeInfo)/[`Cfunc`](crate::Cfunc)) stays on the kernel thread.

use std::ffi::{c_int, c_void};
use std::marker::PhantomData;
use std::ops::Range;

use idakit_sys as sys;

use crate::Idb;
use crate::ea::{Ea, Offset};
use crate::error::{Error, Result};
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
        range: Range<Ea>,
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
/// construction), from `idakit_binpat_compile`, freed exactly once on [`Drop`]. The raw
/// pointer makes `Pattern` `!Send`, so it lives only on the kernel thread; it borrows the
/// [`Idb`] it compiled against, so that database stays open while the pattern exists.
pub struct Pattern<'db> {
    handle: *mut c_void,
    /// `BIN_SEARCH_*` semantics fixed at compile time (case, bitmask), applied per search.
    flags: c_int,
    _db: PhantomData<&'db Idb>,
}

#[bon::bon]
impl<'db> Pattern<'db> {
    /// Compile an IDA-style binary pattern against `db`: space-separated hex bytes with `?`
    /// for a wildcard byte and `"..."` for string literals, e.g. `"B8 ? ? ? ? 90"`. `Err`
    /// if the pattern does not parse.
    ///
    /// `radix` is the numeric base of the byte tokens (default 16). `case_sensitive` matches
    /// `"..."` literals exactly (default insensitive). `bitmask` matches under a strict bit
    /// mask rather than byte-granular wildcards (default off).
    ///
    /// IDA's parser is lenient: only a truly malformed pattern (empty, an unterminated
    /// `"`) is an `Err`. Unrecognized bare tokens are absorbed rather than rejected, so a
    /// typo'd sig can compile to a pattern that simply never matches -- treat "no hits" as
    /// possibly a bad pattern, not proof of absence.
    #[builder]
    pub fn compile(
        #[builder(start_fn)] db: &'db Idb,
        #[builder(start_fn)] pattern: impl AsRef<str>,
        #[builder(default = 16)] radix: u32,
        #[builder(default)] case_sensitive: bool,
        #[builder(default)] bitmask: bool,
    ) -> Result<Self> {
        let pattern = pattern.as_ref();
        let mut flags: c_int = 0;
        if case_sensitive {
            flags |= sys::BIN_SEARCH_CASE;
        }
        if bitmask {
            flags |= sys::BIN_SEARCH_BITMASK;
        }
        // parse_binpat_str needs an address for byte-width context; the image floor is a
        // valid one, and every processor idakit targets is a flat 8-bit byte anyway.
        let ctx = db.min_ea();
        let mut err = [0u8; 256];
        // SAFETY: `err` is a writable buffer of `err.len()`; the facade NUL-terminates
        // within it and writes the parse reason there when it returns null.
        let handle = with_cstr(pattern, "pattern", |p| unsafe {
            sys::idakit_binpat_compile(ctx, p, radix as c_int, err.as_mut_ptr().cast(), err.len())
        })?;
        if handle.is_null() {
            // SAFETY: `err` holds a NUL-terminated string written by the facade.
            let reason = unsafe { cstr(err.as_ptr().cast()) };
            return Err(Error::PatternParse {
                pattern: pattern.to_owned(),
                reason: if reason.is_empty() {
                    "invalid pattern".to_owned()
                } else {
                    reason
                },
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

/// Lazy iterator over a [`Pattern`]'s matches; see [`Idb::search`]/[`Idb::search_in`].
///
/// `'p` borrows the [`Pattern`] (keeping its handle alive); `'db` is the database that
/// pattern belongs to, kept open for the walk.
pub struct Matches<'p, 'db> {
    pat: &'p Pattern<'db>,
    /// Next address to search from; `None` once the range is exhausted.
    cur: Option<Ea>,
    end: Ea,
}

impl<'p, 'db> Matches<'p, 'db> {
    /// An iterator that yields nothing, for a database with no address range.
    #[inline]
    fn empty(pat: &'p Pattern<'db>) -> Self {
        Self {
            pat,
            cur: None,
            end: Ea::new_const(0),
        }
    }
}

impl Iterator for Matches<'_, '_> {
    type Item = Ea;

    fn next(&mut self) -> Option<Ea> {
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
        match Ea::try_new(hit) {
            Some(ea) => {
                self.cur = Some(ea + Offset::new(1));
                Some(ea)
            }
            None => {
                self.cur = None;
                None
            }
        }
    }
}
