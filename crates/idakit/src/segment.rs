//! Enumerates a database's segments and reads them through the [`Segment`] view.

use idakit_sys as sys;

use crate::Database;
use crate::address::Address;
use crate::bitness::Bitness;

impl Database {
    /// Iterate every segment in the database, in kernel order.
    #[inline]
    #[must_use]
    #[doc(alias("get_segm_qty"))]
    pub fn segments(&self) -> Segments<'_> {
        Segments::new(self)
    }
}

/// A borrowed view of one segment, keyed by kernel index.
#[derive(Clone, Copy)]
#[doc(alias("segment_t"))]
pub struct Segment<'db> {
    index: i32,
    db: &'db Database,
}

impl<'db> Segment<'db> {
    #[inline]
    pub(crate) fn new(index: i32, db: &'db Database) -> Self {
        Self { index, db }
    }

    /// The segment's kernel index.
    #[inline]
    #[must_use]
    pub const fn index(&self) -> i32 {
        self.index
    }

    /// The segment's name (e.g. `.text`), or `None` if unavailable.
    #[must_use]
    #[doc(alias("get_visible_segm_name"))]
    pub fn name(&self) -> Option<String> {
        self.db.seg_name(self.index)
    }

    /// First address of the segment.
    #[inline]
    #[must_use]
    #[doc(alias("start_ea"))]
    pub fn start(&self) -> Option<Address> {
        Address::try_new(self.db.seg_start(self.index))
    }

    /// One-past-the-last address of the segment.
    #[inline]
    #[must_use]
    #[doc(alias("end_ea"))]
    pub fn end(&self) -> Option<Address> {
        Address::try_new(self.db.seg_end(self.index))
    }

    /// The whole segment's bytes (`[start, end)`), or `None` if bounds are absent.
    #[must_use]
    #[doc(alias("get_bytes"))]
    pub fn bytes(&self) -> Option<Vec<u8>> {
        let (start, end) = (self.start()?, self.end()?);
        let len = start.distance_to(end) as usize;
        Some(self.db.bytes(start, len))
    }

    /// The segment's raw class string (e.g. `CODE`, `DATA`, `BSS`), or `None` if it has none.
    ///
    /// [`class`](Self::class) classifies this into a [`SegmentClass`]; use this accessor when
    /// the raw text itself (rather than its meaning) is what's wanted.
    #[must_use]
    #[doc(alias("get_segm_class"))]
    pub fn class_name(&self) -> Option<String> {
        self.db.seg_class(self.index)
    }

    /// The segment's class, classified from its [`class_name`](Self::class_name) string, or
    /// `None` if it has none.
    #[must_use]
    pub fn class(&self) -> Option<SegmentClass> {
        self.class_name().map(|s| SegmentClass::from_raw(&s))
    }

    /// The segment's addressing width, or `None` if the segment reports an unrecognized one.
    #[must_use]
    #[doc(alias("abits"))]
    pub fn bitness(&self) -> Option<Bitness> {
        Bitness::try_from_bits(self.db.seg_bitness(self.index).max(0) as u8)
    }

    /// The segment's raw permission bits.
    #[inline]
    #[must_use]
    fn perm(&self) -> sys::SegPerm {
        sys::SegPerm::from_bits_retain(self.db.seg_perm(self.index))
    }

    /// Whether the segment is readable.
    ///
    /// All three permission predicates read `false` when the input format recorded no
    /// permission bits.
    #[must_use]
    #[doc(alias("SEGPERM_READ"))]
    pub fn is_readable(&self) -> bool {
        self.perm().contains(sys::SegPerm::READ)
    }

    /// Whether the segment is writable.
    #[must_use]
    #[doc(alias("SEGPERM_WRITE"))]
    pub fn is_writable(&self) -> bool {
        self.perm().contains(sys::SegPerm::WRITE)
    }

    /// Whether the segment is executable.
    #[must_use]
    #[doc(alias("SEGPERM_EXEC"))]
    pub fn is_executable(&self) -> bool {
        self.perm().contains(sys::SegPerm::EXEC)
    }
}

impl std::fmt::Debug for Segment<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Segment")
            .field("index", &self.index)
            .field("name", &self.name())
            .field("start", &self.start())
            .field("end", &self.end())
            .finish()
    }
}

key_identity!(Segment, index, ord);

/// A lazy iterator over every segment in the database, in kernel order, from
/// [`Database::segments`].
#[doc(alias("getnseg"))]
pub struct Segments<'db> {
    db: &'db Database,
    next: i32,
    count: i32,
}

impl<'db> Segments<'db> {
    #[inline]
    pub(crate) fn new(db: &'db Database) -> Self {
        Self {
            db,
            next: 0,
            count: db.seg_qty(),
        }
    }
}

impl<'db> Iterator for Segments<'db> {
    type Item = Segment<'db>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.count {
            return None;
        }
        let seg = Segment::new(self.next, self.db);
        self.next += 1;
        Some(seg)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = (self.count - self.next).max(0) as usize;
        (rem, Some(rem))
    }
}

impl ExactSizeIterator for Segments<'_> {}

/// A segment's classification, from its [`class_name`](Segment::class_name) string.
///
/// IDA documents the segment class as arbitrary text (max 8 characters): a handful of
/// predefined names map to known segment kinds, but a loader or user can set anything.
/// [`Other`](Self::Other) carries any class string outside that predefined set (e.g. `UNK`,
/// or a loader-specific name).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[doc(alias("get_segm_class"))]
pub enum SegmentClass {
    /// `CODE`: executable code.
    Code,
    /// `DATA`: general read/write data.
    Data,
    /// `CONST`: read-only data.
    Const,
    /// `STACK`: the stack segment.
    Stack,
    /// `BSS`: uninitialized data.
    Bss,
    /// `XTRN`: IDA's extern-definitions pseudo-segment (imports/externs).
    External,
    /// `COMM`: communal (COMMON-block) definitions.
    Common,
    /// `ABS`: absolute-symbol definitions.
    Absolute,
    /// Any class string outside the predefined set, loader- or user-defined.
    Other(String),
}

impl SegmentClass {
    /// Classifies a raw class string.
    ///
    /// The eight predefined names match exactly (case-sensitive, uppercase); anything else,
    /// including `UNK`, becomes [`Other`](Self::Other).
    fn from_raw(raw: &str) -> Self {
        match raw {
            "CODE" => Self::Code,
            "DATA" => Self::Data,
            "CONST" => Self::Const,
            "STACK" => Self::Stack,
            "BSS" => Self::Bss,
            "XTRN" => Self::External,
            "COMM" => Self::Common,
            "ABS" => Self::Absolute,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl std::fmt::Display for SegmentClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Code => "CODE",
            Self::Data => "DATA",
            Self::Const => "CONST",
            Self::Stack => "STACK",
            Self::Bss => "BSS",
            Self::External => "XTRN",
            Self::Common => "COMM",
            Self::Absolute => "ABS",
            Self::Other(s) => s,
        })
    }
}

/// Reconstruct the raw class string via [`Display`](std::fmt::Display).
impl From<SegmentClass> for String {
    #[inline]
    fn from(class: SegmentClass) -> Self {
        class.to_string()
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    /// Each predefined class string round-trips through [`SegmentClass::from_raw`] and back
    /// through [`Display`](std::fmt::Display); an unmodeled string (`RDATA`) falls to
    /// [`Other`](SegmentClass::Other) and still round-trips its own text.
    #[rstest]
    #[case("CODE", SegmentClass::Code)]
    #[case("DATA", SegmentClass::Data)]
    #[case("CONST", SegmentClass::Const)]
    #[case("STACK", SegmentClass::Stack)]
    #[case("BSS", SegmentClass::Bss)]
    #[case("XTRN", SegmentClass::External)]
    #[case("COMM", SegmentClass::Common)]
    #[case("ABS", SegmentClass::Absolute)]
    #[case("RDATA", SegmentClass::Other(String::from("RDATA")))]
    fn classifies_and_round_trips(#[case] raw: &str, #[case] expect: SegmentClass) {
        let classified = SegmentClass::from_raw(raw);
        assert!(classified == expect);
        assert!(classified.to_string() == raw);
    }
}
