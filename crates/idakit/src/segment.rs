//! [`Segment`]: a borrowed view of one segment, keyed by kernel index.

use idakit_sys as sys;

use crate::Database;
use crate::address::Address;
use crate::bitness::Bitness;
use crate::ffi::read_string;

impl Database {
    /// Iterate every segment in the database, in kernel order.
    #[inline]
    #[must_use]
    pub fn segments(&self) -> Segments<'_> {
        Segments::new(self)
    }
}

/// A borrowed view of one segment, valid while the database stays open.
#[derive(Clone, Copy)]
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
    pub fn name(&self) -> Option<String> {
        read_string(|buf, cap| self.db.seg_name(self.index, buf, cap))
    }

    /// First address of the segment.
    #[inline]
    #[must_use]
    pub fn start(&self) -> Option<Address> {
        Address::try_new(self.db.seg_start(self.index))
    }

    /// One-past-the-last address of the segment.
    #[inline]
    #[must_use]
    pub fn end(&self) -> Option<Address> {
        Address::try_new(self.db.seg_end(self.index))
    }

    /// The whole segment's bytes (`[start, end)`), or `None` if bounds are absent.
    #[must_use]
    pub fn bytes(&self) -> Option<Vec<u8>> {
        let (start, end) = (self.start()?, self.end()?);
        let len = start.distance_to(end) as usize;
        Some(self.db.bytes(start, len))
    }

    /// The segment's raw class string (e.g. `CODE`, `DATA`, `BSS`), or `None` if it has none.
    /// [`class`](Self::class) classifies this into a [`SegmentClass`]; use this accessor when
    /// the raw text itself (rather than its meaning) is what's wanted.
    #[must_use]
    pub fn class_name(&self) -> Option<String> {
        read_string(|buf, cap| self.db.seg_class(self.index, buf, cap))
    }

    /// The segment's class, classified from its [`class_name`](Self::class_name) string, or
    /// `None` if it has none.
    #[must_use]
    pub fn class(&self) -> Option<SegmentClass> {
        self.class_name().map(|s| SegmentClass::from_raw(&s))
    }

    /// The segment's addressing width, or `None` if the segment reports an unrecognized one.
    #[must_use]
    pub fn bitness(&self) -> Option<Bitness> {
        Bitness::try_from_bits(self.db.seg_bitness(self.index).max(0) as u8)
    }

    /// Whether the segment is readable (`SEGPERM_READ`). All three permission predicates
    /// read `false` when the input format recorded no permission bits.
    #[must_use]
    pub fn is_readable(&self) -> bool {
        self.db.seg_perm(self.index) & sys::SEGPERM_READ != 0
    }

    /// Whether the segment is writable (`SEGPERM_WRITE`).
    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.db.seg_perm(self.index) & sys::SEGPERM_WRITE != 0
    }

    /// Whether the segment is executable (`SEGPERM_EXEC`).
    #[must_use]
    pub fn is_executable(&self) -> bool {
        self.db.seg_perm(self.index) & sys::SEGPERM_EXEC != 0
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

// Identity is the kernel index alone; the `db` borrow is incidental and must not
// participate, so these are hand-written rather than derived.
impl PartialEq for Segment<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.index == o.index
    }
}
impl Eq for Segment<'_> {}
impl std::hash::Hash for Segment<'_> {
    fn hash<H: std::hash::Hasher>(&self, s: &mut H) {
        self.index.hash(s);
    }
}
impl Ord for Segment<'_> {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.index.cmp(&o.index)
    }
}
impl PartialOrd for Segment<'_> {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

/// Lazy iterator over every segment in the database, in kernel order.
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
/// predefined names map to `SEG_*` segment types, but a loader or user can set anything.
/// [`Other`](Self::Other) carries any class string outside that predefined set (e.g. `UNK`,
/// or a loader-specific name).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
    /// Any class string outside the predefined set -- loader- or user-defined.
    Other(String),
}

impl SegmentClass {
    /// Classify a raw class string. The eight predefined names match exactly
    /// (case-sensitive, uppercase); anything else -- including `UNK` -- becomes
    /// [`Other`](Self::Other).
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
