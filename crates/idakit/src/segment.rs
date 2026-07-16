//! Enumerates a database's segments and reads them through the [`Segment`] view.

use std::fmt;

use idakit_sys as sys;
pub use idakit_sys::SegFlags;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use strum::VariantArray;

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

    /// A view of the segment containing `address`, or `None` if none does.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let first = db.segments().next().unwrap();
    /// let view = db.segment_at(first.start().unwrap()).expect("start resolves to its segment");
    /// assert_eq!(view.index(), first.index());
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[inline]
    #[must_use]
    #[doc(alias("get_segm_num"))]
    pub fn segment_at(&self, address: Address) -> Option<Segment<'_>> {
        let index = self.seg_at(address);
        (index >= 0).then(|| Segment::new(index, self))
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

    /// The segment's selector, unique across the database.
    ///
    /// Unlike [`start`](Self::start)/[`end`](Self::end)/[`color`](Self::color), this never
    /// translates a sentinel: a [`Segment`] always holds a valid index, so the selector it
    /// reports is always real.
    #[inline]
    #[must_use]
    pub fn sel(&self) -> u64 {
        self.db.seg_sel(self.index)
    }

    /// The segment's type, or `None` if it reports an unrecognized code.
    #[must_use]
    #[doc(alias("type"))]
    pub fn kind(&self) -> Option<SegmentType> {
        SegmentType::try_from(self.db.seg_type(self.index).max(0) as u8).ok()
    }

    /// The segment's raw flag bits.
    ///
    /// This is the raw mask backing the `is_*` predicates below; use it directly when a caller
    /// needs to test bit combinations they don't expose.
    #[inline]
    #[must_use]
    pub fn flags(&self) -> SegFlags {
        SegFlags::from_bits_retain(self.db.seg_flags(self.index))
    }

    /// The segment's background color, or `None` when it uses the default color (`DEFCOLOR`).
    #[must_use]
    pub fn color(&self) -> Option<u32> {
        // DEFCOLOR is bgcolor_t(-1): both "no color set" and "index out of range" read as it.
        let raw = self.db.seg_color(self.index);
        (raw != u32::MAX).then_some(raw)
    }

    /// The segment's alignment code, or `None` if it reports an unrecognized one.
    #[inline]
    #[must_use]
    pub fn align(&self) -> Option<SegmentAlign> {
        SegmentAlign::try_from(self.db.seg_align(self.index).max(0) as u8).ok()
    }

    /// The segment's combination code, or `None` if it reports an unrecognized one.
    #[inline]
    #[must_use]
    pub fn comb(&self) -> Option<SegmentComb> {
        SegmentComb::try_from(self.db.seg_comb(self.index).max(0) as u8).ok()
    }

    /// Whether the segment is visible in the disassembly listing.
    #[must_use]
    #[doc(alias("is_visible_segm"))]
    pub fn is_visible(&self) -> bool {
        !self.flags().contains(SegFlags::HIDDEN)
    }

    /// Whether the segment was created for the debugger (temporary).
    #[must_use]
    #[doc(alias("is_debugger_segm"))]
    pub fn is_debugger(&self) -> bool {
        self.flags().contains(SegFlags::DEBUG)
    }

    /// Whether the segment was created by a loader.
    #[must_use]
    #[doc(alias("is_loader_segm"))]
    pub fn is_loader(&self) -> bool {
        self.flags().contains(SegFlags::LOADER)
    }

    /// Whether the segment's *type* is hidden in the listing (`SFL_HIDETYPE`).
    ///
    /// This is not the negation of [`is_visible`](Self::is_visible): it hides the segment's
    /// type label, not the segment itself.
    #[must_use]
    #[doc(alias("is_hidden_segtype"))]
    pub fn is_type_hidden(&self) -> bool {
        self.flags().contains(SegFlags::HIDETYPE)
    }

    /// Whether this is a header segment, into which no offsets are created.
    #[must_use]
    #[doc(alias("is_header_segm"))]
    pub fn is_header(&self) -> bool {
        self.flags().contains(SegFlags::HEADER)
    }

    /// The segment's comment, or `None` if that channel carries none.
    ///
    /// Segment comments are rarely used; `repeatable` selects the repeatable channel over the
    /// regular one.
    #[must_use]
    #[doc(alias("get_segment_cmt"))]
    pub fn comment(&self, repeatable: bool) -> Option<String> {
        self.db.seg_cmt(self.index, repeatable)
    }
}

impl fmt::Debug for Segment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl fmt::Display for SegmentClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

/// A segment's type code (`SEG_*` from `segment.hpp`), from [`Segment::kind`].
///
/// A closed mirror of the SDK's `SEG_*` set: a byte outside it fails `TryFrom<u8>` instead of
/// decoding.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    TryFromPrimitive,
    IntoPrimitive,
    VariantArray,
    Serialize,
    Deserialize,
)]
#[repr(u8)]
#[doc(alias("segment_t"))]
pub enum SegmentType {
    /// `SEG_NORM`: unknown type, no assumptions.
    #[doc(alias("SEG_NORM"))]
    Normal = 0,
    /// `SEG_XTRN`: extern definitions; no instructions or data.
    #[doc(alias("SEG_XTRN"))]
    Extern = 1,
    /// `SEG_CODE`: code segment.
    #[doc(alias("SEG_CODE"))]
    Code = 2,
    /// `SEG_DATA`: data segment.
    #[doc(alias("SEG_DATA"))]
    Data = 3,
    /// `SEG_IMP`: Java implementation segment.
    #[doc(alias("SEG_IMP"))]
    JavaImpl = 4,
    /// `SEG_GRP`: a group of segments.
    #[doc(alias("SEG_GRP"))]
    Group = 6,
    /// `SEG_NULL`: zero-length segment.
    #[doc(alias("SEG_NULL"))]
    Null = 7,
    /// `SEG_UNDF`: undefined segment type, not used.
    #[doc(alias("SEG_UNDF"))]
    Undefined = 8,
    /// `SEG_BSS`: uninitialized segment.
    #[doc(alias("SEG_BSS"))]
    Bss = 9,
    /// `SEG_ABSSYM`: definitions of absolute symbols.
    #[doc(alias("SEG_ABSSYM"))]
    AbsoluteSymbols = 10,
    /// `SEG_COMM`: communal definitions.
    #[doc(alias("SEG_COMM"))]
    Common = 11,
    /// `SEG_IMEM`: internal processor memory and special function registers (8051).
    #[doc(alias("SEG_IMEM"))]
    InternalMemory = 12,
}

impl fmt::Display for SegmentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Normal => "normal",
            Self::Extern => "extern",
            Self::Code => "code",
            Self::Data => "data",
            Self::JavaImpl => "java implementation",
            Self::Group => "group",
            Self::Null => "null",
            Self::Undefined => "undefined",
            Self::Bss => "bss",
            Self::AbsoluteSymbols => "absolute symbols",
            Self::Common => "common",
            Self::InternalMemory => "internal memory",
        })
    }
}

/// A segment's alignment code (`sa*` from `segment.hpp`), from [`Segment::align`].
///
/// A closed mirror of the SDK's `sa*` set: a byte outside it fails `TryFrom<u8>` instead of
/// decoding.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    TryFromPrimitive,
    IntoPrimitive,
    VariantArray,
    Serialize,
    Deserialize,
)]
#[repr(u8)]
pub enum SegmentAlign {
    /// `saAbs`: absolute segment.
    #[doc(alias("saAbs"))]
    Absolute = 0,
    /// `saRelByte`: relocatable, byte aligned.
    #[doc(alias("saRelByte"))]
    RelocatableByte = 1,
    /// `saRelWord`: relocatable, word (2-byte) aligned.
    #[doc(alias("saRelWord"))]
    RelocatableWord = 2,
    /// `saRelPara`: relocatable, paragraph (16-byte) aligned.
    #[doc(alias("saRelPara"))]
    RelocatableParagraph = 3,
    /// `saRelPage`: relocatable, aligned on a 256-byte boundary.
    #[doc(alias("saRelPage"))]
    RelocatablePage = 4,
    /// `saRelDble`: relocatable, aligned on a double word (4-byte) boundary.
    #[doc(alias("saRelDble"))]
    RelocatableDouble = 5,
    /// `saRel4K`: PharLap OMF page (4K) alignment, unsupported by LINK.
    #[doc(alias("saRel4K"))]
    RelocatablePage4K = 6,
    /// `saGroup`: segment group.
    #[doc(alias("saGroup"))]
    Group = 7,
    /// `saRel32Bytes`: relocatable, 32-byte aligned.
    #[doc(alias("saRel32Bytes"))]
    Relocatable32Bytes = 8,
    /// `saRel64Bytes`: relocatable, 64-byte aligned.
    #[doc(alias("saRel64Bytes"))]
    Relocatable64Bytes = 9,
    /// `saRelQword`: relocatable, 8-byte (qword) aligned.
    #[doc(alias("saRelQword"))]
    RelocatableQword = 10,
    /// `saRel128Bytes`: relocatable, 128-byte aligned.
    #[doc(alias("saRel128Bytes"))]
    Relocatable128Bytes = 11,
    /// `saRel512Bytes`: relocatable, 512-byte aligned.
    #[doc(alias("saRel512Bytes"))]
    Relocatable512Bytes = 12,
    /// `saRel1024Bytes`: relocatable, 1024-byte aligned.
    #[doc(alias("saRel1024Bytes"))]
    Relocatable1024Bytes = 13,
    /// `saRel2048Bytes`: relocatable, 2048-byte aligned.
    #[doc(alias("saRel2048Bytes"))]
    Relocatable2048Bytes = 14,
}

/// A segment's combination code (`sc*` from `segment.hpp`), from [`Segment::comb`].
///
/// A closed mirror of the SDK's `sc*` set: a byte outside it (3 is unassigned) fails
/// `TryFrom<u8>` instead of decoding.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    TryFromPrimitive,
    IntoPrimitive,
    VariantArray,
    Serialize,
    Deserialize,
)]
#[repr(u8)]
pub enum SegmentComb {
    /// `scPriv`: private, do not combine with any other segment.
    #[doc(alias("scPriv"))]
    Private = 0,
    /// `scGroup`: segment group.
    #[doc(alias("scGroup"))]
    Group = 1,
    /// `scPub`: public, combine by appending at an alignment-meeting offset.
    #[doc(alias("scPub"))]
    Public = 2,
    /// `scPub2`: Microsoft public, same combination as `scPub`.
    #[doc(alias("scPub2"))]
    Public2 = 4,
    /// `scStack`: stack, combines as `scPub` but forces byte alignment.
    #[doc(alias("scStack"))]
    Stack = 5,
    /// `scCommon`: common, combine by overlay using the maximum size.
    #[doc(alias("scCommon"))]
    Common = 6,
    /// `scPub3`: Microsoft public, same combination as `scPub`.
    #[doc(alias("scPub3"))]
    Public3 = 7,
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

    /// Every modelled [`SegmentType`] variant round-trips through its raw discriminant, so a
    /// variant whose discriminant drifts from the SDK's `SEG_*` value fails here.
    #[test]
    fn segment_type_every_variant_round_trips() {
        for &kind in SegmentType::VARIANTS {
            assert!(SegmentType::try_from(u8::from(kind)).ok() == Some(kind));
        }
    }

    /// A byte outside the modelled `SEG_*` set (5 is unassigned) does not decode.
    #[test]
    fn segment_type_rejects_unmapped_byte() {
        assert!(SegmentType::try_from(5u8).is_err());
        assert!(SegmentType::try_from(255u8).is_err());
    }

    /// `SegmentType` round-trips through JSON.
    #[test]
    fn segment_type_serde_round_trips() {
        let json = serde_json::to_string(&SegmentType::Code).unwrap();
        assert!(serde_json::from_str::<SegmentType>(&json).unwrap() == SegmentType::Code);
    }

    /// Every modelled [`SegmentAlign`] variant round-trips through its raw discriminant, so a
    /// variant whose discriminant drifts from the SDK's `sa*` value fails here.
    #[test]
    fn segment_align_every_variant_round_trips() {
        for &align in SegmentAlign::VARIANTS {
            assert!(SegmentAlign::try_from(u8::from(align)).ok() == Some(align));
        }
    }

    /// A byte outside the modelled `sa*` set (the set is contiguous 0-14) does not decode.
    #[test]
    fn segment_align_rejects_unmapped_byte() {
        assert!(SegmentAlign::try_from(15u8).is_err());
        assert!(SegmentAlign::try_from(255u8).is_err());
    }

    /// Every modelled [`SegmentComb`] variant round-trips through its raw discriminant, so a
    /// variant whose discriminant drifts from the SDK's `sc*` value fails here.
    #[test]
    fn segment_comb_every_variant_round_trips() {
        for &comb in SegmentComb::VARIANTS {
            assert!(SegmentComb::try_from(u8::from(comb)).ok() == Some(comb));
        }
    }

    /// A byte outside the modelled `sc*` set (3 is unassigned) does not decode.
    #[test]
    fn segment_comb_rejects_unmapped_byte() {
        assert!(SegmentComb::try_from(3u8).is_err());
        assert!(SegmentComb::try_from(255u8).is_err());
    }
}
