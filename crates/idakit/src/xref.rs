//! Cross-reference edges, modeled as [`Xref`] and classified by [`XrefKind`]. IDA's
//! reference-type byte is in two overlapping spaces (code/data) split here into
//! [`CodeXref`]/[`DataXref`], each a closed mirror of IDA's own reference-type enums that
//! rejects a byte outside the set rather than folding it into a catch-all.

use std::fmt;

use idakit_sys as sys;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use strum::VariantArray;

use crate::Database;
use crate::address::Address;

#[bon::bon]
impl Database {
    /// Iterates every cross-reference targeting `address`.
    ///
    /// Its callers and the data that points at it (ordinary sequential flow excluded). For
    /// control over that exclusion, use [`xrefs_to_with`](Self::xrefs_to_with).
    #[inline]
    #[must_use]
    #[doc(alias("xrefblk_t", "first_to"))]
    pub fn xrefs_to(&self, address: Address) -> Xrefs {
        self.xrefs_to_with(address).call()
    }

    /// Iterates every cross-reference originating at `address`.
    ///
    /// What the code there calls, jumps to, or reads (ordinary sequential flow excluded). For
    /// control over that exclusion, use [`xrefs_from_with`](Self::xrefs_from_with).
    #[inline]
    #[must_use]
    #[doc(alias("xrefblk_t", "first_from"))]
    pub fn xrefs_from(&self, address: Address) -> Xrefs {
        self.xrefs_from_with(address).call()
    }

    /// Iterates every cross-reference targeting `address`, with control over ordinary flow edges.
    ///
    /// `flow(true)` also includes ordinary next-instruction flow edges ([`CodeXref::Flow`]),
    /// excluded by default, matching [`xrefs_to`](Self::xrefs_to).
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let entry = db.functions().next().unwrap().address();
    /// let noflow: Vec<_> = db.xrefs_to(entry).collect();
    /// let with_flow: Vec<_> = db.xrefs_to_with(entry).flow(true).call().collect();
    /// assert!(with_flow.len() >= noflow.len());
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[builder]
    #[doc(alias("xrefblk_t", "first_to"))]
    pub fn xrefs_to_with(
        &self,
        #[builder(start_fn)] address: Address,
        #[builder(default = false)] flow: bool,
    ) -> Xrefs {
        Xrefs::new(self.xrefs_build(address, true, flow))
    }

    /// Iterates every cross-reference originating at `address`, with control over ordinary flow
    /// edges.
    ///
    /// `flow(true)` also includes ordinary next-instruction flow edges ([`CodeXref::Flow`]),
    /// excluded by default, matching [`xrefs_from`](Self::xrefs_from).
    #[builder]
    #[doc(alias("xrefblk_t", "first_from"))]
    pub fn xrefs_from_with(
        &self,
        #[builder(start_fn)] address: Address,
        #[builder(default = false)] flow: bool,
    ) -> Xrefs {
        Xrefs::new(self.xrefs_build(address, false, flow))
    }

    /// Whether `address` has a reference from outside the function that contains it.
    ///
    /// `false` when `address` is not inside any function.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let entry = db.functions().next().unwrap().address();
    /// let _ = db.has_external_refs(entry);
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[inline]
    #[must_use]
    pub fn has_external_refs(&self, address: Address) -> bool {
        self.xref_has_external_refs(address)
    }

    /// Whether `address` has an incoming jump or ordinary-flow code cross-reference.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let entry = db.functions().next().unwrap().address();
    /// let _ = db.has_jump_or_flow_xref(entry);
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[inline]
    #[must_use]
    pub fn has_jump_or_flow_xref(&self, address: Address) -> bool {
        self.xref_has_jump_or_flow_xref(address)
    }
}

/// A cross-reference edge, carrying both endpoints. For [`xrefs_to`](Database::xrefs_to) the
/// `to` end is the queried address; for [`xrefs_from`](Database::xrefs_from) the `from` end is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[doc(alias("xrefblk_t"))]
pub struct Xref {
    /// The referencing (source) address.
    pub from: Address,
    /// The referenced (target) address.
    pub to: Address,
    /// How the reference is classified, code vs data, and its specific type.
    pub kind: XrefKind,
    /// Who created the reference, IDA's analysis or the user.
    pub origin: XrefOrigin,
}

impl Xref {
    /// Builds from the facade's `(from, to, type, iscode, user)` tuple.
    ///
    /// `None` (and so skipped by the iterator) if either endpoint is `BADADDR`, or if `ty` is
    /// outside the modelled type set (the set is complete, so this version-drift case does not
    /// occur on real data). `ty` is IDA's already-masked base reference type; `user` marks a
    /// user-defined edge.
    #[inline]
    #[must_use]
    pub(crate) fn from_raw(from: u64, to: u64, ty: u8, iscode: u8, user: u8) -> Option<Self> {
        let from = Address::try_new(from)?;
        let to = Address::try_new(to)?;
        let kind = if iscode != 0 {
            XrefKind::Code(CodeXref::try_from(ty).ok()?)
        } else {
            XrefKind::Data(DataXref::try_from(ty).ok()?)
        };
        let origin = if user != 0 {
            XrefOrigin::User
        } else {
            XrefOrigin::Analysis
        };
        Some(Self {
            from,
            to,
            kind,
            origin,
        })
    }

    /// Whether this is a code reference rather than a data one.
    #[inline]
    #[must_use]
    pub const fn is_code(&self) -> bool {
        matches!(self.kind, XrefKind::Code(_))
    }

    /// Whether the user defined this reference (rather than IDA's analysis).
    #[inline]
    #[must_use]
    pub const fn is_user(&self) -> bool {
        matches!(self.origin, XrefOrigin::User)
    }
}

/// A cross-reference's origin, either IDA's own analysis or an explicit user annotation.
///
/// IDA regenerates a function's xrefs on every reanalysis, deleting the ones it made and
/// recreating them from the code, except those a user marked, which it preserves. So the
/// distinction is also one of durability: a [`User`](XrefOrigin::User) edge is an explicit
/// annotation, an [`Analysis`](XrefOrigin::Analysis) edge is a derived fact that moves with
/// the code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[doc(alias("XREF_USER"))]
pub enum XrefOrigin {
    /// Generated by IDA's auto-analysis (the processor module); recreated on reanalysis.
    Analysis,
    /// Defined by the user; marked `XREF_USER`, so IDA preserves it across reanalysis.
    User,
}

/// An iterator over cross-references, from [`Database::xrefs_to`]/[`Database::xrefs_from`].
///
/// Fetches the whole edge list from the kernel up front into an owned snapshot, so it holds no
/// database borrow while iterating, then converts records to [`Xref`]s lazily as it yields. An
/// edge with a `BADADDR` endpoint, or a type byte outside the modelled set, is skipped.
#[doc(alias("first_to", "next_to", "first_from", "next_from"))]
pub struct Xrefs {
    recs: std::vec::IntoIter<sys::XrefRec>,
}

impl Xrefs {
    #[inline]
    pub(crate) fn new(recs: Vec<sys::XrefRec>) -> Self {
        Self {
            recs: recs.into_iter(),
        }
    }
}

impl Iterator for Xrefs {
    type Item = Xref;

    #[inline]
    fn next(&mut self) -> Option<Xref> {
        // Skip records with a BADADDR endpoint or an out-of-set type byte, converting the rest.
        self.recs.by_ref().find_map(|r| {
            Xref::from_raw(
                r.from,
                r.to,
                r.type_ as u8,
                u8::from(r.iscode),
                u8::from(r.user),
            )
        })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        // Lower bound 0: any record may be filtered out; upper bound is one Xref per record.
        (0, self.recs.size_hint().1)
    }
}

/// A reference classified into the code or data type space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum XrefKind {
    /// A code reference (call, jump, or ordinary flow).
    Code(CodeXref),
    /// A data reference (read, write, offset, ...).
    Data(DataXref),
}

/// A closed mirror of IDA's raw code-reference enum.
///
/// A byte outside this set fails `TryFrom<u8>` instead of decoding.
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
#[doc(alias("cref_t"))]
pub enum CodeXref {
    /// IDA's own "unknown" flow type (`fl_U`), kept for compatibility with old databases: a
    /// real value, not a catch-all for unrecognized bytes.
    #[doc(alias("fl_U"))]
    Unknown = 0,
    /// A far call.
    #[doc(alias("fl_CF"))]
    CallFar = 16,
    /// A near call.
    #[doc(alias("fl_CN"))]
    CallNear = 17,
    /// A far jump.
    #[doc(alias("fl_JF"))]
    JumpFar = 18,
    /// A near jump.
    #[doc(alias("fl_JN"))]
    JumpNear = 19,
    /// An obsolete user-specified code reference (`fl_USobsolete`); modern IDA does not emit
    /// it, kept for a complete mirror of the set.
    #[doc(alias("fl_USobsolete"))]
    UserObsolete = 20,
    /// Ordinary sequential flow into the next instruction.
    #[doc(alias("fl_F"))]
    Flow = 21,
}

impl fmt::Display for CodeXref {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unknown => "unknown",
            Self::CallFar => "far call",
            Self::CallNear => "near call",
            Self::JumpFar => "far jump",
            Self::JumpNear => "near jump",
            Self::UserObsolete => "user-specified (obsolete)",
            Self::Flow => "ordinary flow",
        })
    }
}

/// A closed mirror of IDA's raw data-reference enum.
///
/// A byte outside this set fails `TryFrom<u8>` instead of decoding.
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
#[doc(alias("dref_t"))]
pub enum DataXref {
    /// IDA's own "unknown" data type (`dr_U`), kept for compatibility with old databases: a
    /// real value, not a catch-all for unrecognized bytes.
    #[doc(alias("dr_U"))]
    Unknown = 0,
    /// An offset (address-of) reference.
    #[doc(alias("dr_O"))]
    Offset = 1,
    /// A write access.
    #[doc(alias("dr_W"))]
    Write = 2,
    /// A read access.
    #[doc(alias("dr_R"))]
    Read = 3,
    /// A textual reference (forced operands only).
    #[doc(alias("dr_T"))]
    Text = 4,
    /// An informational reference.
    #[doc(alias("dr_I"))]
    Informational = 5,
    /// A reference to an enum member or symbolic constant (`dr_S`).
    #[doc(alias("dr_S"))]
    Symbolic = 6,
}

impl fmt::Display for DataXref {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unknown => "unknown",
            Self::Offset => "offset",
            Self::Write => "write",
            Self::Read => "read",
            Self::Text => "text",
            Self::Informational => "informational",
            Self::Symbolic => "symbolic",
        })
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    /// The `(type, iscode)` byte pair classifies into the right space and variant, `iscode`
    /// selecting the space so the same byte reads differently as code vs data.
    #[rstest]
    #[case::call_near(17, 1, XrefKind::Code(CodeXref::CallNear))]
    #[case::jump_near(19, 1, XrefKind::Code(CodeXref::JumpNear))]
    #[case::flow(21, 1, XrefKind::Code(CodeXref::Flow))]
    #[case::data_write(2, 0, XrefKind::Data(DataXref::Write))]
    #[case::data_read(3, 0, XrefKind::Data(DataXref::Read))]
    #[case::symbolic(6, 0, XrefKind::Data(DataXref::Symbolic))]
    fn classifies_by_type_byte(#[case] ty: u8, #[case] iscode: u8, #[case] expect: XrefKind) {
        let x = Xref::from_raw(0x1000, 0x2000, ty, iscode, 0).expect("valid edge");
        assert!(x.kind == expect);
        assert!(x.is_code() == matches!(expect, XrefKind::Code(_)));
        assert!(x.from.get() == 0x1000);
        assert!(x.to.get() == 0x2000);
    }

    /// The `user` byte maps to [`XrefOrigin`]: nonzero is a user-defined edge, zero is one IDA's
    /// analysis generated.
    #[rstest]
    #[case::analysis(0, XrefOrigin::Analysis, false)]
    #[case::user(1, XrefOrigin::User, true)]
    fn origin_reflects_user_flag(
        #[case] user: u8,
        #[case] origin: XrefOrigin,
        #[case] is_user: bool,
    ) {
        let x = Xref::from_raw(0x1000, 0x2000, 3, 0, user).expect("valid edge");
        assert!(x.origin == origin);
        assert!(x.is_user() == is_user);
    }

    /// A type byte outside the modelled set does not decode, so the iterator skips it rather
    /// than folding it into a catch-all.
    #[rstest]
    #[case::unmapped_code(99, 1)]
    #[case::unmapped_data(99, 0)]
    fn unmapped_type_is_skipped(#[case] ty: u8, #[case] iscode: u8) {
        assert!(Xref::from_raw(0x1000, 0x2000, ty, iscode, 0).is_none());
    }

    /// Every modelled variant round-trips through its raw discriminant, so a variant whose
    /// discriminant drifts from the SDK value fails here.
    #[test]
    fn every_variant_round_trips() {
        for &c in CodeXref::VARIANTS {
            assert!(CodeXref::try_from(u8::from(c)).ok() == Some(c));
        }
        for &d in DataXref::VARIANTS {
            assert!(DataXref::try_from(u8::from(d)).ok() == Some(d));
        }
    }

    /// A `BADADDR` at either endpoint is not a usable edge.
    #[test]
    fn badaddr_endpoint_is_rejected() {
        let bad = sys::BADADDR;
        assert!(Xref::from_raw(bad, 0x2000, 3, 0, 0).is_none());
        assert!(Xref::from_raw(0x1000, bad, 3, 0, 0).is_none());
    }

    /// `Xref` round-trips through JSON, including its nested `XrefKind::Code`/`XrefOrigin`.
    #[test]
    fn xref_serde_round_trips() {
        let x = Xref {
            from: Address::try_new(0x1000).expect("nonzero"),
            to: Address::try_new(0x2000).expect("nonzero"),
            kind: XrefKind::Code(CodeXref::CallNear),
            origin: XrefOrigin::User,
        };
        let json = serde_json::to_string(&x).expect("serializable");
        assert!(serde_json::from_str::<Xref>(&json).expect("deserializable") == x);
    }

    /// `XrefKind::Data` round-trips too, exercising the enum's other variant.
    #[test]
    fn xref_kind_data_serde_round_trips() {
        let kind = XrefKind::Data(DataXref::Symbolic);
        let json = serde_json::to_string(&kind).expect("serializable");
        assert!(serde_json::from_str::<XrefKind>(&json).expect("deserializable") == kind);
    }

    /// `CodeXref`'s `Display` renders a stable, human-readable label.
    #[rstest]
    #[case::unknown(CodeXref::Unknown, "unknown")]
    #[case::call_near(CodeXref::CallNear, "near call")]
    #[case::flow(CodeXref::Flow, "ordinary flow")]
    fn code_xref_display(#[case] value: CodeXref, #[case] expect: &str) {
        assert!(value.to_string() == expect);
    }

    /// `DataXref`'s `Display` renders a stable, human-readable label.
    #[rstest]
    #[case::unknown(DataXref::Unknown, "unknown")]
    #[case::write(DataXref::Write, "write")]
    #[case::symbolic(DataXref::Symbolic, "symbolic")]
    fn data_xref_display(#[case] value: DataXref, #[case] expect: &str) {
        assert!(value.to_string() == expect);
    }
}
