//! The per-context type attributes, `StructAttributes` and its siblings, and the values decoded
//! from them.
//!
//! IDA's `tattr` bits mean different things by owning context (`0x0020` is `MSSTRUCT` on a
//! struct, `BASE_CLASS` on a member, `__ptr32` on a pointer), so each context has its own mask
//! type, defined in `idakit-sys` and re-exported here. Where a mask packs a field rather than
//! flags, or one fact spans a bit and a value, the fact is decoded beside the raw mask:
//! [`PointerModifier`] reads the pointer word's two-bit field, and [`Comment`] pairs a member's
//! comment text with the `REGULAR_COMMENT` bit that gives its kind. The raw masks stay the escape
//! hatch beneath both.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use strum::VariantArray;

pub use idakit_sys::{EnumAttributes, MemberAttributes, PointerAttributes, StructAttributes};

use super::TypeId;

/// A member comment and its kind, which IDA stores as one fact across two fields.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[doc(alias("udm_t::cmt"))]
pub struct Comment {
    /// The comment text.
    pub text: String,
    /// Whether the comment is regular or repeatable.
    pub kind: CommentKind,
}

/// Whether a comment is regular or repeatable.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum CommentKind {
    /// A regular comment (`TAFLD_REGCMT` set).
    #[doc(alias("TAFLD_REGCMT"))]
    Regular,
    /// A repeatable comment, the SDK's default (`TAFLD_REGCMT` clear).
    Repeatable,
}

impl Comment {
    /// The comment a member carries, kind taken from its attribute word; `None` when it has none.
    pub(crate) fn from_member(text: &str, attributes: MemberAttributes) -> Option<Self> {
        (!text.is_empty()).then(|| Self {
            text: text.to_owned(),
            kind: if attributes.contains(MemberAttributes::REGULAR_COMMENT) {
                CommentKind::Regular
            } else {
                CommentKind::Repeatable
            },
        })
    }
}

/// A struct or union's layout beyond its total size, which [`TypeValue::size`](super::TypeValue)
/// already carries.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize)]
#[doc(alias("udt_type_data_t"))]
pub struct StructLayout {
    /// Size in bytes without trailing padding; the gap to the total size is that padding.
    pub unpadded_size: u64,
    /// The alignment IDA computed for the aggregate, in bytes.
    #[doc(alias("effalign"))]
    pub effective_alignment: u32,
    /// The declared alignment in bytes (`alignas`/`__declspec(align)`), or `None` when unspecified.
    #[doc(alias("sda"))]
    pub declared_alignment: Option<u32>,
    /// The raw `#pragma pack` value, or `None` when unset.
    ///
    /// Left undecoded: the SDK documents it both as a shift amount and with examples that only fit
    /// a shift-plus-one encoding, so a byte count read from it would be a guess.
    pub pack: Option<u8>,
}

impl StructLayout {
    /// The layout from the walk's raw fields: `sda` is a shift plus one (0 when unspecified), and a
    /// zero `pack` means none.
    pub(crate) fn from_raw(
        unpadded_size: u64,
        effective_alignment: u32,
        declared_alignment_shift: u32,
        pack: u32,
    ) -> Self {
        Self {
            unpadded_size,
            effective_alignment,
            declared_alignment: declared_alignment_shift
                .checked_sub(1)
                .and_then(|shift| 1u32.checked_shl(shift)),
            pack: u8::try_from(pack).ok().filter(|&p| p != 0),
        }
    }
}

/// A pointer's MSVC width or aliasing modifier.
///
/// The two-bit field at `0x0060` of a [`PointerAttributes`] word. `Restrict` is both bits set, so
/// it is a value of the field rather than a combination of the other two. A plain pointer has
/// neither bit and reads as no modifier.
// raw TAPTR_* values from typeinf.hpp (IDA 9.3)
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Serialize,
    Deserialize,
    TryFromPrimitive,
    IntoPrimitive,
    VariantArray,
)]
#[repr(u32)]
pub enum PointerModifier {
    /// `__ptr32`.
    #[doc(alias("TAPTR_PTR32"))]
    Ptr32 = 0x0020,
    /// `__ptr64`.
    #[doc(alias("TAPTR_PTR64"))]
    Ptr64 = 0x0040,
    /// `__restrict`.
    #[doc(alias("TAPTR_RESTRICT"))]
    Restrict = 0x0060,
}

impl PointerModifier {
    /// The modifier a pointer word carries, or `None` for a plain pointer.
    #[must_use]
    pub fn from_attributes(attributes: PointerAttributes) -> Option<Self> {
        Self::try_from(attributes.bits() & idakit_sys::POINTER_MODIFIER_MASK).ok()
    }
}

/// Where a `__shifted(parent, delta)` pointer points from.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[doc(alias("TAPTR_SHIFTED"))]
pub struct ShiftedPointer {
    /// The struct the pointer is shifted into.
    pub parent: TypeId,
    /// The pointer's byte offset from the start of `parent`.
    pub delta: i32,
}

/// `#[serde(with)]` adapters carrying each mask as its raw `u32`, since the masks are defined in
/// `idakit-sys`, which has no serde.
macro_rules! serde_bits {
    ($($module:ident: $ty:ty;)*) => {$(
        pub(crate) mod $module {
            use serde::{Deserialize, Deserializer, Serializer};

            // serde's `with` contract fixes the by-reference receiver, Copy or not.
            #[allow(clippy::trivially_copy_pass_by_ref)]
            pub(crate) fn serialize<S: Serializer>(f: &$ty, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_u32(f.bits())
            }

            pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<$ty, D::Error> {
                u32::deserialize(d).map(<$ty>::from_bits_retain)
            }
        }
    )*};
}

serde_bits! {
    struct_bits: idakit_sys::StructAttributes;
    member_bits: idakit_sys::MemberAttributes;
    pointer_bits: idakit_sys::PointerAttributes;
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use idakit_sys as sys;
    use rstest::rstest;

    use super::*;

    /// Pin each mask to the facade's SDK bits: the facade names every `TA*_*` constant in
    /// declaration order, so a header renumbering or a flag added on one side alone fails here.
    #[rstest]
    #[case::structs(sys::struct_attribute_ids(), StructAttributes::all().iter().map(|f| f.bits()).collect())]
    #[case::members(sys::member_attribute_ids(), MemberAttributes::all().iter().map(|f| f.bits()).collect())]
    #[case::enums(sys::enum_attribute_ids(), EnumAttributes::all().iter().map(|f| f.bits()).collect())]
    #[case::pointers(sys::pointer_attribute_ids(), PointerAttributes::all().iter().map(|f| f.bits()).collect())]
    fn attribute_ids_align_with_the_facade(#[case] facade: Vec<u32>, #[case] ours: Vec<u32>) {
        assert!(facade == ours);
    }

    #[test]
    fn pointer_modifier_ids_align_with_the_facade() {
        let ids = sys::pointer_modifier_ids();
        assert!(ids.len() == PointerModifier::VARIANTS.len());
        for (&id, &variant) in ids.iter().zip(PointerModifier::VARIANTS) {
            assert!(id == u32::from(variant), "{variant:?}");
        }
    }

    /// The modifier field is read whole: `Restrict` is the two bits together, and the flag bits
    /// beside the field never change the answer.
    #[rstest]
    #[case::plain(0x0000, None)]
    #[case::ptr32(0x0020, Some(PointerModifier::Ptr32))]
    #[case::ptr64(0x0040, Some(PointerModifier::Ptr64))]
    #[case::restrict(0x0060, Some(PointerModifier::Restrict))]
    #[case::shifted_plain(0x0080, None)]
    #[case::shifted_restrict(0x00E0, Some(PointerModifier::Restrict))]
    fn modifier_reads_only_its_field(#[case] raw: u32, #[case] expect: Option<PointerModifier>) {
        let attributes = PointerAttributes::from_bits_retain(raw);
        assert!(PointerModifier::from_attributes(attributes) == expect);
    }

    #[rstest]
    #[case::unspecified(0, None)]
    #[case::byte(1, Some(1))]
    #[case::eight(4, Some(8))]
    #[case::page(13, Some(4096))]
    #[case::overflow(40, None)]
    fn declared_alignment_decodes_shift_plus_one(#[case] sda: u32, #[case] bytes: Option<u32>) {
        assert!(StructLayout::from_raw(0, 0, sda, 0).declared_alignment == bytes);
    }

    #[rstest]
    #[case::regular(MemberAttributes::REGULAR_COMMENT, CommentKind::Regular)]
    #[case::repeatable(MemberAttributes::empty(), CommentKind::Repeatable)]
    fn comment_kind_follows_the_regcmt_bit(
        #[case] attributes: MemberAttributes,
        #[case] kind: CommentKind,
    ) {
        assert!(let Some(Comment { kind: k, .. }) = Comment::from_member("note", attributes));
        assert!(k == kind);
    }

    #[test]
    fn empty_comment_text_is_no_comment() {
        assert!(Comment::from_member("", MemberAttributes::REGULAR_COMMENT).is_none());
    }
}
