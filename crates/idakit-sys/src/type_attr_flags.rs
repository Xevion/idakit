//! The typed layers over the SDK's `tattr` words, one type per owning context.
//!
//! `typeinf.hpp` reuses the same bit values across four contexts: `0x0020` is `TAUDT_MSSTRUCT` on
//! a struct, `TAFLD_BASECLASS` on a member, `TAPTR_PTR32` on a pointer, and `TAENUM_64BIT` on an
//! enum. One shared mask would let a struct answer "is this `__ptr32`" with a confident `true`, so
//! each context gets its own type and the bits never mix.
//!
//! The words as the type walk reads them (`udt_type_data_t::taudt_bits`, `udm_t::tafld_bits`,
//! `enum_type_data_t::taenum_bits`, `ptr_type_data_t::taptr_bits`) carry only the context's named
//! bits: the serialized header's alignment nibble (`MAX_DECL_ALIGN`) and `TAH_HASATTRS` are
//! consumed by the decoder. Every type still accepts any pattern (`from_bits_retain`), since each
//! crosses the FFI as a raw `u32`.

use bitflags::bitflags;

bitflags! {
    /// A struct or union's `taudt_bits`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias("taudt_bits"))]
    pub struct StructAttributes: u32 {
        /// Laid out under gcc's `ms_struct` attribute.
        #[doc(alias("TAUDT_MSSTRUCT"))]
        const MSSTRUCT = 0x0020;
        /// An unaligned struct.
        #[doc(alias("TAUDT_UNALIGNED"))]
        const UNALIGNED = 0x0040;
        /// A C++ object rather than a plain-old-data type.
        #[doc(alias("TAUDT_CPPOBJ"))]
        const CPP_OBJECT = 0x0080;
        /// A virtual function table.
        #[doc(alias("TAUDT_VFTABLE"))]
        const VFTABLE = 0x0100;
        /// Member offsets are fixed and stored in serialized form; never set on a union.
        #[doc(alias("TAUDT_FIXED"))]
        const FIXED = 0x0400;
        /// A tuple: laid out like a struct, returned differently from functions.
        #[doc(alias("TAUDT_TUPLE"))]
        const TUPLE = 0x0800;
        /// An Objective-C `@interface`.
        #[doc(alias("TAUDT_IFACE"))]
        const INTERFACE = 0x1000;
    }
}

bitflags! {
    /// A struct, union, or frame member's `tafld_bits`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias("tafld_bits"))]
    pub struct MemberAttributes: u32 {
        /// A base-class subobject: inherited rather than included as a named field.
        #[doc(alias("TAFLD_BASECLASS"))]
        const BASE_CLASS = 0x0020;
        /// An unaligned member.
        #[doc(alias("TAFLD_UNALIGNED"))]
        const UNALIGNED = 0x0040;
        /// A virtual base, which the SDK documents as not yet supported.
        #[doc(alias("TAFLD_VIRTBASE"))]
        const VIRTUAL_BASE = 0x0080;
        /// A pointer to the virtual function table.
        #[doc(alias("TAFLD_VFTABLE"))]
        const VFTABLE = 0x0100;
        /// A member function.
        #[doc(alias("TAFLD_METHOD"))]
        const METHOD = 0x0200;
        /// A gap IDA synthesized as padding, shown as such in type details.
        #[doc(alias("TAFLD_GAP"))]
        const GAP = 0x0400;
        /// The member's comment is regular; clear means repeatable.
        #[doc(alias("TAFLD_REGCMT"))]
        const REGULAR_COMMENT = 0x0800;
        /// A frame's return-address slot.
        #[doc(alias("TAFLD_FRAME_R"))]
        const RETURN_ADDRESS = 0x1000;
        /// A frame's saved-registers slot.
        #[doc(alias("TAFLD_FRAME_S"))]
        const SAVED_REGISTERS = 0x2000;
        /// Created by the type system rather than declared.
        #[doc(alias("TAFLD_BYTIL"))]
        const FROM_TYPE_SYSTEM = 0x4000;
    }
}

bitflags! {
    /// An enum's `taenum_bits`.
    ///
    /// `OCTAL`/`BINARY`/`SIGNED_DISPLAY` only mean anything when the enum's output radix is hex,
    /// and at most one of `OCTAL`/`BINARY` is set.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias("taenum_bits"))]
    pub struct EnumAttributes: u32 {
        /// Values are stored as 64-bit.
        #[doc(alias("TAENUM_64BIT"))]
        const VALUES_64BIT = 0x0020;
        /// Declared unsigned.
        #[doc(alias("TAENUM_UNSIGNED"))]
        const UNSIGNED = 0x0040;
        /// Declared signed.
        #[doc(alias("TAENUM_SIGNED"))]
        const SIGNED = 0x0080;
        /// Shown in octal.
        #[doc(alias("TAENUM_OCT"))]
        const OCTAL = 0x0100;
        /// Shown in binary.
        #[doc(alias("TAENUM_BIN"))]
        const BINARY = 0x0200;
        /// Shown with a sign.
        #[doc(alias("TAENUM_NUMSIGN"))]
        const SIGNED_DISPLAY = 0x0400;
        /// Shown with leading zeros.
        #[doc(alias("TAENUM_LZERO"))]
        const LEADING_ZEROS = 0x0800;
    }
}

bitflags! {
    /// A pointer's `taptr_bits`.
    ///
    /// Bits `0x0060` are not flags but a two-bit field (`TAPTR_PTR32`, `TAPTR_PTR64`, and
    /// `TAPTR_RESTRICT`, which is the two OR-ed), so they are deliberately left unnamed here.
    /// `idakit`'s `PointerModifier` reads that field; the bits survive in the raw word.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias("taptr_bits"))]
    pub struct PointerAttributes: u32 {
        /// A `__shifted(parent, delta)` pointer into a parent struct.
        #[doc(alias("TAPTR_SHIFTED"))]
        const SHIFTED = 0x0080;
    }
}

/// The two-bit pointer-modifier field inside a [`PointerAttributes`] word.
pub const POINTER_MODIFIER_MASK: u32 = 0x0060;

#[cfg(test)]
mod tests {
    use assert2::assert;
    use proptest::prelude::*;

    use super::*;

    /// The four contexts reuse bit values, so only the names and their counts differ.
    #[test]
    fn contexts_share_bit_values_but_not_types() {
        assert!(StructAttributes::MSSTRUCT.bits() == MemberAttributes::BASE_CLASS.bits());
        assert!(MemberAttributes::BASE_CLASS.bits() == EnumAttributes::VALUES_64BIT.bits());
        assert!(PointerAttributes::all().bits() & POINTER_MODIFIER_MASK == 0);
    }

    proptest! {
        #[test]
        fn from_bits_retain_round_trips_every_bit_pattern(raw: u32) {
            prop_assert_eq!(StructAttributes::from_bits_retain(raw).bits(), raw);
            prop_assert_eq!(MemberAttributes::from_bits_retain(raw).bits(), raw);
            prop_assert_eq!(EnumAttributes::from_bits_retain(raw).bits(), raw);
            prop_assert_eq!(PointerAttributes::from_bits_retain(raw).bits(), raw);
        }
    }
}
