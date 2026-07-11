//! Mirrors IDA's operand-value-type byte as the closed [`OperandDataType`] enum.
//!
//! Discriminants are the raw values IDA reports for each type, so the `IntoPrimitive`/
//! `TryFromPrimitive` derives are the single source of truth for the mapping. This mirror
//! is pinned to one IDA version, where that set is fixed, so the enum is exhaustive and an
//! alignment test ties it to the facade. A later version that grows the set is a
//! deliberate, breaking widening. An out-of-domain value decodes to
//! [`DecodeError::UnsupportedDataType`](super::DecodeError), never a silent fallback.
//!
//! `data_type` is the *value* type, distinct from the addressing-mode size, since a float
//! and a dword are both four bytes but differ here. This is exactly why the operand keeps
//! `data_type` rather than only a byte count.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::VariantArray;

/// The value type of an operand.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive, VariantArray,
)]
#[repr(u8)]
#[doc(alias("op_dtype_t"))]
pub enum OperandDataType {
    /// 8-bit integer.
    #[doc(alias("dt_byte"))]
    Byte = 0,
    /// 16-bit integer.
    #[doc(alias("dt_word"))]
    Word = 1,
    /// 32-bit integer.
    #[doc(alias("dt_dword"))]
    Dword = 2,
    /// 4-byte floating point.
    #[doc(alias("dt_float"))]
    Float = 3,
    /// 8-byte floating point.
    #[doc(alias("dt_double"))]
    Double = 4,
    /// Variable-size floating point (its width depends on the processor).
    #[doc(alias("dt_tbyte"))]
    Tbyte = 5,
    /// Packed real (mc68040).
    #[doc(alias("dt_packreal"))]
    PackReal = 6,
    /// 64-bit integer.
    #[doc(alias("dt_qword"))]
    Qword = 7,
    /// 128-bit integer.
    #[doc(alias("dt_byte16"))]
    Byte16 = 8,
    /// Pointer to code.
    #[doc(alias("dt_code"))]
    Code = 9,
    /// No value type.
    #[doc(alias("dt_void"))]
    Void = 10,
    /// 48-bit.
    #[doc(alias("dt_fword"))]
    Fword = 11,
    /// Bit field (mc680x0).
    #[doc(alias("dt_bitfild"))]
    BitField = 12,
    /// Pointer to an ASCIIZ string.
    #[doc(alias("dt_string"))]
    String = 13,
    /// Pointer to a Unicode string.
    #[doc(alias("dt_unicode"))]
    Unicode = 14,
    /// Long double, which may differ from [`Tbyte`](Self::Tbyte).
    #[doc(alias("dt_ldbl"))]
    Ldbl = 15,
    /// 256-bit integer.
    #[doc(alias("dt_byte32"))]
    Byte32 = 16,
    /// 512-bit integer.
    #[doc(alias("dt_byte64"))]
    Byte64 = 17,
    /// 2-byte floating point.
    #[doc(alias("dt_half"))]
    Half = 18,
}

impl OperandDataType {
    /// Fixed byte width, when the type has one.
    ///
    /// `None` for variable-size ([`Tbyte`](Self::Tbyte), [`Ldbl`](Self::Ldbl),
    /// [`PackReal`](Self::PackReal)), pointer ([`Code`](Self::Code), [`String`](Self::String),
    /// [`Unicode`](Self::Unicode)), or sizeless ([`Void`](Self::Void), [`BitField`](Self::BitField))
    /// types, whose true size is processor- or context-dependent and can't be answered off the
    /// kernel thread.
    #[must_use]
    pub fn bytes(self) -> Option<u32> {
        Some(match self {
            OperandDataType::Byte => 1,
            OperandDataType::Word | OperandDataType::Half => 2,
            OperandDataType::Dword | OperandDataType::Float => 4,
            OperandDataType::Fword => 6,
            OperandDataType::Double | OperandDataType::Qword => 8,
            OperandDataType::Byte16 => 16,
            OperandDataType::Byte32 => 32,
            OperandDataType::Byte64 => 64,
            _ => return None,
        })
    }

    /// Whether this is a floating-point value type.
    #[inline]
    #[must_use]
    pub fn is_float(self) -> bool {
        matches!(
            self,
            OperandDataType::Float
                | OperandDataType::Double
                | OperandDataType::Tbyte
                | OperandDataType::Ldbl
                | OperandDataType::Half
        )
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use idakit_sys as sys;

    use super::*;

    #[test]
    fn raw_roundtrips_every_variant() {
        for &d in OperandDataType::VARIANTS {
            assert!(OperandDataType::try_from(u8::from(d)).ok() == Some(d));
        }
    }

    // Pin the mirror to the facade's reported values: the facade reports each type in this
    // enum's discriminant order, so a header change (or a mistyped discriminant) mismatches.
    // Pure constant source, no kernel, so it runs as a unit test.
    #[test]
    fn dtype_ids_align_with_the_facade() {
        let ids = sys::op_dtype_ids();
        assert!(ids.len() == OperandDataType::VARIANTS.len());
        for (i, &d) in OperandDataType::VARIANTS.iter().enumerate() {
            assert!(
                ids[i] == u8::from(d),
                "data type {d:?}: facade dt_ {} != discriminant {}",
                ids[i],
                u8::from(d)
            );
        }
    }

    #[test]
    fn try_from_rejects_unknown() {
        assert!(OperandDataType::try_from(19).is_err());
        assert!(OperandDataType::try_from(255).is_err());
    }

    #[test]
    fn fixed_sizes_match_the_isa() {
        assert!(OperandDataType::Byte.bytes() == Some(1));
        assert!(OperandDataType::Qword.bytes() == Some(8));
        assert!(OperandDataType::Byte16.bytes() == Some(16));
        assert!(OperandDataType::Half.bytes() == Some(2));
        // Variable / pointer / sizeless types report no fixed width.
        assert!(OperandDataType::Tbyte.bytes().is_none());
        assert!(OperandDataType::Code.bytes().is_none());
        assert!(OperandDataType::Void.bytes().is_none());
    }

    #[test]
    fn float_classification() {
        assert!(OperandDataType::Float.is_float());
        assert!(OperandDataType::Half.is_float());
        assert!(OperandDataType::Ldbl.is_float());
        assert!(!OperandDataType::Dword.is_float());
        assert!(!OperandDataType::Qword.is_float());
    }
}
