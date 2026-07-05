//! Operand value types, mirroring IDA's `op_dtype_t`.
//!
//! Discriminants are the raw `dt_*` values from `ua.hpp`, so the `IntoPrimitive`/
//! `TryFromPrimitive` derives are the single source of truth for the SDK mapping. This mirror
//! is pinned to one IDA minor (9.3): the `dt_*` set is fixed there, so the enum is exhaustive
//! and an alignment test ties it to the facade. A later SDK that grows the set (as 9.x grew
//! `dt_half`) is a deliberate, breaking widening -- an out-of-domain value decodes to
//! [`DecodeError::UnsupportedDataType`](super::DecodeError), never a silent fallback.
//!
//! `data_type` is the *value* type, distinct from the addressing-mode size: `dt_float` and
//! `dt_dword` are both four bytes but differ here, which is exactly why the operand keeps
//! the data_type rather than only a byte count.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::VariantArray;

/// The value type of an operand (IDA `op_dtype_t`).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive, VariantArray,
)]
#[repr(u8)]
pub enum DataType {
    /// 8-bit integer.
    Byte = 0,
    /// 16-bit integer.
    Word = 1,
    /// 32-bit integer.
    Dword = 2,
    /// 4-byte floating point.
    Float = 3,
    /// 8-byte floating point.
    Double = 4,
    /// Variable-size floating point (`ph.tbyte_size`).
    Tbyte = 5,
    /// Packed real (mc68040).
    PackReal = 6,
    /// 64-bit integer.
    Qword = 7,
    /// 128-bit integer.
    Byte16 = 8,
    /// Pointer to code.
    Code = 9,
    /// No value type.
    Void = 10,
    /// 48-bit.
    Fword = 11,
    /// Bit field (mc680x0).
    BitField = 12,
    /// Pointer to an ASCIIZ string.
    String = 13,
    /// Pointer to a Unicode string.
    Unicode = 14,
    /// Long double, which may differ from [`Tbyte`](Self::Tbyte).
    Ldbl = 15,
    /// 256-bit integer.
    Byte32 = 16,
    /// 512-bit integer.
    Byte64 = 17,
    /// 2-byte floating point.
    Half = 18,
}

impl DataType {
    /// Fixed byte width, when the type has one. `None` for variable-size
    /// ([`Tbyte`](Self::Tbyte), [`Ldbl`](Self::Ldbl), [`PackReal`](Self::PackReal)),
    /// pointer ([`Code`](Self::Code), [`String`](Self::String), [`Unicode`](Self::Unicode)),
    /// or sizeless ([`Void`](Self::Void), [`BitField`](Self::BitField)) types, whose true
    /// size is processor- or context-dependent and can't be answered off the kernel thread.
    #[must_use]
    pub fn bytes(self) -> Option<u32> {
        Some(match self {
            DataType::Byte => 1,
            DataType::Word | DataType::Half => 2,
            DataType::Dword | DataType::Float => 4,
            DataType::Fword => 6,
            DataType::Double | DataType::Qword => 8,
            DataType::Byte16 => 16,
            DataType::Byte32 => 32,
            DataType::Byte64 => 64,
            _ => return None,
        })
    }

    /// Whether this is a floating-point value type.
    #[inline]
    #[must_use]
    pub fn is_float(self) -> bool {
        matches!(
            self,
            DataType::Float | DataType::Double | DataType::Tbyte | DataType::Ldbl | DataType::Half
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
        for &d in DataType::VARIANTS {
            assert!(DataType::try_from(u8::from(d)).ok() == Some(d));
        }
    }

    // Pin the mirror to this SDK's `op_dtype_t` values: the facade reports each `dt_*` in this
    // enum's discriminant order, so a header change (or a mistyped discriminant) mismatches.
    // Pure constant source -- no kernel, so it runs as a unit test.
    #[test]
    fn dtype_ids_align_with_the_facade() {
        assert!(DataType::VARIANTS.len() == sys::IDAKIT_OP_DTYPE_COUNT);
        let mut ids = [0u8; sys::IDAKIT_OP_DTYPE_COUNT];
        // SAFETY: the facade writes exactly IDAKIT_OP_DTYPE_COUNT bytes.
        unsafe { sys::idakit_op_dtype_ids(ids.as_mut_ptr()) };
        for (i, &d) in DataType::VARIANTS.iter().enumerate() {
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
        assert!(DataType::try_from(19).is_err());
        assert!(DataType::try_from(255).is_err());
    }

    #[test]
    fn fixed_sizes_match_the_isa() {
        assert!(DataType::Byte.bytes() == Some(1));
        assert!(DataType::Qword.bytes() == Some(8));
        assert!(DataType::Byte16.bytes() == Some(16));
        assert!(DataType::Half.bytes() == Some(2));
        // Variable / pointer / sizeless types report no fixed width.
        assert!(DataType::Tbyte.bytes().is_none());
        assert!(DataType::Code.bytes().is_none());
        assert!(DataType::Void.bytes().is_none());
    }

    #[test]
    fn float_classification() {
        assert!(DataType::Float.is_float());
        assert!(DataType::Half.is_float());
        assert!(DataType::Ldbl.is_float());
        assert!(!DataType::Dword.is_float());
        assert!(!DataType::Qword.is_float());
    }
}
