//! Operand value types, mirroring IDA's `op_dtype_t`.
//!
//! Discriminants are the raw `dt_*` values from `ua.hpp` (IDA 9.3), so the
//! `IntoPrimitive`/`TryFromPrimitive` derives are the single source of truth for the SDK
//! mapping. `#[non_exhaustive]` because a future SDK may add a value (as 9.x already grew
//! `dt_half`); a new data_type should widen this, not break every `match`.
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
#[non_exhaustive]
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
    /// The raw `op_dtype_t` byte.
    #[inline]
    #[must_use]
    pub fn raw(self) -> u8 {
        self.into()
    }

    /// Wrap a raw `op_dtype_t`; `None` for a value this SDK build doesn't define.
    #[inline]
    #[must_use]
    pub fn from_raw(v: u8) -> Option<Self> {
        Self::try_from(v).ok()
    }

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

    use super::*;

    #[test]
    fn raw_roundtrips_every_variant() {
        for &d in DataType::VARIANTS {
            assert!(DataType::from_raw(d.raw()) == Some(d));
        }
    }

    #[test]
    fn from_raw_rejects_unknown() {
        assert!(DataType::from_raw(19).is_none());
        assert!(DataType::from_raw(255).is_none());
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
