//! Operand value types, mirroring IDA's `op_dtype_t`.
//!
//! Discriminants are the raw `dt_*` values from `ua.hpp` (IDA 9.3), so the
//! `IntoPrimitive`/`TryFromPrimitive` derives are the single source of truth for the SDK
//! mapping. `#[non_exhaustive]` because a future SDK may add a value (as 9.x already grew
//! `dt_half`); a new dtype should widen this, not break every `match`.
//!
//! `dtype` is the *value* type, distinct from the addressing-mode size: `dt_float` and
//! `dt_dword` are both four bytes but differ here, which is exactly why the operand keeps
//! the dtype rather than only a byte count.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::VariantArray;

/// The value type of an operand (IDA `op_dtype_t`).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive, VariantArray,
)]
#[repr(u8)]
#[non_exhaustive]
pub enum Dtype {
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

impl Dtype {
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
            Dtype::Byte => 1,
            Dtype::Word | Dtype::Half => 2,
            Dtype::Dword | Dtype::Float => 4,
            Dtype::Fword => 6,
            Dtype::Double | Dtype::Qword => 8,
            Dtype::Byte16 => 16,
            Dtype::Byte32 => 32,
            Dtype::Byte64 => 64,
            _ => return None,
        })
    }

    /// Whether this is a floating-point value type.
    #[inline]
    #[must_use]
    pub fn is_float(self) -> bool {
        matches!(
            self,
            Dtype::Float | Dtype::Double | Dtype::Tbyte | Dtype::Ldbl | Dtype::Half
        )
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn raw_roundtrips_every_variant() {
        for &d in Dtype::VARIANTS {
            assert!(Dtype::from_raw(d.raw()) == Some(d));
        }
    }

    #[test]
    fn from_raw_rejects_unknown() {
        assert!(Dtype::from_raw(19).is_none());
        assert!(Dtype::from_raw(255).is_none());
    }

    #[test]
    fn fixed_sizes_match_the_isa() {
        assert!(Dtype::Byte.bytes() == Some(1));
        assert!(Dtype::Qword.bytes() == Some(8));
        assert!(Dtype::Byte16.bytes() == Some(16));
        assert!(Dtype::Half.bytes() == Some(2));
        // Variable / pointer / sizeless types report no fixed width.
        assert!(Dtype::Tbyte.bytes().is_none());
        assert!(Dtype::Code.bytes().is_none());
        assert!(Dtype::Void.bytes().is_none());
    }

    #[test]
    fn float_classification() {
        assert!(Dtype::Float.is_float());
        assert!(Dtype::Half.is_float());
        assert!(Dtype::Ldbl.is_float());
        assert!(!Dtype::Dword.is_float());
        assert!(!Dtype::Qword.is_float());
    }
}
