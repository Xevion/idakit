//! Register references in a decoded operand.
//!
//! A [`Register`] carries the processor-local register number, its class, the byte width the
//! operand selects, and the name IDA resolved for that `(number, width)` at decode time.
//! The name is baked in so a [`Register`] stays meaningful off the kernel thread -- resolving
//! it later would need a kernel call, which an owned `Send` value must never do.
//!
//! [`RegisterClass`] is idakit's own grouping (not a raw SDK enum), so its discriminants are
//! arbitrary and stable only within idakit. The x86 decoder assigns it two ways: the vector
//! and integer classes (GPR/segment/MMX/XMM/YMM/ZMM/mask/BND/IP) arrive as plain `o_reg`
//! operands and are classified by the register *number*'s range (IDA hands out e.g. `xmm0`
//! and `ymm0` as ordinary register operands, not distinct operand types), while `st`/control/
//! debug/test arrive as their own `o_idpspec*` operand types. Either way the class is a small
//! closed set, which lets the semantic [`OperandKind`](super::OperandKind) stay closed while
//! still representing every register x86 can encode.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::VariantArray;

/// The register file a [`Register`] belongs to.
///
/// A closed set: the x86 decoder maps every register it can emit into one of these, so the
/// facade never produces a value outside this range (a register in no modelled class is a
/// [`DecodeError`](super::DecodeError), not a stray discriminant). Exhaustive on purpose --
/// adding a class is a deliberate, breaking widening, pinned to the facade by an alignment test.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive, VariantArray,
)]
#[repr(u8)]
pub enum RegisterClass {
    /// General-purpose integer register (`al`/`ax`/`eax`/`rax`, ...).
    Gpr = 0,
    /// Segment register (`cs`/`ds`/`ss`/`es`/`fs`/`gs`).
    Segment = 1,
    /// 128-bit SSE/AVX vector register (`xmm0`..).
    Xmm = 2,
    /// 256-bit AVX vector register (`ymm0`..).
    Ymm = 3,
    /// 512-bit AVX-512 vector register (`zmm0`..).
    Zmm = 4,
    /// AVX-512 opmask register (`k0`..`k7`).
    Mask = 5,
    /// x87 floating-point stack register (`st0`..`st7`).
    St = 6,
    /// 64-bit MMX register (`mm0`..`mm7`).
    Mmx = 7,
    /// Control register (`cr0`..).
    Control = 8,
    /// Debug register (`dr0`..).
    Debug = 9,
    /// Test register (`tr0`..).
    Test = 10,
    /// Instruction pointer (`rip`/`eip`), as used by RIP-relative addressing.
    Ip = 11,
    /// MPX bounds register (`bnd0`..`bnd3`).
    Bnd = 12,
}

impl RegisterClass {
    /// The raw idakit RegisterClass byte.
    #[inline]
    #[must_use]
    pub fn raw(self) -> u8 {
        self.into()
    }

    /// Wrap a raw RegisterClass byte; `None` for a value this build doesn't define.
    #[inline]
    #[must_use]
    pub fn from_raw(v: u8) -> Option<Self> {
        Self::try_from(v).ok()
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use idakit_sys as sys;

    use super::*;

    #[test]
    fn raw_roundtrips_every_variant() {
        for &c in RegisterClass::VARIANTS {
            assert!(RegisterClass::from_raw(c.raw()) == Some(c));
        }
    }

    #[test]
    fn from_raw_rejects_unknown() {
        assert!(RegisterClass::from_raw(13).is_none());
        assert!(RegisterClass::from_raw(255).is_none());
    }

    // The facade fills its RegClass codes by position in this enum's declaration order, so a
    // drift between a C++ `RC_*` #define and its Rust variant surfaces as a mismatch here.
    // `idakit_reg_class_ids` is a pure constant source -- no kernel, so it runs as a unit test.
    #[test]
    fn reg_class_ids_align_with_the_facade() {
        let expected = [
            RegisterClass::Gpr,
            RegisterClass::Segment,
            RegisterClass::Xmm,
            RegisterClass::Ymm,
            RegisterClass::Zmm,
            RegisterClass::Mask,
            RegisterClass::St,
            RegisterClass::Mmx,
            RegisterClass::Control,
            RegisterClass::Debug,
            RegisterClass::Test,
            RegisterClass::Ip,
            RegisterClass::Bnd,
        ];
        assert!(expected.len() == sys::IDAKIT_REG_CLASS_COUNT);
        assert!(RegisterClass::VARIANTS.len() == expected.len());

        let mut ids = [0u8; sys::IDAKIT_REG_CLASS_COUNT];
        // SAFETY: the facade writes exactly IDAKIT_REG_CLASS_COUNT bytes.
        unsafe { sys::idakit_reg_class_ids(ids.as_mut_ptr()) };
        for (i, cls) in expected.iter().enumerate() {
            assert!(
                ids[i] == cls.raw(),
                "reg class {cls:?}: facade {} != discriminant {}",
                ids[i],
                cls.raw()
            );
        }
    }
}

/// A register reference within an operand.
///
/// `num` is the processor-local register number, meaningful together with the owning
/// [`Instruction`](super::Instruction)'s [`Isa`](super::Isa). `name` is IDA's resolved spelling for the
/// operand's width (register `0` at width 4 is `eax`, at width 8 is `rax`), copied out at
/// decode so it travels with the value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Register {
    /// Processor-local register number.
    pub num: u16,
    /// Which register file this belongs to.
    pub class: RegisterClass,
    /// Byte width the operand selects (drives which alias `name` holds).
    pub width: u8,
    /// IDA's resolved register name for `(num, width)`.
    pub name: Box<str>,
}
