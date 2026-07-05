//! Register references in a decoded operand.
//!
//! A [`Register`] carries the processor-local register number, its class, the byte width the
//! operand selects, and the name IDA resolved for that `(number, width)` at decode time.
//! The name is baked in so a [`Register`] stays meaningful off the kernel thread -- resolving
//! it later would need a kernel call, which an owned `Send` value must never do.
//!
//! [`RegisterClass`] is idakit's own grouping (not a raw SDK enum), so its discriminants are
//! arbitrary and stable only within idakit. The x86 decoder assigns it: the SIMD and
//! special classes fall straight out of the operand's raw type byte (IDA encodes YMM/ZMM/
//! mask/st/mmx/control/debug/test as distinct `o_idpspec*` types), which is what lets the
//! semantic [`OperandKind`](super::OperandKind) stay a small closed set while still
//! representing every register x86 can encode.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::VariantArray;

/// The register file a [`Register`] belongs to.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive, VariantArray,
)]
#[repr(u8)]
#[non_exhaustive]
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
