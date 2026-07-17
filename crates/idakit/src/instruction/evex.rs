//! EVEX modifiers on an AVX-512 [`Instruction`](super::Instruction): write-masking and embedded
//! floating-point control.
//!
//! An EVEX-encoded instruction can carry a write-mask ([`Masking`]) and, in its register-operand
//! form, an embedded FP control ([`FpControl`]) selecting a static rounding mode or exception
//! suppression. IDA stores both in a slot shaped like a sixth operand, which is why a naive decode
//! surfaces the mask as a phantom operand; these types lift that data to where it belongs, on the
//! instruction rather than in its operand list. Embedded broadcast (`{1toN}`) is the third EVEX
//! modifier and lives on the memory operand it decorates, as [`Memory::broadcast`](super::Memory::broadcast).
//!
//! All three are x86-specific: EVEX is an x86 encoding, so these are populated only by the x86/x64
//! decoder and are `None` under any other processor.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

use super::register::Register;

/// The EVEX write-masking applied to an instruction's destination.
///
/// Present when an AVX-512 instruction selects an opmask (`k1`..`k7`); `k0` encodes "no mask" and
/// yields `None` rather than a `Masking`. The mask gates which destination lanes the instruction
/// writes, and [`zeroing`](Self::zeroing) picks what happens to the masked-off lanes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Masking {
    /// The opmask register (`k1`..`k7`) selecting which lanes are written.
    pub register: Register,
    /// `true` for zeroing-masking (`{z}`, masked-off lanes are zeroed), `false` for
    /// merging-masking (masked-off lanes keep their previous value).
    pub zeroing: bool,
}

/// The embedded floating-point control on a register-form EVEX instruction.
///
/// Present only on the register-operand form (`EVEX.b` set with no memory operand). Both variants
/// suppress floating-point exceptions; they differ in whether the instruction also overrides the
/// rounding mode. A memory-form `EVEX.b` is embedded broadcast instead, carried on the operand as
/// [`Memory::broadcast`](super::Memory::broadcast).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FpControl {
    /// Static rounding-control (`{rn-sae}`/`{rd-sae}`/`{ru-sae}`/`{rz-sae}`): the instruction
    /// rounds by `mode` and suppresses exceptions.
    Rounding {
        /// The overriding rounding mode.
        mode: RoundMode,
    },
    /// Suppress-all-exceptions only (`{sae}`): exceptions are suppressed with no rounding
    /// override, for instructions that do not round.
    SuppressExceptions,
}

/// An EVEX static rounding mode, from an [`FpControl::Rounding`].
///
/// Mirrors the two-bit rounding-control field an EVEX prefix embeds. The discriminants match that
/// field's encoding, pinned to the facade in a unit test.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive, Serialize, Deserialize,
)]
#[repr(u8)]
pub enum RoundMode {
    /// Round to nearest (ties to even).
    Nearest = 0,
    /// Round toward negative infinity.
    Down = 1,
    /// Round toward positive infinity.
    Up = 2,
    /// Round toward zero (truncate).
    Zero = 3,
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use idakit_sys as sys;

    use super::*;

    // The RoundMode discriminants mirror the facade's ROUND_* codes (the raw two-bit EVEX
    // rounding-control field), so decode's `try_from(round_mode)` lands on the right variant; a
    // drift here would silently remap rounding modes.
    #[test]
    fn round_mode_discriminants_pin_the_facade() {
        assert!(u8::from(RoundMode::Nearest) == sys::ROUND_NEAREST);
        assert!(u8::from(RoundMode::Down) == sys::ROUND_DOWN);
        assert!(u8::from(RoundMode::Up) == sys::ROUND_UP);
        assert!(u8::from(RoundMode::Zero) == sys::ROUND_ZERO);
    }

    #[test]
    fn round_mode_try_from_rejects_out_of_range() {
        assert!(RoundMode::try_from(4).is_err());
        assert!(RoundMode::try_from(255).is_err());
    }
}
