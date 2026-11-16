//! A function's [`CallingConvention`] and the surgery return-code mapper `sig_result`.

use std::ffi::c_int;
use std::fmt;

use idakit_sys::SigWriteCode;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use strum::VariantArray;

use crate::address::Address;
use crate::error::Result;
use crate::ffi::reason_or;
use crate::types::TypeWriteError;

/// Maps a surgery return code, the current arity, and any captured reason to a crate [`Result`],
/// the shared tail of the [`FunctionEdit`](super::FunctionEdit) surgery verbs. `arg` is
/// `Some((index, arity))` for the index-taking verbs, so an out-of-range code names both.
/// [`SigWriteCode`] is the closed set; an unmodelled code names itself in the message rather than
/// silently landing on a generic reason, so a facade drift shows up immediately instead of only
/// in the reason text.
pub(super) fn sig_result(
    code: c_int,
    address: Address,
    arg: Option<(usize, usize)>,
    reason: &str,
) -> Result<()> {
    match SigWriteCode::try_from(code) {
        Ok(SigWriteCode::Ok) => Ok(()),
        Ok(SigWriteCode::NoPrototype) => Err(TypeWriteError::NoPrototype {
            address: address.get(),
        }
        .into()),
        Ok(SigWriteCode::ArgRange) => {
            let (index, arity) = arg.unwrap_or_default();
            Err(TypeWriteError::ArgIndexOutOfRange {
                address: address.get(),
                index,
                arity,
            }
            .into())
        }
        Ok(SigWriteCode::Build) => Err(TypeWriteError::BuildFailed {
            reason: reason_or(
                reason,
                "an unknown named type or invalid declaration within it",
            ),
        }
        .into()),
        Ok(SigWriteCode::Apply) => Err(TypeWriteError::ApplyRejected {
            address: address.get(),
            reason: reason_or(reason, "the kernel rejected the edited signature"),
        }
        .into()),
        Err(_) => Err(TypeWriteError::ApplyRejected {
            address: address.get(),
            reason: reason_or(
                reason,
                &format!(
                    "the kernel rejected the edited signature (unexpected facade code {code})"
                ),
            ),
        }
        .into()),
    }
}

/// A function's calling convention, decoded from IDA's `callcnv_t`.
///
/// `callcnv_t` is a layered `u32`, not a closed enum (`typeinf.hpp`, IDA 9.3). Below `0x100` the
/// high nibble names the convention and the low nibble is zero, except in the two ranges the SDK
/// reserves for variations: ellipsis conventions (`0x40..=0x4F`) and usercall conventions
/// (`0xD0..=0xFF`). `0x100` is Go's stack convention, and `0x200` up is an open range of plain
/// custom conventions. `CM_CC_INVALID`, the `__spoil` marker `0xA0..=0xAF`, and the internal
/// `CM_CC_RESERVE3` are not conventions, so [`TryFrom<u32>`] rejects them along with every other
/// code the header leaves unassigned.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[doc(alias("callcnv_t", "cm_t", "CM_CC_MASK"))]
pub enum CallingConvention {
    /// Unknown or unspecified (`CM_CC_UNKNOWN`).
    #[doc(alias("CM_CC_UNKNOWN"))]
    Unknown,
    /// A function taking no arguments (`CM_CC_VOIDARG`).
    #[doc(alias("CM_CC_VOIDARG"))]
    VoidArg,
    /// `__cdecl`: caller-cleaned stack (`CM_CC_CDECL`).
    #[doc(alias("CM_CC_CDECL"))]
    Cdecl,
    /// `__cdecl` with an ellipsis (`CM_CC_ELLIPSIS`), or one of its variations.
    #[doc(alias("CM_CC_ELLIPSIS"))]
    Ellipsis {
        /// The low nibble, 0 for plain `CM_CC_ELLIPSIS`.
        variation: u8,
    },
    /// `__stdcall`: callee-cleaned stack (`CM_CC_STDCALL`).
    #[doc(alias("CM_CC_STDCALL"))]
    Stdcall,
    /// `__pascal`: callee-cleaned, reversed argument order (`CM_CC_PASCAL`).
    #[doc(alias("CM_CC_PASCAL"))]
    Pascal,
    /// `__fastcall`: leading arguments in registers (`CM_CC_FASTCALL`).
    #[doc(alias("CM_CC_FASTCALL"))]
    Fastcall,
    /// `__thiscall`: the `this` pointer in a register (`CM_CC_THISCALL`).
    #[doc(alias("CM_CC_THISCALL"))]
    Thiscall,
    /// Swift: arguments and results in registers (`CM_CC_SWIFT`).
    #[doc(alias("CM_CC_SWIFT"))]
    Swift,
    /// Go: arguments and results in registers or on the stack by version (`CM_CC_GOLANG`).
    #[doc(alias("CM_CC_GOLANG"))]
    Golang,
    /// `__usercall` and its variants: every argument location is explicit.
    #[doc(alias("CM_CC_SPECIAL"))]
    UserCall {
        /// Which usercall convention.
        kind: UserCallKind,
        /// The low nibble, 0 for the plain code.
        variation: u8,
    },
    /// Go with arguments and results on the stack (`CM_CC_GOSTK`).
    #[doc(alias("CM_CC_GOSTK"))]
    GoStack,
    /// A plain custom convention, from the open range at `CM_CC_FIRST_PLAIN_CUSTOM` up.
    #[doc(alias("CM_CC_FIRST_PLAIN_CUSTOM"))]
    Custom(u32),
}

/// Which of the three usercall conventions a [`CallingConvention::UserCall`] is.
// raw CM_CC_* values from typeinf.hpp (IDA 9.3)
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Serialize,
    Deserialize,
    TryFromPrimitive,
    IntoPrimitive,
    VariantArray,
)]
#[repr(u32)]
pub enum UserCallKind {
    /// With an ellipsis (`CM_CC_SPECIALE`).
    #[doc(alias("CM_CC_SPECIALE"))]
    Ellipsis = 0xD0,
    /// With a callee-purged stack (`CM_CC_SPECIALP`).
    #[doc(alias("CM_CC_SPECIALP"))]
    Purged = 0xE0,
    /// The plain usercall (`CM_CC_SPECIAL`).
    #[doc(alias("CM_CC_SPECIAL"))]
    Plain = 0xF0,
}

/// A raw `callcnv_t` that names no calling convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCallingConvention {
    /// The rejected code.
    pub raw: u32,
}

impl fmt::Display for InvalidCallingConvention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x} is not a calling convention", self.raw)
    }
}

impl std::error::Error for InvalidCallingConvention {}

impl CallingConvention {
    const GO_STACK: u32 = 0x100;
    const FIRST_PLAIN_CUSTOM: u32 = 0x200;

    /// Whether every argument location is explicit, as in `__usercall`.
    #[inline]
    #[must_use]
    #[doc(alias("is_user_cc"))]
    pub const fn is_usercall(self) -> bool {
        matches!(self, Self::UserCall { .. })
    }

    /// Whether the convention takes a variable argument list.
    #[inline]
    #[must_use]
    #[doc(alias("is_vararg_cc"))]
    pub const fn is_vararg(self) -> bool {
        matches!(
            self,
            Self::Ellipsis { .. }
                | Self::UserCall {
                    kind: UserCallKind::Ellipsis,
                    ..
                }
        )
    }

    /// Whether the callee cleans its stack arguments on return. Only meaningful for x86.
    #[inline]
    #[must_use]
    #[doc(alias("is_purging_cc"))]
    pub const fn is_purging(self) -> bool {
        matches!(
            self,
            Self::Stdcall
                | Self::Pascal
                | Self::Fastcall
                | Self::Thiscall
                | Self::Swift
                | Self::UserCall {
                    kind: UserCallKind::Purged,
                    ..
                }
        )
    }

    /// Whether this is one of Go's conventions.
    #[inline]
    #[must_use]
    #[doc(alias("is_golang_cc"))]
    pub const fn is_golang(self) -> bool {
        matches!(self, Self::Golang | Self::GoStack)
    }
}

impl TryFrom<u32> for CallingConvention {
    type Error = InvalidCallingConvention;

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        let invalid = InvalidCallingConvention { raw };
        if raw >= Self::FIRST_PLAIN_CUSTOM {
            return Ok(Self::Custom(raw));
        }
        if raw == Self::GO_STACK {
            return Ok(Self::GoStack);
        }
        if raw > 0xFF {
            return Err(invalid);
        }
        let (base, variation) = (raw & 0xF0, (raw & 0x0F) as u8);
        if let Ok(kind) = UserCallKind::try_from(base) {
            return Ok(Self::UserCall { kind, variation });
        }
        if base == 0x40 {
            return Ok(Self::Ellipsis { variation });
        }
        if variation != 0 {
            return Err(invalid);
        }
        Ok(match base {
            0x10 => Self::Unknown,
            0x20 => Self::VoidArg,
            0x30 => Self::Cdecl,
            0x50 => Self::Stdcall,
            0x60 => Self::Pascal,
            0x70 => Self::Fastcall,
            0x80 => Self::Thiscall,
            0x90 => Self::Swift,
            0xB0 => Self::Golang,
            _ => return Err(invalid),
        })
    }
}

impl From<CallingConvention> for u32 {
    fn from(cc: CallingConvention) -> Self {
        match cc {
            CallingConvention::Unknown => 0x10,
            CallingConvention::VoidArg => 0x20,
            CallingConvention::Cdecl => 0x30,
            CallingConvention::Ellipsis { variation } => 0x40 | Self::from(variation & 0x0F),
            CallingConvention::Stdcall => 0x50,
            CallingConvention::Pascal => 0x60,
            CallingConvention::Fastcall => 0x70,
            CallingConvention::Thiscall => 0x80,
            CallingConvention::Swift => 0x90,
            CallingConvention::Golang => 0xB0,
            CallingConvention::UserCall { kind, variation } => {
                Self::from(kind) | Self::from(variation & 0x0F)
            }
            CallingConvention::GoStack => CallingConvention::GO_STACK,
            CallingConvention::Custom(raw) => raw,
        }
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use idakit_sys as sys;
    use rstest::rstest;

    use super::*;

    /// The codec over the header's own `CM_CC_*` constants: the facade lists them in a fixed order
    /// and this table says what each must decode to, so a renumbered constant or a codec that
    /// drifts from the header fails here. Kernel-free.
    #[test]
    fn cm_cc_ids_align_with_the_facade() {
        use CallingConvention as C;
        let expected: &[Option<C>] = &[
            Some(C::Unknown),
            Some(C::VoidArg),
            Some(C::Cdecl),
            Some(C::Ellipsis { variation: 0 }),
            Some(C::Stdcall),
            Some(C::Pascal),
            Some(C::Fastcall),
            Some(C::Thiscall),
            Some(C::Swift),
            Some(C::Golang),
            Some(C::UserCall {
                kind: UserCallKind::Ellipsis,
                variation: 0,
            }),
            Some(C::UserCall {
                kind: UserCallKind::Purged,
                variation: 0,
            }),
            Some(C::UserCall {
                kind: UserCallKind::Plain,
                variation: 0,
            }),
            Some(C::UserCall {
                kind: UserCallKind::Plain,
                variation: 0xF,
            }),
            Some(C::GoStack),
            Some(C::Custom(0x200)),
            // CM_CC_INVALID, CM_CC_SPOILED, CM_CC_RESERVE3: not conventions.
            None,
            None,
            None,
        ];
        let ids = sys::cm_cc_ids();
        assert!(
            ids.len() == expected.len(),
            "facade lists {} codes",
            ids.len()
        );
        for (&raw, want) in ids.iter().zip(expected) {
            assert!(
                CallingConvention::try_from(raw).ok() == *want,
                "code {raw:#x}"
            );
        }
    }

    #[rstest]
    #[case::ellipsis_variation(0x4A, true, false)]
    #[case::usercall_ellipsis_variation(0xD3, true, false)]
    #[case::usercall_purged(0xE0, false, true)]
    #[case::stdcall(0x50, false, true)]
    #[case::cdecl(0x30, false, false)]
    fn predicates_follow_the_sdk_ranges(
        #[case] raw: u32,
        #[case] vararg: bool,
        #[case] purging: bool,
    ) {
        let cc = CallingConvention::try_from(raw).expect("a convention");
        assert!(cc.is_vararg() == vararg);
        assert!(cc.is_purging() == purging);
    }

    #[rstest]
    #[case::invalid(0x00)]
    #[case::spoiled(0xA0)]
    #[case::spoiled_count(0xA3)]
    #[case::reserved(0xC0)]
    #[case::stray_nibble(0x31)]
    #[case::between_gostack_and_custom(0x101)]
    #[case::below_custom(0x1FF)]
    fn non_conventions_are_rejected(#[case] raw: u32) {
        assert!(CallingConvention::try_from(raw) == Err(InvalidCallingConvention { raw }));
    }

    /// `sig_result` classifies every surgery return code, kernel-free: only `SigWriteCode::Ok`
    /// maps to success, and no code panics regardless of the captured reason or arg pair.
    #[test]
    fn sig_result_classifies_every_known_code() {
        use idakit_sys::{SIG_APPLY, SIG_ARG_RANGE, SIG_BUILD, SIG_NO_PROTOTYPE, SIG_OK};

        let address = Address::new_const(0x1000);
        assert!(sig_result(SIG_OK, address, None, "").is_ok());
        assert!(let Err(_) = sig_result(SIG_NO_PROTOTYPE, address, None, ""));
        assert!(let Err(_) = sig_result(SIG_ARG_RANGE, address, Some((3, 2)), ""));
        assert!(let Err(_) = sig_result(SIG_BUILD, address, None, ""));
        assert!(let Err(_) = sig_result(SIG_APPLY, address, None, "kernel said no"));
    }

    mod proptests {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            // Every code the codec accepts encodes back to itself, so the two directions agree on
            // the whole accepted set.
            #[test]
            fn accepted_codes_round_trip(raw in any::<u32>()) {
                if let Ok(cc) = CallingConvention::try_from(raw) {
                    prop_assert_eq!(u32::from(cc), raw);
                }
            }

            // Across the full i32 domain: exactly the SIG_OK code succeeds, every other code
            // (modelled or not) is a rejection, and the mapper never panics on any bit pattern.
            #[test]
            fn sig_result_only_ok_succeeds(code in any::<i32>(), reason in ".*") {
                let address = Address::new_const(0x1000);
                let result = sig_result(code, address, Some((0, 1)), &reason);
                prop_assert_eq!(result.is_ok(), code == idakit_sys::SIG_OK);
            }
        }
    }
}
