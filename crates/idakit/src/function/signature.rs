//! A function's [`CallingConvention`] and the surgery return-code mapper [`sig_result`].

use std::ffi::c_int;

use idakit_sys::SigWriteCode;
use num_enum::{IntoPrimitive, TryFromPrimitive};
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

/// A function's calling convention: the plain register/stack conventions surgery can set.
///
/// A curated closed set mirroring the settable `CM_CC_*` conventions from `typeinf.hpp`
/// (IDA 9.3), idakit's own semantic layer over IDA's open convention byte. It omits the
/// usercall/special and custom conventions (which carry explicit argument locations), the ellipsis
/// convention (varargs is a [`function`](crate::types::expr::function) builder flag), and the
/// spoiled-registers marker.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    TryFromPrimitive,
    IntoPrimitive,
    VariantArray,
)]
#[repr(u8)]
#[doc(alias("cm_t", "CM_CC_MASK"))]
pub enum CallingConvention {
    /// Unknown or unspecified (`CM_CC_UNKNOWN`).
    Unknown = 0x10,
    /// `__cdecl`: caller-cleaned stack (`CM_CC_CDECL`).
    Cdecl = 0x30,
    /// `__stdcall`: callee-cleaned stack (`CM_CC_STDCALL`).
    Stdcall = 0x50,
    /// `__pascal`: callee-cleaned, reversed argument order (`CM_CC_PASCAL`).
    Pascal = 0x60,
    /// `__fastcall`: leading arguments in registers (`CM_CC_FASTCALL`).
    Fastcall = 0x70,
    /// `__thiscall`: the `this` pointer in a register (`CM_CC_THISCALL`).
    Thiscall = 0x80,
    /// Swift: arguments and results in registers (`CM_CC_SWIFT`).
    Swift = 0x90,
    /// Go: arguments and results in registers or on the stack by version (`CM_CC_GOLANG`).
    Golang = 0xB0,
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    /// Every `CallingConvention` round-trips its byte, so a drifted value fails here rather than
    /// silently setting the wrong convention at the facade.
    #[test]
    fn calling_convention_round_trips() {
        for &cc in CallingConvention::VARIANTS {
            assert!(CallingConvention::try_from(u8::from(cc)).ok() == Some(cc));
        }
        // A byte outside the curated set is rejected, not absorbed.
        assert!(CallingConvention::try_from(0x20u8).is_err());
    }

    /// Each discriminant is pinned to the raw `CM_CC_*` code (typeinf.hpp, IDA 9.3).
    #[rstest]
    #[case(CallingConvention::Unknown, 0x10)]
    #[case(CallingConvention::Cdecl, 0x30)]
    #[case(CallingConvention::Stdcall, 0x50)]
    #[case(CallingConvention::Pascal, 0x60)]
    #[case(CallingConvention::Fastcall, 0x70)]
    #[case(CallingConvention::Thiscall, 0x80)]
    #[case(CallingConvention::Swift, 0x90)]
    #[case(CallingConvention::Golang, 0xB0)]
    fn calling_convention_pins_cm_cc(#[case] cc: CallingConvention, #[case] raw: u8) {
        assert!(u8::from(cc) == raw);
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
