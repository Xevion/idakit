//! The typed [`FuncFlags`] layer over `funcs.hpp`'s `func_t::flags` bits.

use bitflags::bitflags;

bitflags! {
    /// Function flag bits from `funcs.hpp` (`func_t::flags`).
    ///
    /// Accepts any bit pattern (`from_bits_retain`), so it is sound to lift straight from
    /// `func_flags`'s raw `u64`, which may carry bits this type does not name.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    #[doc(alias(
        "FUNC_NORET", "FUNC_FAR", "FUNC_LIB", "FUNC_STATICDEF", "FUNC_FRAME", "FUNC_USERFAR",
        "FUNC_HIDDEN", "FUNC_THUNK", "FUNC_BOTTOMBP", "FUNC_NORET_PENDING", "FUNC_SP_READY",
        "FUNC_FUZZY_SP", "FUNC_PROLOG_OK", "FUNC_PURGED_OK", "FUNC_TAIL", "FUNC_LUMINA",
        "FUNC_OUTLINE", "FUNC_REANALYZE", "FUNC_UNWIND", "FUNC_CATCH", "FUNC_RESERVED"
    ))]
    pub struct FuncFlags: u64 {
        /// The function does not return (`FUNC_NORET`).
        #[doc(alias("FUNC_NORET"))]
        const NORET = 0x0000_0001;
        /// A far function (`FUNC_FAR`).
        #[doc(alias("FUNC_FAR"))]
        const FAR = 0x0000_0002;
        /// A library function (`FUNC_LIB`).
        #[doc(alias("FUNC_LIB"))]
        const LIB = 0x0000_0004;
        /// A static function (`FUNC_STATICDEF`).
        #[doc(alias("FUNC_STATICDEF"))]
        const STATICDEF = 0x0000_0008;
        /// The function uses a frame pointer, BP (`FUNC_FRAME`).
        #[doc(alias("FUNC_FRAME"))]
        const FRAME = 0x0000_0010;
        /// The user has specified the function's far-ness (`FUNC_USERFAR`).
        #[doc(alias("FUNC_USERFAR"))]
        const USERFAR = 0x0000_0020;
        /// A hidden function chunk (`FUNC_HIDDEN`).
        #[doc(alias("FUNC_HIDDEN"))]
        const HIDDEN = 0x0000_0040;
        /// A thunk, jump function (`FUNC_THUNK`).
        #[doc(alias("FUNC_THUNK"))]
        const THUNK = 0x0000_0080;
        /// BP points to the bottom of the stack frame (`FUNC_BOTTOMBP`).
        #[doc(alias("FUNC_BOTTOMBP"))]
        const BOTTOMBP = 0x0000_0100;
        /// Non-return analysis is still pending (`FUNC_NORET_PENDING`).
        #[doc(alias("FUNC_NORET_PENDING"))]
        const NORET_PENDING = 0x0000_0200;
        /// SP analysis has been performed (`FUNC_SP_READY`).
        #[doc(alias("FUNC_SP_READY"))]
        const SP_READY = 0x0000_0400;
        /// The function changes SP in an untraceable way (`FUNC_FUZZY_SP`).
        #[doc(alias("FUNC_FUZZY_SP"))]
        const FUZZY_SP = 0x0000_0800;
        /// Prolog analysis has been performed (`FUNC_PROLOG_OK`).
        #[doc(alias("FUNC_PROLOG_OK"))]
        const PROLOG_OK = 0x0000_1000;
        /// The `argsize` field has been validated (`FUNC_PURGED_OK`).
        #[doc(alias("FUNC_PURGED_OK"))]
        const PURGED_OK = 0x0000_4000;
        /// This is a function tail (`FUNC_TAIL`).
        #[doc(alias("FUNC_TAIL"))]
        const TAIL = 0x0000_8000;
        /// Function info is provided by Lumina (`FUNC_LUMINA`).
        #[doc(alias("FUNC_LUMINA"))]
        const LUMINA = 0x0001_0000;
        /// Outlined code, not a real function (`FUNC_OUTLINE`).
        #[doc(alias("FUNC_OUTLINE"))]
        const OUTLINE = 0x0002_0000;
        /// The function frame changed, request to reanalyze (`FUNC_REANALYZE`).
        #[doc(alias("FUNC_REANALYZE"))]
        const REANALYZE = 0x0004_0000;
        /// The function is an exception unwind handler (`FUNC_UNWIND`).
        #[doc(alias("FUNC_UNWIND"))]
        const UNWIND = 0x0008_0000;
        /// The function is an exception catch handler (`FUNC_CATCH`).
        #[doc(alias("FUNC_CATCH"))]
        const CATCH = 0x0010_0000;
        /// Reserved for internal use (`FUNC_RESERVED`).
        #[doc(alias("FUNC_RESERVED"))]
        const RESERVED = 0x8000_0000_0000_0000;
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::noret(FuncFlags::NORET, 0x0000_0001)]
    #[case::far(FuncFlags::FAR, 0x0000_0002)]
    #[case::lib(FuncFlags::LIB, 0x0000_0004)]
    #[case::staticdef(FuncFlags::STATICDEF, 0x0000_0008)]
    #[case::frame(FuncFlags::FRAME, 0x0000_0010)]
    #[case::userfar(FuncFlags::USERFAR, 0x0000_0020)]
    #[case::hidden(FuncFlags::HIDDEN, 0x0000_0040)]
    #[case::thunk(FuncFlags::THUNK, 0x0000_0080)]
    #[case::bottombp(FuncFlags::BOTTOMBP, 0x0000_0100)]
    #[case::noret_pending(FuncFlags::NORET_PENDING, 0x0000_0200)]
    #[case::sp_ready(FuncFlags::SP_READY, 0x0000_0400)]
    #[case::fuzzy_sp(FuncFlags::FUZZY_SP, 0x0000_0800)]
    #[case::prolog_ok(FuncFlags::PROLOG_OK, 0x0000_1000)]
    #[case::purged_ok(FuncFlags::PURGED_OK, 0x0000_4000)]
    #[case::tail(FuncFlags::TAIL, 0x0000_8000)]
    #[case::lumina(FuncFlags::LUMINA, 0x0001_0000)]
    #[case::outline(FuncFlags::OUTLINE, 0x0002_0000)]
    #[case::reanalyze(FuncFlags::REANALYZE, 0x0004_0000)]
    #[case::unwind(FuncFlags::UNWIND, 0x0008_0000)]
    #[case::catch(FuncFlags::CATCH, 0x0010_0000)]
    #[case::reserved(FuncFlags::RESERVED, 0x8000_0000_0000_0000)]
    fn flags_pin_the_raw_sdk_values(#[case] flag: FuncFlags, #[case] raw: u64) {
        assert!(flag.bits() == raw);
    }

    proptest! {
        #[test]
        fn from_bits_retain_round_trips_every_bit_pattern(raw: u64) {
            prop_assert_eq!(FuncFlags::from_bits_retain(raw).bits(), raw);
        }

        #[test]
        fn union_and_intersection_are_raw_bitwise_ops(a: u64, b: u64) {
            let (fa, fb) = (FuncFlags::from_bits_retain(a), FuncFlags::from_bits_retain(b));
            prop_assert_eq!((fa | fb).bits(), a | b);
            prop_assert_eq!((fa & fb).bits(), a & b);
        }

        #[test]
        fn complement_truncates_to_the_known_flag_mask(a: u64) {
            let fa = FuncFlags::from_bits_retain(a);
            prop_assert_eq!((!fa).bits(), !a & FuncFlags::all().bits());
        }
    }
}
