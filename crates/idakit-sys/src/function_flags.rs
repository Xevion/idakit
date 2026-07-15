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

    use super::*;

    #[test]
    fn flags_pin_the_raw_sdk_values() {
        assert!(FuncFlags::NORET.bits() == 0x0000_0001);
        assert!(FuncFlags::FAR.bits() == 0x0000_0002);
        assert!(FuncFlags::LIB.bits() == 0x0000_0004);
        assert!(FuncFlags::STATICDEF.bits() == 0x0000_0008);
        assert!(FuncFlags::FRAME.bits() == 0x0000_0010);
        assert!(FuncFlags::USERFAR.bits() == 0x0000_0020);
        assert!(FuncFlags::HIDDEN.bits() == 0x0000_0040);
        assert!(FuncFlags::THUNK.bits() == 0x0000_0080);
        assert!(FuncFlags::BOTTOMBP.bits() == 0x0000_0100);
        assert!(FuncFlags::NORET_PENDING.bits() == 0x0000_0200);
        assert!(FuncFlags::SP_READY.bits() == 0x0000_0400);
        assert!(FuncFlags::FUZZY_SP.bits() == 0x0000_0800);
        assert!(FuncFlags::PROLOG_OK.bits() == 0x0000_1000);
        assert!(FuncFlags::PURGED_OK.bits() == 0x0000_4000);
        assert!(FuncFlags::TAIL.bits() == 0x0000_8000);
        assert!(FuncFlags::LUMINA.bits() == 0x0001_0000);
        assert!(FuncFlags::OUTLINE.bits() == 0x0002_0000);
        assert!(FuncFlags::REANALYZE.bits() == 0x0004_0000);
        assert!(FuncFlags::UNWIND.bits() == 0x0008_0000);
        assert!(FuncFlags::CATCH.bits() == 0x0010_0000);
        assert!(FuncFlags::RESERVED.bits() == 0x8000_0000_0000_0000);
    }

    #[test]
    fn from_bits_retain_preserves_unknown_bits() {
        let raw = FuncFlags::LIB.bits() | 0x0020_0000;
        let flags = FuncFlags::from_bits_retain(raw);
        assert!(flags.contains(FuncFlags::LIB));
        assert!(flags.bits() == raw);
    }
}
