//! The typed layer over a ctree expression's `cexpr_t::exflags` word.

use bitflags::bitflags;

bitflags! {
    /// A ctree expression's `EXFL_*` property bits.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias("cexpr_t::exflags"))]
    pub struct ExpressionFlags: u32 {
        /// Pointer-arithmetic correction is done.
        #[doc(alias("EXFL_CPADONE"))]
        const POINTER_ARITHMETIC_DONE = 0x0001;
        /// An lvalue even though it doesn't look like one.
        #[doc(alias("EXFL_LVALUE"))]
        const ODD_LVALUE = 0x0002;
        /// A floating-point operation; the only way to tell a float comparison from an integer one.
        #[doc(alias("EXFL_FPOP"))]
        const FLOATING_POINT = 0x0004;
        /// A standalone helper call; the SDK names no predicate for it.
        #[doc(alias("EXFL_ALONE"))]
        const STANDALONE = 0x0008;
        /// A string literal.
        #[doc(alias("EXFL_CSTR"))]
        const STRING_LITERAL = 0x0010;
        /// Its type is considered partial.
        #[doc(alias("EXFL_PARTIAL"))]
        const PARTIAL_TYPE = 0x0020;
        /// Uses an undefined value.
        #[doc(alias("EXFL_UNDEF"))]
        const UNDEFINED_VALUE = 0x0040;
        /// A jump out of the function.
        #[doc(alias("EXFL_JUMPOUT"))]
        const JUMP_OUT = 0x0080;
        /// A pointer to a virtual function table, on a member pointer or reference.
        #[doc(alias("EXFL_VFTABLE"))]
        const VFTABLE = 0x0100;
    }
}
