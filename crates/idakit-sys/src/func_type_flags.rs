//! The typed layers over a prototype's `FTI_*` word and its parameters' `FAI_*` words.

use bitflags::bitflags;

bitflags! {
    /// A prototype's independent `func_type_data_t::flags` bits.
    ///
    /// Bits `0x00C0` are not flags but a two-bit field (`FTI_NEARCALL`, `FTI_FARCALL`, and
    /// `FTI_INTCALL`, which is the two OR-ed), so they are deliberately left unnamed here.
    /// `idakit`'s `CallType` reads that field.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias("func_type_data_t::flags"))]
    pub struct FunctionTypeFlags: u32 {
        /// The prototype carries an explicit spoiled-register list.
        #[doc(alias("FTI_SPOILED"))]
        const SPOILED = 0x0001;
        /// Does not return.
        #[doc(alias("FTI_NORET"))]
        const NO_RETURN = 0x0002;
        /// `__pure`.
        #[doc(alias("FTI_PURE"))]
        const PURE = 0x0004;
        /// A high-level prototype, which may carry hidden parameters.
        #[doc(alias("FTI_HIGH"))]
        const HIGH_LEVEL = 0x0008;
        /// `static`.
        #[doc(alias("FTI_STATIC"))]
        const STATIC = 0x0010;
        /// `virtual`.
        #[doc(alias("FTI_VIRTUAL"))]
        const VIRTUAL = 0x0020;
        /// Parameter locations, the return location, and the stack-argument size were computed.
        #[doc(alias("FTI_ARGLOCS"))]
        const LOCATIONS = 0x0100;
        /// Every parameter location is specified explicitly.
        #[doc(alias("FTI_EXPLOCS"))]
        const EXPLICIT_LOCATIONS = 0x0200;
        /// A `const` member function.
        #[doc(alias("FTI_CONST"))]
        const CONST = 0x0400;
        /// A constructor.
        #[doc(alias("FTI_CTOR"))]
        const CONSTRUCTOR = 0x0800;
        /// A destructor.
        #[doc(alias("FTI_DTOR"))]
        const DESTRUCTOR = 0x1000;
    }
}

/// The two-bit call-type field inside a raw `FTI_*` word.
#[doc(alias("FTI_CALLTYPE"))]
pub const CALL_TYPE_MASK: u32 = 0x00C0;

bitflags! {
    /// One parameter's `funcarg_t::flags`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias("funcarg_t::flags"))]
    pub struct ParameterFlags: u32 {
        /// A hidden parameter.
        #[doc(alias("FAI_HIDDEN"))]
        const HIDDEN = 0x0001;
        /// A pointer to the return value, which is hidden whether or not `HIDDEN` is set.
        #[doc(alias("FAI_RETPTR"))]
        const RETURN_POINTER = 0x0002;
        /// Lowered from a by-value structure.
        #[doc(alias("FAI_STRUCT"))]
        const STRUCT = 0x0004;
        /// Lowered from an array.
        #[doc(alias("FAI_ARRAY"))]
        const ARRAY = 0x0008;
        /// Not used by the function.
        #[doc(alias("FAI_UNUSED"))]
        const UNUSED = 0x0010;
    }
}
