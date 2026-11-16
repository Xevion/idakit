//! The typed layer over a decompiled local's `lvar_t::flags` word.

use bitflags::bitflags;

bitflags! {
    /// A decompiled local variable's `CVAR_*` property bits.
    ///
    /// `lvar_t` keeps the word private, so the facade rebuilds it from the SDK's own accessors.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias("lvar_t::flags"))]
    pub struct LocalFlags: u32 {
        /// Used in the code.
        #[doc(alias("CVAR_USED"))]
        const USED = 0x0000_0001;
        /// Has a defined type.
        #[doc(alias("CVAR_TYPE"))]
        const TYPED = 0x0000_0002;
        /// Has a meaningful name rather than a synthesized one.
        #[doc(alias("CVAR_NAME"))]
        const NICE_NAME = 0x0000_0004;
        /// Microcode register substitution is done for it.
        #[doc(alias("CVAR_MREG"))]
        const MREG_DONE = 0x0000_0008;
        /// Its width is unknown.
        #[doc(alias("CVAR_NOWD"))]
        const UNKNOWN_WIDTH = 0x0000_0010;
        /// Named by the user.
        #[doc(alias("CVAR_UNAME"))]
        const USER_NAME = 0x0000_0020;
        /// Typed by the user.
        #[doc(alias("CVAR_UTYPE"))]
        const USER_TYPE = 0x0000_0040;
        /// The function's result variable.
        #[doc(alias("CVAR_RESULT"))]
        const RESULT = 0x0000_0080;
        /// A function argument.
        #[doc(alias("CVAR_ARG"))]
        const ARGUMENT = 0x0000_0100;
        /// A fake variable: the return variable or a `va_list`.
        #[doc(alias("CVAR_FAKE"))]
        const FAKE = 0x0000_0200;
        /// Overlaps another variable.
        #[doc(alias("CVAR_OVER"))]
        const OVERLAPPED = 0x0000_0400;
        /// Used in an FPU instruction.
        #[doc(alias("CVAR_FLOAT"))]
        const FLOATING = 0x0000_0800;
        /// Spoiled; the SDK marks this bit internal.
        #[doc(alias("CVAR_SPOILED"))]
        const SPOILED = 0x0000_1000;
        /// Other variables are mapped onto this one.
        #[doc(alias("CVAR_MAPDST"))]
        const MAPPING_TARGET = 0x0000_2000;
        /// Its type is only partially defined.
        #[doc(alias("CVAR_PARTIAL"))]
        const PARTIALLY_TYPED = 0x0000_4000;
        /// The `this` argument of a C++ member function.
        #[doc(alias("CVAR_THISARG"))]
        const THIS_ARGUMENT = 0x0000_8000;
        /// Created by an explicit split request rather than reused.
        #[doc(alias("CVAR_SPLIT"))]
        const SPLIT = 0x0001_0000;
        /// Has a register name (like `_RAX`), from use by an `m_ext` instruction.
        #[doc(alias("CVAR_REGNAME"))]
        const REGISTER_NAME = 0x0002_0000;
        /// Cannot be a pointer, by the user's choice.
        #[doc(alias("CVAR_NOPTR"))]
        const NOT_POINTER = 0x0004_0000;
        /// A dummy argument filling a hole in the argument list.
        #[doc(alias("CVAR_DUMMY"))]
        const DUMMY_ARGUMENT = 0x0008_0000;
        /// Cannot be an input argument.
        #[doc(alias("CVAR_NOTARG"))]
        const NOT_ARGUMENT = 0x0010_0000;
        /// Mapped automatically.
        #[doc(alias("CVAR_AUTOMAP"))]
        const AUTO_MAPPED = 0x0020_0000;
        /// Its address was taken.
        #[doc(alias("CVAR_BYREF"))]
        const BY_REFERENCE = 0x0040_0000;
        /// Used in instructions translated into `__asm {...}`.
        #[doc(alias("CVAR_INASM"))]
        const IN_ASM = 0x0080_0000;
        /// Declared `__unused` by the user; meaningful only on an argument before final typing.
        #[doc(alias("CVAR_UNUSED"))]
        const DECLARED_UNUSED = 0x0100_0000;
        /// Mapped to several value chains.
        #[doc(alias("CVAR_SHARED"))]
        const SHARED = 0x0200_0000;
        /// A stack argument transformed from a scattered one.
        #[doc(alias("CVAR_SCARG"))]
        const SCATTERED_ARGUMENT = 0x0400_0000;
        /// Forbidden from propagation.
        #[doc(alias("CVAR_NOPROP"))]
        const NO_PROPAGATION = 0x0800_0000;
    }
}
