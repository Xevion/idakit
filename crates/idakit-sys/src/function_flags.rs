//! Function flag bits from `funcs.hpp`: [`FUNC_NORET`], [`FUNC_LIB`], [`FUNC_THUNK`].

/// `FUNC_NORET` from `funcs.hpp`: the function does not return.
pub const FUNC_NORET: u64 = 0x0000_0001;
/// `FUNC_LIB` from `funcs.hpp`: a library function.
pub const FUNC_LIB: u64 = 0x0000_0004;
/// `FUNC_THUNK` from `funcs.hpp`: a thunk (jump) function.
pub const FUNC_THUNK: u64 = 0x0000_0080;
