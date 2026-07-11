//! Flow-chart flag bits from `gdl.hpp`: [`FC_NOEXT`], [`FC_CALL_ENDS`], [`FC_NOPREDS`].

use std::ffi::c_int;

/// `FC_NOEXT` from `gdl.hpp`: omit external blocks (jump targets outside the function).
pub const FC_NOEXT: c_int = 0x0002;
/// `FC_CALL_ENDS` from `gdl.hpp`: call instructions terminate a basic block.
pub const FC_CALL_ENDS: c_int = 0x0020;
/// `FC_NOPREDS` from `gdl.hpp`: skip predecessor-list computation.
pub const FC_NOPREDS: c_int = 0x0040;
