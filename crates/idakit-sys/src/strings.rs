//! STRTYPE field masks from `nalt.hpp`: [`STRWIDTH_MASK`], [`STRLYT_MASK`], [`STRLYT_SHIFT`].

use std::ffi::c_int;

/// `STRWIDTH_MASK` from `nalt.hpp`: the STRTYPE bits selecting bytes-per-character.
pub const STRWIDTH_MASK: c_int = 0x03;
/// `STRLYT_MASK` from `nalt.hpp`: the STRTYPE bits selecting the layout (terminated vs Pascal).
pub const STRLYT_MASK: c_int = 0xFC;
/// `STRLYT_SHIFT` from `nalt.hpp`: right-shift applied to the [`STRLYT_MASK`] field.
pub const STRLYT_SHIFT: c_int = 2;
