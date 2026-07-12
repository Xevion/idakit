//! Segment permission bits from `segment.hpp`: [`SEGPERM_EXEC`], [`SEGPERM_WRITE`], [`SEGPERM_READ`].

use std::ffi::c_int;

/// `SEGPERM_EXEC` from `segment.hpp`: the segment is executable.
pub const SEGPERM_EXEC: c_int = 1;
/// `SEGPERM_WRITE` from `segment.hpp`: the segment is writable.
pub const SEGPERM_WRITE: c_int = 2;
/// `SEGPERM_READ` from `segment.hpp`: the segment is readable.
pub const SEGPERM_READ: c_int = 4;
