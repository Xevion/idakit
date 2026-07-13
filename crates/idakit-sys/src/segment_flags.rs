//! The typed [`SegPerm`] layer over `segment.hpp`'s `SEGPERM_*` permission bits.

use std::ffi::c_int;

use bitflags::bitflags;

bitflags! {
    /// Segment permission bits from `segment.hpp` (`SEGPERM_EXEC`/`SEGPERM_WRITE`/`SEGPERM_READ`).
    ///
    /// Accepts any bit pattern (`from_bits_retain`), so it is sound to lift straight from
    /// `get_segm_attr(SEGATTR_PERM)`'s raw byte, which may carry bits this type does not name.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    #[doc(alias("SEGPERM_EXEC", "SEGPERM_WRITE", "SEGPERM_READ"))]
    pub struct SegPerm: c_int {
        /// The segment is executable (`SEGPERM_EXEC`).
        #[doc(alias("SEGPERM_EXEC"))]
        const EXEC = 1;
        /// The segment is writable (`SEGPERM_WRITE`).
        #[doc(alias("SEGPERM_WRITE"))]
        const WRITE = 2;
        /// The segment is readable (`SEGPERM_READ`).
        #[doc(alias("SEGPERM_READ"))]
        const READ = 4;
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn flags_pin_the_raw_sdk_values() {
        assert!(SegPerm::EXEC.bits() == 1);
        assert!(SegPerm::WRITE.bits() == 2);
        assert!(SegPerm::READ.bits() == 4);
    }

    #[test]
    fn from_bits_retain_preserves_unknown_bits() {
        let raw = SegPerm::READ.bits() | 0x10;
        let perm = SegPerm::from_bits_retain(raw);
        assert!(perm.contains(SegPerm::READ));
        assert!(perm.bits() == raw);
    }
}
