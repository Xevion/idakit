//! The typed [`SegPerm`]/[`SegFlags`] layers over `segment.hpp`'s `SEGPERM_*`/`SFL_*` bit masks.

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

bitflags! {
    /// Segment flag bits from `segment.hpp` (`SFL_*`, `segment_t::flags`).
    ///
    /// Accepts any bit pattern (`from_bits_retain`), so it is sound to lift straight from the raw
    /// `flags` word, which may carry bits this type does not name.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    #[doc(alias("SFL_COMORG", "SFL_OBOK", "SFL_HIDDEN", "SFL_DEBUG", "SFL_LOADER", "SFL_HIDETYPE", "SFL_HEADER"))]
    pub struct SegFlags: c_int {
        /// IDP-dependent: the ORG directive is not commented out (`SFL_COMORG`).
        #[doc(alias("SFL_COMORG"))]
        const COMORG = 0x01;
        /// The `orgbase` field is present (`SFL_OBOK`).
        #[doc(alias("SFL_OBOK"))]
        const OBOK = 0x02;
        /// The segment is hidden from the disassembly listing (`SFL_HIDDEN`).
        #[doc(alias("SFL_HIDDEN"))]
        const HIDDEN = 0x04;
        /// The segment was created for the debugger, temporary (`SFL_DEBUG`).
        #[doc(alias("SFL_DEBUG"))]
        const DEBUG = 0x08;
        /// The segment was created by a loader (`SFL_LOADER`).
        #[doc(alias("SFL_LOADER"))]
        const LOADER = 0x10;
        /// The segment's type is hidden in the listing (`SFL_HIDETYPE`).
        #[doc(alias("SFL_HIDETYPE"))]
        const HIDETYPE = 0x20;
        /// A header segment: no offsets are created into it (`SFL_HEADER`).
        #[doc(alias("SFL_HEADER"))]
        const HEADER = 0x40;
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

    #[test]
    fn seg_flags_pin_the_raw_sdk_values() {
        assert!(SegFlags::COMORG.bits() == 0x01);
        assert!(SegFlags::OBOK.bits() == 0x02);
        assert!(SegFlags::HIDDEN.bits() == 0x04);
        assert!(SegFlags::DEBUG.bits() == 0x08);
        assert!(SegFlags::LOADER.bits() == 0x10);
        assert!(SegFlags::HIDETYPE.bits() == 0x20);
        assert!(SegFlags::HEADER.bits() == 0x40);
    }

    #[test]
    fn seg_flags_from_bits_retain_preserves_unknown_bits() {
        let raw = SegFlags::HIDDEN.bits() | 0x1000;
        let flags = SegFlags::from_bits_retain(raw);
        assert!(flags.contains(SegFlags::HIDDEN));
        assert!(flags.bits() == raw);
    }
}
