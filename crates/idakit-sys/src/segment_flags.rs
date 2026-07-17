//! The typed [`SegmentPermissions`]/[`SegmentFlags`] layers over `segment.hpp`'s
//! `SEGPERM_*`/`SFL_*` bit masks.

use std::ffi::c_int;

use bitflags::bitflags;

bitflags! {
    /// Segment permission bits from `segment.hpp` (`SEGPERM_EXEC`/`SEGPERM_WRITE`/`SEGPERM_READ`).
    ///
    /// Accepts any bit pattern (`from_bits_retain`), so it is sound to lift straight from
    /// `get_segm_attr(SEGATTR_PERM)`'s raw byte, which may carry bits this type does not name.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    #[doc(alias("SEGPERM_EXEC", "SEGPERM_WRITE", "SEGPERM_READ"))]
    pub struct SegmentPermissions: c_int {
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
    pub struct SegmentFlags: c_int {
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
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::exec(SegmentPermissions::EXEC, 1)]
    #[case::write(SegmentPermissions::WRITE, 2)]
    #[case::read(SegmentPermissions::READ, 4)]
    fn flags_pin_the_raw_sdk_values(#[case] flag: SegmentPermissions, #[case] raw: c_int) {
        assert!(flag.bits() == raw);
    }

    #[rstest]
    #[case::comorg(SegmentFlags::COMORG, 0x01)]
    #[case::obok(SegmentFlags::OBOK, 0x02)]
    #[case::hidden(SegmentFlags::HIDDEN, 0x04)]
    #[case::debug(SegmentFlags::DEBUG, 0x08)]
    #[case::loader(SegmentFlags::LOADER, 0x10)]
    #[case::hidetype(SegmentFlags::HIDETYPE, 0x20)]
    #[case::header(SegmentFlags::HEADER, 0x40)]
    fn seg_flags_pin_the_raw_sdk_values(#[case] flag: SegmentFlags, #[case] raw: c_int) {
        assert!(flag.bits() == raw);
    }

    proptest! {
        #[test]
        fn seg_perm_from_bits_retain_round_trips_every_bit_pattern(raw: c_int) {
            prop_assert_eq!(SegmentPermissions::from_bits_retain(raw).bits(), raw);
        }

        #[test]
        fn seg_perm_union_and_intersection_are_raw_bitwise_ops(a: c_int, b: c_int) {
            let (fa, fb) = (SegmentPermissions::from_bits_retain(a), SegmentPermissions::from_bits_retain(b));
            prop_assert_eq!((fa | fb).bits(), a | b);
            prop_assert_eq!((fa & fb).bits(), a & b);
        }

        #[test]
        fn seg_perm_complement_truncates_to_the_known_flag_mask(a: c_int) {
            let fa = SegmentPermissions::from_bits_retain(a);
            prop_assert_eq!((!fa).bits(), !a & SegmentPermissions::all().bits());
        }

        #[test]
        fn seg_flags_from_bits_retain_round_trips_every_bit_pattern(raw: c_int) {
            prop_assert_eq!(SegmentFlags::from_bits_retain(raw).bits(), raw);
        }

        #[test]
        fn seg_flags_union_and_intersection_are_raw_bitwise_ops(a: c_int, b: c_int) {
            let (fa, fb) = (SegmentFlags::from_bits_retain(a), SegmentFlags::from_bits_retain(b));
            prop_assert_eq!((fa | fb).bits(), a | b);
            prop_assert_eq!((fa & fb).bits(), a & b);
        }

        #[test]
        fn seg_flags_complement_truncates_to_the_known_flag_mask(a: c_int) {
            let fa = SegmentFlags::from_bits_retain(a);
            prop_assert_eq!((!fa).bits(), !a & SegmentFlags::all().bits());
        }
    }
}
