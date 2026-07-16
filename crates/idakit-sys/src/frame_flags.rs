//! The typed [`FrameVarFlags`] layer over `FrameVar`'s reserved-slot flag bits.
//!
//! The frame walk itself is the `cxx` `bridge::frame_type_walk_visit` entry (see
//! `bridge_visitors`); these flags classify the slots it returns.

use bitflags::bitflags;

bitflags! {
    /// `FrameVar::flags` bits marking the reserved return-address and saved-registers slots.
    ///
    /// The bits are idakit's own, set by the C++ frame walk; they correspond to the SDK's
    /// `FPC_RETADDR`/`FPC_SAVREGS` frame parts (`frame_part_t`). Accepts any bit pattern
    /// (`from_bits_retain`), since `FrameVar::flags` is a raw `u32` field the walk writes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias("FPC_RETADDR", "FPC_SAVREGS"))]
    pub struct FrameVarFlags: u32 {
        /// The return-address slot in the frame (SDK `FPC_RETADDR`).
        #[doc(alias("FPC_RETADDR"))]
        const RETADDR = 1;
        /// The saved-registers slot in the frame (SDK `FPC_SAVREGS`).
        #[doc(alias("FPC_SAVREGS"))]
        const SAVREGS = 2;
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::retaddr(FrameVarFlags::RETADDR, 1)]
    #[case::savregs(FrameVarFlags::SAVREGS, 2)]
    fn flags_pin_the_raw_values(#[case] flag: FrameVarFlags, #[case] raw: u32) {
        assert!(flag.bits() == raw);
    }

    proptest! {
        #[test]
        fn from_bits_retain_round_trips_every_bit_pattern(raw: u32) {
            prop_assert_eq!(FrameVarFlags::from_bits_retain(raw).bits(), raw);
        }

        #[test]
        fn union_and_intersection_are_raw_bitwise_ops(a: u32, b: u32) {
            let (fa, fb) = (FrameVarFlags::from_bits_retain(a), FrameVarFlags::from_bits_retain(b));
            prop_assert_eq!((fa | fb).bits(), a | b);
            prop_assert_eq!((fa & fb).bits(), a & b);
        }

        #[test]
        fn complement_truncates_to_the_known_flag_mask(a: u32) {
            let fa = FrameVarFlags::from_bits_retain(a);
            prop_assert_eq!((!fa).bits(), !a & FrameVarFlags::all().bits());
        }
    }
}
