//! The typed [`FlowChartFlags`] layer over `gdl.hpp`'s `FC_*` flow-chart build bits.

use std::ffi::c_int;

use bitflags::bitflags;

bitflags! {
    /// Flow-chart build flag bits from `gdl.hpp` (`FC_NOEXT`/`FC_CALL_ENDS`/`FC_NOPREDS`), passed
    /// to `qflow_chart_t::qflow_chart_t`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias("FC_NOEXT", "FC_CALL_ENDS", "FC_NOPREDS"))]
    pub struct FlowChartFlags: c_int {
        /// Omit external blocks, jump targets outside the function (`FC_NOEXT`).
        #[doc(alias("FC_NOEXT"))]
        const NOEXT = 0x0002;
        /// Call instructions terminate a basic block (`FC_CALL_ENDS`).
        #[doc(alias("FC_CALL_ENDS"))]
        const CALL_ENDS = 0x0020;
        /// Skip predecessor-list computation (`FC_NOPREDS`).
        #[doc(alias("FC_NOPREDS"))]
        const NOPREDS = 0x0040;
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::noext(FlowChartFlags::NOEXT, 0x0002)]
    #[case::call_ends(FlowChartFlags::CALL_ENDS, 0x0020)]
    #[case::nopreds(FlowChartFlags::NOPREDS, 0x0040)]
    fn flags_pin_the_raw_sdk_values(#[case] flag: FlowChartFlags, #[case] raw: c_int) {
        assert!(flag.bits() == raw);
    }

    #[test]
    fn default_is_empty() {
        assert!(FlowChartFlags::default().is_empty());
    }

    proptest! {
        #[test]
        fn from_bits_retain_round_trips_every_bit_pattern(raw: c_int) {
            prop_assert_eq!(FlowChartFlags::from_bits_retain(raw).bits(), raw);
        }

        #[test]
        fn union_and_intersection_are_raw_bitwise_ops(a: c_int, b: c_int) {
            let (fa, fb) = (FlowChartFlags::from_bits_retain(a), FlowChartFlags::from_bits_retain(b));
            prop_assert_eq!((fa | fb).bits(), a | b);
            prop_assert_eq!((fa & fb).bits(), a & b);
        }

        #[test]
        fn complement_truncates_to_the_known_flag_mask(a: c_int) {
            let fa = FlowChartFlags::from_bits_retain(a);
            prop_assert_eq!((!fa).bits(), !a & FlowChartFlags::all().bits());
        }
    }
}
