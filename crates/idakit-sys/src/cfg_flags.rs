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

    use super::*;

    #[test]
    fn flags_pin_the_raw_sdk_values() {
        assert!(FlowChartFlags::NOEXT.bits() == 0x0002);
        assert!(FlowChartFlags::CALL_ENDS.bits() == 0x0020);
        assert!(FlowChartFlags::NOPREDS.bits() == 0x0040);
    }

    #[test]
    fn default_is_empty() {
        assert!(FlowChartFlags::default().is_empty());
    }
}
