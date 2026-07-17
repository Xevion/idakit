//! The typed [`NameFlags`] layer over `name.hpp`'s `GN_*` bits for `get_ea_name`.

use std::ffi::c_int;

use bitflags::bitflags;

bitflags! {
    /// `get_ea_name`'s `gtn_flags` bits (`name.hpp`), controlling substitution/demangling.
    ///
    /// Accepts any bit pattern (`from_bits_retain`), so it stays sound as the raw `int` argument
    /// crossing to `get_ea_name`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias(
        "GN_VISIBLE", "GN_COLORED", "GN_DEMANGLED", "GN_STRICT", "GN_SHORT", "GN_LONG",
        "GN_LOCAL", "GN_ISRET", "GN_NOT_ISRET", "GN_NOT_DUMMY"
    ))]
    pub struct NameFlags: c_int {
        /// Replace forbidden characters with `SUBSTCHAR` (`GN_VISIBLE`).
        #[doc(alias("GN_VISIBLE"))]
        const VISIBLE = 0x0001;
        /// Return a colored name (`GN_COLORED`).
        #[doc(alias("GN_COLORED"))]
        const COLORED = 0x0002;
        /// Return the demangled form (`GN_DEMANGLED`).
        #[doc(alias("GN_DEMANGLED"))]
        const DEMANGLED = 0x0004;
        /// Fail rather than fall back when demangling fails (`GN_STRICT`).
        #[doc(alias("GN_STRICT"))]
        const STRICT = 0x0008;
        /// Use the short demangled form (`GN_SHORT`).
        #[doc(alias("GN_SHORT"))]
        const SHORT = 0x0010;
        /// Use the long demangled form (`GN_LONG`).
        #[doc(alias("GN_LONG"))]
        const LONG = 0x0020;
        /// Try the local name first, falling back to the global one (`GN_LOCAL`).
        #[doc(alias("GN_LOCAL"))]
        const LOCAL = 0x0040;
        /// For a dummy name, use the return-location form (`GN_ISRET`).
        #[doc(alias("GN_ISRET"))]
        const ISRET = 0x0080;
        /// For a dummy name, do not use the return-location form (`GN_NOT_ISRET`).
        #[doc(alias("GN_NOT_ISRET"))]
        const NOT_ISRET = 0x0100;
        /// Do not return a dummy name (`GN_NOT_DUMMY`).
        #[doc(alias("GN_NOT_DUMMY"))]
        const NOT_DUMMY = 0x0200;
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::visible(NameFlags::VISIBLE, 0x0001)]
    #[case::colored(NameFlags::COLORED, 0x0002)]
    #[case::demangled(NameFlags::DEMANGLED, 0x0004)]
    #[case::strict(NameFlags::STRICT, 0x0008)]
    #[case::short(NameFlags::SHORT, 0x0010)]
    #[case::long(NameFlags::LONG, 0x0020)]
    #[case::local(NameFlags::LOCAL, 0x0040)]
    #[case::isret(NameFlags::ISRET, 0x0080)]
    #[case::not_isret(NameFlags::NOT_ISRET, 0x0100)]
    #[case::not_dummy(NameFlags::NOT_DUMMY, 0x0200)]
    fn flags_pin_the_raw_sdk_values(#[case] flag: NameFlags, #[case] raw: c_int) {
        assert!(flag.bits() == raw);
    }

    proptest! {
        #[test]
        fn from_bits_retain_round_trips_every_bit_pattern(raw: c_int) {
            prop_assert_eq!(NameFlags::from_bits_retain(raw).bits(), raw);
        }

        #[test]
        fn union_and_intersection_are_raw_bitwise_ops(a: c_int, b: c_int) {
            let (fa, fb) = (NameFlags::from_bits_retain(a), NameFlags::from_bits_retain(b));
            prop_assert_eq!((fa | fb).bits(), a | b);
            prop_assert_eq!((fa & fb).bits(), a & b);
        }

        #[test]
        fn complement_truncates_to_the_known_flag_mask(a: c_int) {
            let fa = NameFlags::from_bits_retain(a);
            prop_assert_eq!((!fa).bits(), !a & NameFlags::all().bits());
        }
    }
}
