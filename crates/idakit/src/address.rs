//! Wraps raw effective addresses in a validated, niche-optimized [`Address`] type.
//!
//! An `Address` wraps any raw address except the `BADADDR` sentinel (`0` is a valid
//! address). It stores `!raw` in a [`NonZeroU64`], so the niche sits on the sentinel and
//! `Option<Address>` is `u64`-sized. `BADADDR`-on-failure maps straight to `None`.

use std::num::NonZeroU64;
use std::ops::Add;

use idakit_sys::BADADDR;
use serde::{Deserialize, Serialize};

const MAX_EA: u64 = BADADDR - 1;

/// A validated address, any real value other than the invalid sentinel.
///
/// The invalid-address sentinel maps to [`None`], and a niche keeps `Option<Address>` the same
/// size as a bare [`u64`].
///
/// Ordering is by the real address: the niche stores `!raw`, so a *derived* `Ord` would
/// compare inverted bits and reverse the order. Callers expect an `Address` to sort like the
/// raw address it wraps (linear walks, chunk bounds, `BTreeMap` keys), so `Ord`/`PartialOrd` are
/// hand-written over [`get`](Self::get).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[doc(alias("ea_t"))]
pub struct Address(NonZeroU64);

impl Address {
    /// Wrap a raw address. `None` only when `raw == BADADDR`.
    #[inline]
    #[must_use]
    #[doc(alias("BADADDR"))]
    pub const fn try_new(raw: u64) -> Option<Self> {
        // !BADADDR == 0, rejected by NonZeroU64; every other address is non-zero.
        match NonZeroU64::new(!raw) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    /// Const constructor for literals.
    ///
    /// # Panics
    /// At compile time, if `raw == BADADDR`.
    #[inline]
    #[must_use]
    pub const fn new_const(raw: u64) -> Self {
        match Self::try_new(raw) {
            Some(address) => address,
            None => panic!("Address::new_const: value is BADADDR"),
        }
    }

    /// The raw address.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u64 {
        !self.0.get()
    }
}

impl std::fmt::Debug for Address {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Address({:#x})", self.get())
    }
}

impl std::fmt::Display for Address {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.get())
    }
}

impl std::fmt::LowerHex for Address {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(&self.get(), f)
    }
}

impl std::fmt::UpperHex for Address {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::UpperHex::fmt(&self.get(), f)
    }
}

impl From<Address> for u64 {
    #[inline]
    fn from(address: Address) -> Self {
        address.get()
    }
}

// Serialize the real address, not the inverted niche a derive would emit: an
// `Address` round-trips as its `get()` value, and any non-sentinel `u64` deserializes back.
impl Serialize for Address {
    #[inline]
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.get())
    }
}

impl<'de> Deserialize<'de> for Address {
    #[inline]
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = u64::deserialize(deserializer)?;
        Self::try_new(raw)
            .ok_or_else(|| serde::de::Error::custom("address is the BADADDR sentinel"))
    }
}

impl Ord for Address {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.get().cmp(&other.get())
    }
}

impl PartialOrd for Address {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Add<u64> for Address {
    type Output = Self;

    /// Advance by a byte count, saturating into `[0, BADADDR)` so the result is always a
    /// valid [`Address`], never the sentinel.
    #[inline]
    fn add(self, bytes: u64) -> Self {
        let clamped = self.get().saturating_add(bytes).min(MAX_EA);
        Self::try_new(clamped).expect("clamped below BADADDR")
    }
}

impl Address {
    /// The non-negative byte span `end - self`, saturating to `0` when `end` is below `self`.
    ///
    /// The natural length of a `[self, end)` range, so a caller reads
    /// `start.distance_to(end)` rather than an unsigned-cast subtraction.
    #[inline]
    #[must_use]
    pub const fn distance_to(self, end: Self) -> u64 {
        end.get().saturating_sub(self.get())
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    /// Every raw value round-trips except the `BADADDR` sentinel itself.
    #[rstest]
    #[case::zero(0, true)]
    #[case::one(1, true)]
    #[case::below_max_ea(MAX_EA - 1, true)]
    #[case::max_ea(MAX_EA, true)]
    #[case::badaddr(BADADDR, false)]
    fn try_new_boundary(#[case] raw: u64, #[case] expect_valid: bool) {
        let got = Address::try_new(raw);
        assert!(got.is_some() == expect_valid);
        if expect_valid {
            assert!(got.unwrap().get() == raw);
        }
    }

    #[test]
    fn zero_is_a_valid_address() {
        assert!(Address::try_new(0).unwrap().get() == 0);
    }

    #[test]
    fn new_const_panics_on_badaddr() {
        let result = std::panic::catch_unwind(|| Address::new_const(BADADDR));
        assert!(result.is_err());
    }

    #[test]
    fn option_address_is_niche_optimized() {
        assert!(size_of::<Option<Address>>() == size_of::<u64>());
    }

    #[test]
    fn advance_normal() {
        let a = Address::new_const(0x1400_1000);
        assert!((a + 0x40).get() == 0x1400_1040);
        assert!((a + 0).get() == 0x1400_1000);
    }

    #[test]
    fn advance_saturates_below_sentinel() {
        let a = Address::new_const(BADADDR - 1);
        // Pushing past the top clamps to BADADDR-1, never the sentinel.
        assert!((a + 100).get() == BADADDR - 1);
        assert!((a + u64::MAX).get() == BADADDR - 1);
    }

    #[test]
    fn order_follows_address_not_niche() {
        // The niche stores `!raw`, so a derived `Ord` would sort these backwards.
        let lo = Address::new_const(0x1000);
        let hi = Address::new_const(0x2000);
        assert!(lo < hi);
        assert!(hi > lo);
        assert!(lo.min(hi) == lo);
        assert!([hi, lo].iter().min() == Some(&lo));
    }

    #[rstest]
    #[case::forward(0x1f00, 0x2000, 0x100)]
    #[case::zero_span(0x1000, 0x1000, 0)]
    // Below-self saturates to zero rather than wrapping.
    #[case::backward_saturates(0x2000, 0x1f00, 0)]
    #[case::from_zero(0, MAX_EA, MAX_EA)]
    fn distance_to_is_a_saturating_span(#[case] start: u64, #[case] end: u64, #[case] expect: u64) {
        assert!(Address::new_const(start).distance_to(Address::new_const(end)) == expect);
    }

    #[test]
    fn serde_round_trips_as_the_real_address() {
        let a = Address::new_const(0x1400_1000);
        let json = serde_json::to_string(&a).unwrap();
        // Serializes the logical address, not the inverted niche.
        assert!(json == a.get().to_string());
        let back: Address = serde_json::from_str(&json).unwrap();
        assert!(back == a);
    }

    #[test]
    fn serde_rejects_the_sentinel() {
        assert!(serde_json::from_str::<Address>(&BADADDR.to_string()).is_err());
    }

    #[test]
    fn hex_formatting() {
        let a = Address::new_const(0xdead_beef);
        assert!(format!("{a:#x}") == "0xdeadbeef");
        assert!(format!("{a:?}") == "Address(0xdeadbeef)");
    }

    mod proptests {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn try_new_get_roundtrips(raw in 0u64..BADADDR) {
                prop_assert_eq!(Address::try_new(raw).unwrap().get(), raw);
            }

            // Across the *full* u64 domain, not just the valid sub-range: the only rejected
            // value is the sentinel itself.
            #[test]
            fn try_new_is_none_iff_badaddr(raw in any::<u64>()) {
                prop_assert_eq!(Address::try_new(raw).is_none(), raw == BADADDR);
            }

            #[test]
            fn advance_never_yields_sentinel(base in 0u64..BADADDR, bytes in 0u64..=u64::MAX) {
                let r = Address::new_const(base) + bytes;
                prop_assert!(r.get() < BADADDR);
            }

            #[test]
            fn advance_matches_saturating_within_range(
                base in 0u64..(1u64 << 40),
                bytes in 0u64..(1u64 << 30),
            ) {
                let r = Address::new_const(base) + bytes;
                prop_assert_eq!(r.get(), base.saturating_add(bytes).min(BADADDR - 1));
            }

            #[test]
            fn distance_to_inverts_advance(base in 0u64..(1u64 << 40), bytes in 0u64..(1u64 << 30)) {
                let a = Address::new_const(base);
                let b = a + bytes;
                prop_assert_eq!(a.distance_to(b), bytes);
            }

            #[test]
            fn order_matches_raw(a in 0u64..BADADDR, b in 0u64..BADADDR) {
                prop_assert_eq!(Address::new_const(a).cmp(&Address::new_const(b)), a.cmp(&b));
            }
        }
    }
}
