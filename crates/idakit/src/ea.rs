//! Typed effective addresses: [`Ea`] and [`Offset`].
//!
//! An `Ea` is any `ea_t` except the [`BADADDR`] sentinel (`0` is a valid
//! address). It stores `!raw` in a [`NonZeroU64`], so the niche sits on the
//! sentinel and `Option<Ea>` is `u64`-sized -- `BADADDR`-on-failure maps straight
//! to `None`.

use std::num::NonZeroU64;
use std::ops::Add;

/// The IDA "no address" sentinel. An [`Ea`] never holds this.
pub const BADADDR: u64 = u64::MAX;

const MAX_EA: u64 = BADADDR - 1;

/// A validated effective address: any `ea_t` except [`BADADDR`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ea(NonZeroU64);

impl Ea {
    /// Wrap a raw `ea_t`. `None` only when `raw == BADADDR`.
    #[inline]
    #[must_use]
    pub const fn try_new(raw: u64) -> Option<Self> {
        // !BADADDR == 0, rejected by NonZeroU64; every other ea is non-zero.
        match NonZeroU64::new(!raw) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    /// Const constructor for literals. Panics (at compile time) if `raw == BADADDR`.
    #[inline]
    #[must_use]
    pub const fn new_const(raw: u64) -> Self {
        match Self::try_new(raw) {
            Some(ea) => ea,
            None => panic!("Ea::new_const: value is BADADDR"),
        }
    }

    /// The raw `ea_t`.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u64 {
        !self.0.get()
    }
}

impl std::fmt::Debug for Ea {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ea({:#x})", self.get())
    }
}

impl std::fmt::Display for Ea {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.get())
    }
}

impl std::fmt::LowerHex for Ea {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(&self.get(), f)
    }
}

impl std::fmt::UpperHex for Ea {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::UpperHex::fmt(&self.get(), f)
    }
}

impl From<Ea> for u64 {
    #[inline]
    fn from(ea: Ea) -> Self {
        ea.get()
    }
}

/// A signed byte delta between two addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Offset(i64);

impl Offset {
    /// Wrap a raw signed byte delta.
    #[inline]
    #[must_use]
    pub const fn new(v: i64) -> Self {
        Self(v)
    }

    /// The raw signed byte delta.
    #[inline]
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl From<i64> for Offset {
    #[inline]
    fn from(v: i64) -> Self {
        Self(v)
    }
}

impl Add<Offset> for Ea {
    type Output = Ea;

    /// Saturating signed displacement, clamped into `[0, BADADDR)`.
    #[inline]
    fn add(self, rhs: Offset) -> Ea {
        let clamped = self.get().saturating_add_signed(rhs.get()).min(MAX_EA);
        Ea::try_new(clamped).expect("clamped below BADADDR")
    }
}

impl std::ops::Sub<Offset> for Ea {
    type Output = Ea;

    /// Saturating signed displacement, sharing [`Add<Offset>`]'s clamp. Negating
    /// saturates because `i64::MIN.checked_neg()` is `None`; without it, subtracting
    /// the minimum offset would overflow.
    // Subtracting an offset is adding its negation, so this `Sub` impl reuses `Add`'s
    // clamp by design (clippy::suspicious_arithmetic_impl).
    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline]
    fn sub(self, rhs: Offset) -> Ea {
        self + Offset::new(rhs.get().saturating_neg())
    }
}

impl std::ops::Sub<Ea> for Ea {
    type Output = i64;

    /// Signed distance `self - rhs`.
    #[inline]
    fn sub(self, rhs: Ea) -> i64 {
        self.get().wrapping_sub(rhs.get()) as i64
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn rejects_only_badaddr() {
        assert!(Ea::try_new(BADADDR).is_none());
        assert!(Ea::try_new(0).is_some());
        assert!(Ea::try_new(1).is_some());
        assert!(Ea::try_new(BADADDR - 1).is_some());
    }

    #[test]
    fn zero_is_a_valid_address() {
        assert!(Ea::try_new(0).unwrap().get() == 0);
    }

    #[test]
    fn option_ea_is_niche_optimized() {
        assert!(size_of::<Option<Ea>>() == size_of::<u64>());
    }

    #[test]
    fn add_offset_normal() {
        let a = Ea::new_const(0x1400_1000);
        assert!((a + Offset::new(0x40)).get() == 0x1400_1040);
        assert!((a + Offset::new(-0x40)).get() == 0x1400_0fc0);
    }

    #[test]
    fn add_saturates_below_sentinel() {
        let a = Ea::new_const(BADADDR - 1);
        // Pushing past the top clamps to BADADDR-1, never the sentinel.
        assert!((a + Offset::new(100)).get() == BADADDR - 1);
        let z = Ea::new_const(0);
        assert!((z + Offset::new(-100)).get() == 0);
    }

    #[test]
    fn sub_is_signed_distance() {
        let a = Ea::new_const(0x2000);
        let b = Ea::new_const(0x1f00);
        assert!(a - b == 0x100);
        assert!(b - a == -0x100);
    }

    #[test]
    fn hex_formatting() {
        let a = Ea::new_const(0xdead_beef);
        assert!(format!("{a:#x}") == "0xdeadbeef");
        assert!(format!("{a:?}") == "Ea(0xdeadbeef)");
    }

    mod proptests {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn try_new_get_roundtrips(raw in 0u64..BADADDR) {
                prop_assert_eq!(Ea::try_new(raw).unwrap().get(), raw);
            }

            #[test]
            fn add_never_yields_sentinel(base in 0u64..BADADDR, off in i64::MIN..i64::MAX) {
                let r = Ea::new_const(base) + Offset::new(off);
                prop_assert!(r.get() < BADADDR);
            }

            #[test]
            fn add_matches_saturating_within_range(
                base in 0u64..(1u64 << 40),
                off in -(1i64 << 30)..(1i64 << 30),
            ) {
                let r = Ea::new_const(base) + Offset::new(off);
                prop_assert_eq!(r.get(), base.saturating_add_signed(off).min(BADADDR - 1));
            }

            #[test]
            fn sub_inverts_add(base in 0u64..(1u64 << 40), off in 0i64..(1i64 << 30)) {
                let a = Ea::new_const(base);
                let b = a + Offset::new(off);
                prop_assert_eq!(b - a, off);
            }
        }
    }
}
