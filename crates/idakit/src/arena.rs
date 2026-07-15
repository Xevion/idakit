//! A minimal append-only index arena ([`Arena<T>`]), modeled on rust-analyzer's `la_arena`.
//!
//! [`Idx<T>`] is a 32-bit handle into an [`Arena<T>`]:`Copy`, lifetime-free, and typed by
//! `T` so an `Idx<ExpressionData>` cannot be used where an `Idx<TypeValue>` is expected. The
//! arena only appends, so a handle stays valid for the arena's life. Being lifetime-free and
//! (for `T: Send`) `Send` is what lets a materialized graph, the decompiler ctree or a
//! function's [`FlowChart`](crate::flowchart::FlowChart), move off the kernel thread to a
//! worker.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::ops::{Index, IndexMut};

use serde::{Deserialize, Serialize};

/// A typed handle into an [`Arena<T>`].
///
/// Cheap (`Copy`), `Send`/`Sync` regardless of `T`, and stable for the life of the arena.
pub struct Idx<T> {
    raw: u32,
    // `fn() -> T` keeps `Idx<T>` covariant in `T` and unconditionally `Send + Sync`,
    // so a handle never inherits `T`'s thread-affinity (cf. la_arena).
    _ty: PhantomData<fn() -> T>,
}

impl<T> Idx<T> {
    /// Reconstructs a handle from a raw index.
    ///
    /// `pub(crate)` for the ctree builder, which receives node indices back across the
    /// facade boundary as bare `u32`s.
    #[inline]
    pub(crate) fn from_raw(raw: u32) -> Self {
        Self {
            raw,
            _ty: PhantomData,
        }
    }

    /// Handle for an arena position.
    ///
    /// The single place the `usize` index is narrowed to the 32-bit handle, so `alloc` and
    /// `iter` agree on the bound.
    #[inline]
    fn from_index(index: usize) -> Self {
        let raw = u32::try_from(index).expect("ctree arena exceeded u32 nodes");
        Self::from_raw(raw)
    }

    /// The position this handle refers to.
    #[inline]
    #[must_use]
    pub fn index(self) -> usize {
        self.raw as usize
    }
}

// Hand-implemented so the bounds are on `Idx<T>` unconditionally, not on `T`:
// a handle is `Copy`/`Eq`/`Hash`/`Ord`/serde-(de)serializable even when the payload `T` is not.
impl<T> Clone for Idx<T> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Idx<T> {}
impl<T> PartialEq for Idx<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}
impl<T> Eq for Idx<T> {}
impl<T> Hash for Idx<T> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}
impl<T> PartialOrd for Idx<T> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for Idx<T> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.raw.cmp(&other.raw)
    }
}
impl<T> fmt::Debug for Idx<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Idx").field(&self.raw).finish()
    }
}
impl<T> Serialize for Idx<T> {
    #[inline]
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.raw)
    }
}
impl<'de, T> Deserialize<'de> for Idx<T> {
    #[inline]
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        u32::deserialize(deserializer).map(Self::from_raw)
    }
}

/// An append-only arena of `T`, addressed by [`Idx<T>`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arena<T> {
    data: Vec<T>,
}

impl<T> Arena<T> {
    /// An empty arena.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Appends a value, returning a stable handle to it.
    #[inline]
    pub fn alloc(&mut self, value: T) -> Idx<T> {
        let idx = Idx::from_index(self.data.len());
        self.data.push(value);
        idx
    }

    /// The number of allocated elements.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether nothing has been allocated yet.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Iterates every `(handle, value)` pair in allocation order.
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (Idx<T>, &T)> {
        self.data
            .iter()
            .enumerate()
            .map(|(i, v)| (Idx::from_index(i), v))
    }
}

impl<T> Default for Arena<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Index<Idx<T>> for Arena<T> {
    type Output = T;

    #[inline]
    fn index(&self, idx: Idx<T>) -> &T {
        &self.data[idx.index()]
    }
}

impl<T> IndexMut<Idx<T>> for Arena<T> {
    #[inline]
    fn index_mut(&mut self, idx: Idx<T>) -> &mut T {
        &mut self.data[idx.index()]
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn alloc_returns_stable_handles() {
        let mut arena = Arena::new();
        let a = arena.alloc("a");
        let b = arena.alloc("b");
        let c = arena.alloc("c");

        // Each handle indexes back to the value it was allocated for, and stays valid
        // after later allocations.
        assert!(arena[a] == "a");
        assert!(arena[b] == "b");
        assert!(arena[c] == "c");
        assert!(a != b);
        assert!(b != c);
        assert!(arena.len() == 3);
    }

    #[test]
    fn iter_yields_all_in_order() {
        let mut arena = Arena::new();
        let ids: Vec<_> = [10, 20, 30].into_iter().map(|v| arena.alloc(v)).collect();
        let seen: Vec<_> = arena.iter().collect();

        assert!(seen.len() == 3);
        for (expected_id, (got_id, &got_val)) in ids.iter().zip(seen) {
            assert!(*expected_id == got_id);
            assert!(arena[got_id] == got_val);
        }
    }

    #[test]
    fn handle_is_send_and_sync_even_when_payload_is_not() {
        fn assert_send_sync<T: Send + Sync>() {}
        // `*const ()` is neither Send nor Sync, but a handle to it still is.
        assert_send_sync::<Idx<*const ()>>();
    }

    #[test]
    fn arena_clone_and_eq() {
        let mut arena = Arena::new();
        arena.alloc("a");
        arena.alloc("b");

        let cloned = arena.clone();
        assert!(cloned == arena);

        let mut other = Arena::new();
        other.alloc("a");
        assert!(other != arena);
    }

    #[test]
    fn arena_serde_round_trip() {
        let mut arena = Arena::new();
        arena.alloc(1);
        arena.alloc(2);
        arena.alloc(3);

        let json = serde_json::to_string(&arena).unwrap();
        let round_tripped: Arena<i32> = serde_json::from_str(&json).unwrap();
        assert!(round_tripped == arena);
    }

    #[test]
    fn idx_ord_sorts_by_raw_position() {
        let mut arena = Arena::new();
        let a = arena.alloc("a");
        let b = arena.alloc("b");
        let c = arena.alloc("c");

        let mut ids = vec![c, a, b];
        ids.sort();
        assert!(ids == [a, b, c]);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn idx_serde_round_trip_without_payload_bound() {
        // `*const ()` doesn't implement Serialize/Deserialize; the handle still does.
        let idx: Idx<*const ()> = Idx::from_raw(7);

        let json = serde_json::to_string(&idx).unwrap();
        let round_tripped: Idx<*const ()> = serde_json::from_str(&json).unwrap();
        assert!(round_tripped == idx);
    }
}
