//! Lazy iterators over a netnode's alt, sup, and hash arrays.
//!
//! Each retires IDA's `*first`/`*next` cursor dance into a Rust [`Iterator`], re-querying the
//! kernel per step and borrowing `&Database` so it can't coexist with a write. None knows its
//! length up front, so none is an [`ExactSizeIterator`]. Each is scoped to one tag.

use crate::Database;

use super::{BADNODE, NodeId};

/// Map a raw enumeration result to `Some(index)`, or `None` at the `BADNODE` end sentinel.
#[inline]
fn index_or_end(raw: u64) -> Option<u64> {
    (raw != BADNODE).then_some(raw)
}

/// A lazy iterator over one netnode's alt array as `(index, value)` pairs, from
/// [`Netnode::alts`](super::Netnode::alts).
///
/// ```
/// # idakit::doctest::with_db(|db| {
/// let id = db.netnode_mut("$ idakit-alts-debug-doctest").id();
/// let node = db.netnode_at(id);
/// let iter = node.alts();
/// assert!(format!("{iter:?}").starts_with("Alts"));
/// # Ok(())
/// # }).unwrap();
/// ```
pub struct Alts<'db> {
    db: &'db Database,
    id: NodeId,
    tag: u32,
    next: Option<u64>,
}

impl<'db> Alts<'db> {
    pub(crate) fn new(db: &'db Database, id: NodeId, tag: u32) -> Self {
        let next = index_or_end(db.netnode_altfirst(id.get(), tag));
        Self { db, id, tag, next }
    }
}

impl std::fmt::Debug for Alts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Alts")
            .field("id", &self.id)
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

impl Iterator for Alts<'_> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.next?;
        let value = self.db.netnode_altval(self.id.get(), index, self.tag);
        self.next = index_or_end(self.db.netnode_altnext(self.id.get(), index, self.tag));
        Some((index, value))
    }
}

/// A lazy iterator over one netnode's sup array as `(index, bytes)` pairs, from
/// [`Netnode::sups`](super::Netnode::sups).
///
/// ```
/// # idakit::doctest::with_db(|db| {
/// let id = db.netnode_mut("$ idakit-sups-debug-doctest").id();
/// let node = db.netnode_at(id);
/// let iter = node.sups();
/// assert!(format!("{iter:?}").starts_with("Sups"));
/// # Ok(())
/// # }).unwrap();
/// ```
pub struct Sups<'db> {
    db: &'db Database,
    id: NodeId,
    tag: u32,
    next: Option<u64>,
}

impl<'db> Sups<'db> {
    pub(crate) fn new(db: &'db Database, id: NodeId, tag: u32) -> Self {
        let next = index_or_end(db.netnode_supfirst(id.get(), tag));
        Self { db, id, tag, next }
    }
}

impl std::fmt::Debug for Sups<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sups")
            .field("id", &self.id)
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

impl Iterator for Sups<'_> {
    type Item = (u64, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.next?;
        let value = self
            .db
            .netnode_supval(self.id.get(), index, self.tag)
            .unwrap_or_default();
        self.next = index_or_end(self.db.netnode_supnext(self.id.get(), index, self.tag));
        Some((index, value))
    }
}

/// A lazy iterator over one netnode's hash as `(key, bytes)` pairs, in lexical key order, from
/// [`Netnode::hash_entries`](super::Netnode::hash_entries).
///
/// ```
/// # idakit::doctest::with_db(|db| {
/// let id = db.netnode_mut("$ idakit-hash-entries-debug-doctest").id();
/// let node = db.netnode_at(id);
/// let iter = node.hash_entries();
/// assert!(format!("{iter:?}").starts_with("HashEntries"));
/// # Ok(())
/// # }).unwrap();
/// ```
pub struct HashEntries<'db> {
    db: &'db Database,
    id: NodeId,
    tag: u32,
    next: Option<String>,
}

impl<'db> HashEntries<'db> {
    pub(crate) fn new(db: &'db Database, id: NodeId, tag: u32) -> Self {
        let next = db.netnode_hashfirst(id.get(), tag);
        Self { db, id, tag, next }
    }
}

impl std::fmt::Debug for HashEntries<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashEntries")
            .field("id", &self.id)
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

impl Iterator for HashEntries<'_> {
    type Item = (String, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.next.take()?;
        let value = self
            .db
            .netnode_hashval(self.id.get(), &key, self.tag)
            .unwrap_or_default();
        self.next = self.db.netnode_hashnext(self.id.get(), &key, self.tag);
        Some((key, value))
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;
    use crate::Database;

    // Debug formats only `id`/`tag`, so an unclaimed Database is safe to format against.

    #[test]
    fn alts_debug_renders_id_and_tag() {
        let db = Database::new();
        let iter = Alts {
            db: &db,
            id: NodeId::try_new(1).unwrap(),
            tag: u32::from(b'A'),
            next: None,
        };
        let rendered = format!("{iter:?}");
        assert!(rendered.contains("NodeId(0x1)"));
        assert!(rendered.contains("tag: 65"));
    }

    #[test]
    fn sups_debug_renders_id_and_tag() {
        let db = Database::new();
        let iter = Sups {
            db: &db,
            id: NodeId::try_new(1).unwrap(),
            tag: u32::from(b'S'),
            next: None,
        };
        let rendered = format!("{iter:?}");
        assert!(rendered.contains("NodeId(0x1)"));
        assert!(rendered.contains("tag: 83"));
    }

    #[test]
    fn hash_entries_debug_renders_id_and_tag() {
        let db = Database::new();
        let iter = HashEntries {
            db: &db,
            id: NodeId::try_new(1).unwrap(),
            tag: u32::from(b'H'),
            next: None,
        };
        let rendered = format!("{iter:?}");
        assert!(rendered.contains("NodeId(0x1)"));
        assert!(rendered.contains("tag: 72"));
    }
}
