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
