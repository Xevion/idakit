//! Tag-scoped views over a netnode's arrays under a non-default [`Tag`].
//!
//! [`Netnode::tag`](super::Netnode::tag) and [`NetnodeMut::tag`](super::NetnodeMut::tag) reach the
//! arrays under any tag rather than the reserved defaults. A tag addresses one numeric-indexed
//! array plus one string-keyed hash. The default view keeps integers and bytes apart by tag (`atag`
//! vs `stag`); under a single tag they are the same storage, so [`int`](TaggedNetnode::int) and
//! [`value`](TaggedNetnode::value) are the integer and byte views of one slot, not two arrays.

use crate::Database;
use crate::error::Result;

use super::{HashEntries, NodeId, Sups, Tag, rejected};

/// The read accessors shared by [`TaggedNetnode`] and [`TaggedNetnodeMut`], scoped to `self.tag`.
macro_rules! tagged_reads {
    () => {
        /// The tag these accessors are scoped to.
        #[inline]
        #[must_use]
        pub const fn tag(&self) -> Tag {
            self.tag
        }

        /// The numeric slot at `index` read as an integer, or `0` if unset.
        #[inline]
        #[must_use]
        pub fn int(&self, index: u64) -> u64 {
            self.db.netnode_altval(self.id.get(), index, self.tag.raw())
        }

        /// The numeric slot at `index` read as bytes, or `None` if unset.
        #[inline]
        #[must_use]
        pub fn value(&self, index: u64) -> Option<Vec<u8>> {
            self.db.netnode_supval(self.id.get(), index, self.tag.raw())
        }

        /// The hash value for `key`, or `None` if unset.
        #[inline]
        #[must_use]
        pub fn hash(&self, key: &str) -> Option<Vec<u8>> {
            self.db.netnode_hashval(self.id.get(), key, self.tag.raw())
        }

        /// Lazily iterate the numeric array as `(index, bytes)` pairs, in ascending index order.
        #[inline]
        #[must_use]
        pub fn values(&self) -> Sups<'_> {
            Sups::new(&*self.db, self.id, self.tag.raw())
        }

        /// Lazily iterate the hash as `(key, bytes)` pairs, in lexical key order.
        #[inline]
        #[must_use]
        pub fn hash_entries(&self) -> HashEntries<'_> {
            HashEntries::new(&*self.db, self.id, self.tag.raw())
        }
    };
}

/// A read view of one netnode's arrays under a single [`Tag`], from
/// [`Netnode::tag`](super::Netnode::tag).
#[derive(Clone, Copy)]
pub struct TaggedNetnode<'db> {
    db: &'db Database,
    id: NodeId,
    tag: Tag,
}

impl<'db> TaggedNetnode<'db> {
    pub(super) fn new(db: &'db Database, id: NodeId, tag: Tag) -> Self {
        Self { db, id, tag }
    }

    tagged_reads!();
}

/// A read-write view of one netnode's arrays under a single [`Tag`], from
/// [`NetnodeMut::tag`](super::NetnodeMut::tag).
pub struct TaggedNetnodeMut<'db> {
    db: &'db mut Database,
    id: NodeId,
    tag: Tag,
}

impl<'db> TaggedNetnodeMut<'db> {
    pub(super) fn new(db: &'db mut Database, id: NodeId, tag: Tag) -> Self {
        Self { db, id, tag }
    }

    tagged_reads!();

    /// Set the numeric slot at `index` to an integer.
    ///
    /// # Errors
    /// [`Error::WriteRejected`](crate::Error::WriteRejected) if the kernel rejects the write.
    pub fn set_int(&mut self, index: u64, value: u64) -> Result<()> {
        let ok = self
            .db
            .netnode_altset(self.id.get(), index, value, self.tag.raw());
        self.checked(ok, "set_int")
    }

    /// Set the numeric slot at `index` to bytes (max 1024 bytes).
    ///
    /// # Errors
    /// [`Error::WriteRejected`](crate::Error::WriteRejected) if the kernel rejects the write.
    pub fn set_value(&mut self, index: u64, value: &[u8]) -> Result<()> {
        let ok = self
            .db
            .netnode_supset(self.id.get(), index, value, self.tag.raw());
        self.checked(ok, "set_value")
    }

    /// Delete the numeric slot at `index`.
    ///
    /// # Errors
    /// [`Error::WriteRejected`](crate::Error::WriteRejected) if the kernel rejects the write.
    pub fn remove(&mut self, index: u64) -> Result<()> {
        let ok = self.db.netnode_supdel(self.id.get(), index, self.tag.raw());
        self.checked(ok, "remove")
    }

    /// Delete every numeric slot under this tag.
    ///
    /// # Errors
    /// [`Error::WriteRejected`](crate::Error::WriteRejected) if the kernel rejects the write.
    pub fn clear(&mut self) -> Result<()> {
        let ok = self.db.netnode_supdel_all(self.id.get(), self.tag.raw());
        self.checked(ok, "clear")
    }

    /// Set the hash value for `key` to raw bytes (max 1024 bytes).
    ///
    /// # Errors
    /// [`Error::WriteRejected`](crate::Error::WriteRejected) if the kernel rejects the write.
    pub fn set_hash(&mut self, key: &str, value: &[u8]) -> Result<()> {
        let ok = self
            .db
            .netnode_hashset(self.id.get(), key, value, self.tag.raw());
        self.checked(ok, "set_hash")
    }

    /// Delete the hash value for `key`.
    ///
    /// # Errors
    /// [`Error::WriteRejected`](crate::Error::WriteRejected) if the kernel rejects the write.
    pub fn remove_hash(&mut self, key: &str) -> Result<()> {
        let ok = self.db.netnode_hashdel(self.id.get(), key, self.tag.raw());
        self.checked(ok, "remove_hash")
    }

    /// Delete every hash entry under this tag.
    ///
    /// # Errors
    /// [`Error::WriteRejected`](crate::Error::WriteRejected) if the kernel rejects the write.
    pub fn clear_hash(&mut self) -> Result<()> {
        let ok = self.db.netnode_hashdel_all(self.id.get(), self.tag.raw());
        self.checked(ok, "clear_hash")
    }

    fn checked(&self, ok: bool, op: &'static str) -> Result<()> {
        if ok {
            Ok(())
        } else {
            Err(rejected(&*self.db, self.id.get(), op))
        }
    }
}
