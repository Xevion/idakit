//! Tag-scoped views over a netnode's arrays under a non-default [`Tag`].
//!
//! [`Netnode::tag`](super::Netnode::tag) and [`NetnodeMut::tag`](super::NetnodeMut::tag) reach the
//! arrays under any tag rather than the reserved defaults. A tag addresses one numeric-indexed
//! array plus one string-keyed hash. The default view keeps integers and bytes apart by tag (`atag`
//! vs `stag`); under a single tag they are the same storage, so [`int`](TaggedNetnode::int) and
//! [`value`](TaggedNetnode::value) are the integer and byte views of one slot, not two arrays.

use crate::Database;
use crate::error::Result;

use super::{
    HashEntries, NetnodeBytes, NetnodeBytesError, NodeId, Sups, Tag, checked, delete_ops, write_ops,
};

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
///
/// Identity is the `(id, tag)` pair, not the id alone: two views over the same node under
/// different tags compare unequal.
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

// Compound (id, tag) key: key_identity! only spans one field, so this is hand-written.
impl PartialEq for TaggedNetnode<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.id == o.id && self.tag == o.tag
    }
}
impl Eq for TaggedNetnode<'_> {}
impl std::hash::Hash for TaggedNetnode<'_> {
    fn hash<H: std::hash::Hasher>(&self, s: &mut H) {
        self.id.hash(s);
        self.tag.hash(s);
    }
}

impl std::fmt::Debug for TaggedNetnode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaggedNetnode")
            .field("id", &self.id)
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

/// A read-write view of one netnode's arrays under a single [`Tag`], from
/// [`NetnodeMut::tag`](super::NetnodeMut::tag).
pub struct TaggedNetnodeMut<'db> {
    db: &'db mut Database,
    id: NodeId,
    tag: Tag,
}

impl std::fmt::Debug for TaggedNetnodeMut<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaggedNetnodeMut")
            .field("id", &self.id)
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

impl<'db> TaggedNetnodeMut<'db> {
    pub(super) fn new(db: &'db mut Database, id: NodeId, tag: Tag) -> Self {
        Self { db, id, tag }
    }

    tagged_reads!();

    write_ops! {
        /// Set the numeric slot at `index` to an integer.
        ///
        /// # Errors
        /// [`Error::WriteRejected`](crate::Error::WriteRejected) if the kernel rejects the write.
        fn set_int(this, index: u64, value: u64) => this.db.netnode_altset(this.id.get(), index, value, this.tag.raw());
    }

    delete_ops! {
        /// Delete the numeric slot at `index`, returning whether it was set.
        fn remove(this, index: u64) => this.db.netnode_supdel(this.id.get(), index, this.tag.raw());

        /// Delete every numeric slot under this tag, returning whether any were set.
        fn clear(this) => this.db.netnode_supdel_all(this.id.get(), this.tag.raw());

        /// Delete the hash value for `key`, returning whether it was set.
        fn remove_hash(this, key: &str) => this.db.netnode_hashdel(this.id.get(), key, this.tag.raw());

        /// Delete every hash entry under this tag, returning whether any were set.
        fn clear_hash(this) => this.db.netnode_hashdel_all(this.id.get(), this.tag.raw());
    }

    /// Set the numeric slot at `index` to bytes, from 1 to `MAXSPECSIZE` (1024) bytes.
    ///
    /// # Errors
    /// [`Error::InvalidNetnodeBytes`](crate::Error::InvalidNetnodeBytes) if `value` is empty or
    /// exceeds `MAXSPECSIZE`, or [`Error::WriteRejected`](crate::Error::WriteRejected) if the
    /// kernel rejects the write.
    #[doc(alias("netnode::supset"))]
    pub fn set_value<'a>(
        &mut self,
        index: u64,
        value: impl TryInto<NetnodeBytes<'a>, Error: Into<NetnodeBytesError>>,
    ) -> Result<()> {
        let bytes: NetnodeBytes<'_> = value.try_into().map_err(Into::into)?;
        let ok = self
            .db
            .netnode_supset(self.id.get(), index, bytes.as_bytes(), self.tag.raw());
        checked(&*self.db, self.id, ok, "set_value")
    }

    /// Set the hash value for `key` to raw bytes, from 1 to `MAXSPECSIZE` (1024) bytes.
    ///
    /// # Errors
    /// [`Error::InvalidNetnodeBytes`](crate::Error::InvalidNetnodeBytes) if `value` is empty or
    /// exceeds `MAXSPECSIZE`, or [`Error::WriteRejected`](crate::Error::WriteRejected) if the
    /// kernel rejects the write.
    #[doc(alias("netnode::hashset"))]
    pub fn set_hash<'a>(
        &mut self,
        key: &str,
        value: impl TryInto<NetnodeBytes<'a>, Error: Into<NetnodeBytesError>>,
    ) -> Result<()> {
        let bytes: NetnodeBytes<'_> = value.try_into().map_err(Into::into)?;
        let ok = self
            .db
            .netnode_hashset(self.id.get(), key, bytes.as_bytes(), self.tag.raw());
        checked(&*self.db, self.id, ok, "set_hash")
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn identity_is_by_id_and_tag() {
        let db = Database::new();
        let id = NodeId::try_new(1).unwrap();
        let other_id = NodeId::try_new(2).unwrap();
        let a = TaggedNetnode::new(&db, id, Tag::new(b'X'));
        let b = TaggedNetnode::new(&db, id, Tag::new(b'X'));
        let different_tag = TaggedNetnode::new(&db, id, Tag::new(b'Y'));
        let different_id = TaggedNetnode::new(&db, other_id, Tag::new(b'X'));

        assert!(a == b);
        assert!(a != different_tag);
        assert!(a != different_id);
    }

    #[test]
    fn debug_renders_id_and_tag() {
        let db = Database::new();
        let view = TaggedNetnode::new(&db, NodeId::try_new(1).unwrap(), Tag::new(b'X'));
        assert!(format!("{view:?}").starts_with("TaggedNetnode"));
    }

    #[test]
    fn hash_reflects_id_and_tag() {
        use std::hash::{Hash, Hasher};

        fn hash_of<T: Hash>(x: &T) -> u64 {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            x.hash(&mut h);
            h.finish()
        }

        let db = Database::new();
        let a = TaggedNetnode::new(&db, NodeId::try_new(1).unwrap(), Tag::new(b'X'));
        let b = TaggedNetnode::new(&db, NodeId::try_new(2).unwrap(), Tag::new(b'Y'));
        assert!(hash_of(&a) != hash_of(&b));
    }

    #[test]
    fn mut_debug_renders_id_and_tag() {
        let mut db = Database::new();
        let view = TaggedNetnodeMut::new(&mut db, NodeId::try_new(1).unwrap(), Tag::new(b'X'));
        let rendered = format!("{view:?}");
        assert!(rendered.contains("NodeId(0x1)"));
        assert!(rendered.contains("Tag('X')"));
    }
}
