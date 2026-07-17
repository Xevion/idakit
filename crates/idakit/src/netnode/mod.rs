//! Reads and writes IDA's persistent per-database store through the [`Netnode`] view and
//! [`NetnodeMut`] cursor.
//!
//! A netnode is IDA's lowest-level persistence primitive: a node, addressed by a [`NodeId`] or a
//! name, carrying a single value plus several typed arrays. idakit surfaces the arrays as native
//! Rust collections and hides IDA's 8-bit tag selectors behind fixed defaults:
//!
//! - the **altval** array ([`altvals`](Netnode::altvals)), a sparse map of [`u64`] indices to
//!   [`u64`] values;
//! - the **supval** array ([`supvals`](Netnode::supvals)), a sparse map of [`u64`] indices to
//!   byte objects;
//! - the **hash** ([`hash_entries`](Netnode::hash_entries)), a string-keyed map of byte objects, and
//!   the typed key/value store ([`get`](Netnode::get)/[`put`](NetnodeMut::put)) layered on it;
//! - **blobs** ([`blob`](Netnode::blob)), unlimited-size byte objects.
//!
//! Every value/supval/hash byte write goes through [`NetnodeBytes`], validating the object-size
//! domain against [`NetnodeBytes::MAX_SIZE`] at conversion time. Blobs alone are unbounded.
//!
//! [`Netnode`] reads (absence is [`None`], never an error); [`NetnodeMut`], acquired by
//! [`netnode_mut`](Database::netnode_mut) from `&mut Database`, writes. The whole layer holds no
//! kernel handle and needs no `unsafe`: a netnode is a value over its [`NodeId`], so the views are
//! plain `Database`-bound borrows over safe FFI.
//!
//! Absence stays a non-error on the write side too. The kernel answers a delete with one bit
//! meaning "there was something there", so the `remove_*`/`clear_*` methods return it as a `bool`
//! the way [`HashSet::remove`](std::collections::HashSet::remove) does, and deleting what was
//! never set is an ordinary `false` rather than a failure. Only setters return [`Result`], since
//! only a setter can actually be refused.
//!
//! Char values and non-default tags are the raw-FFI surface's domain (`idakit_sys::netnode_*`);
//! this layer is the curated, idiomatic subset.

mod arrays;
mod bytes;
mod persist;
mod tag;
mod tagged;

use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::Database;
use crate::error::{Error, Result};

pub use self::arrays::{Altvals, HashEntries, Supvals};
pub use self::bytes::{NetnodeBytes, NetnodeBytesError};
pub use self::persist::Persist;
pub use self::tag::Tag;
pub use self::tagged::{TaggedNetnode, TaggedNetnodeMut};

/// The bad-node sentinel (`BADNODE`), the niche of [`NodeId`].
const BADNODE: u64 = u64::MAX;

/// Build an [`Error::WriteRejected`] for `op` from the kernel's error channel after a failed write.
fn rejected(db: &Database, address: u64, op: &'static str) -> Error {
    let (errno, reason) = db.last_reason();
    Error::WriteRejected {
        op,
        address,
        errno,
        reason,
    }
}

/// Map a setter's boolean result to `Result`, building an [`Error::WriteRejected`] for `op` from
/// the kernel's error channel on failure.
///
/// Shared by both cursors: the tagged one differs only in which array it addresses, not in how a
/// refusal surfaces. Deletes never come through here, since their boolean answers "was it there".
fn checked(db: &Database, id: NodeId, ok: bool, op: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(rejected(db, id.get(), op))
    }
}

impl Database {
    /// The netnode named `name`, or `None` if no such node exists.
    ///
    /// Does not create the node. User nodes conventionally prefix their name with `"$ "` to avoid
    /// clashing with program symbol names.
    #[must_use]
    #[doc(alias("netnode::netnode"))]
    pub fn netnode(&self, name: &str) -> Option<Netnode<'_>> {
        NodeId::try_new(self.netnode_open(name)).map(|id| Netnode { db: self, id })
    }

    /// A read view of the node with id `id`, without checking that it exists.
    ///
    /// Absence surfaces per accessor (as [`None`]), matching [`at`](Self::at).
    #[inline]
    #[must_use]
    #[doc(alias("netnode::netnode"))]
    pub fn netnode_at(&self, id: NodeId) -> Netnode<'_> {
        Netnode { db: self, id }
    }

    /// A write cursor on the netnode named `name`, creating it if it does not exist.
    ///
    /// The write half of [`netnode`](Self::netnode): the cursor is read-capable, so a
    /// read-modify-write stays on one handle. User node names conventionally start with `"$ "`.
    ///
    /// # Panics
    /// If the kernel reports an internal failure creating the node (it never has been observed to
    /// for a valid name).
    #[must_use]
    #[doc(alias("netnode::create"))]
    pub fn netnode_mut(&mut self, name: &str) -> NetnodeMut<'_> {
        let id = NodeId::try_new(self.netnode_create(name))
            .expect("netnode creation returned BADNODE for a valid name");
        NetnodeMut { db: self, id }
    }

    /// Lazily iterate every netnode in the database, in ascending id order.
    #[inline]
    #[must_use]
    #[doc(alias("netnode::start"))]
    pub fn netnodes(&self) -> Netnodes<'_> {
        Netnodes::new(self)
    }
}

/// A netnode id: any raw `nodeidx_t` other than the `BADNODE` sentinel.
///
/// The sentinel maps to [`None`], and a niche keeps `Option<NodeId>` the same size as a bare
/// [`u64`]. Id `0` is valid (the node mapped to address `0`); only `BADNODE` is excluded.
///
/// Ordering follows the real id: the niche stores `!raw`, so a *derived* `Ord` would compare
/// inverted bits and reverse it, and [`Ord`]/[`PartialOrd`] are hand-written over
/// [`get`](Self::get) instead.
///
/// ```
/// use idakit::NodeId;
/// assert!(NodeId::try_new(u64::MAX).is_none()); // BADNODE
/// assert_eq!(NodeId::try_new(0).unwrap().get(), 0);
/// assert_eq!(size_of::<Option<NodeId>>(), size_of::<u64>());
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[doc(alias("nodeidx_t"))]
pub struct NodeId(NonZeroU64);

impl NodeId {
    /// Wrap a raw node id. `None` only when `raw == BADNODE`.
    #[inline]
    #[must_use]
    #[doc(alias("BADNODE"))]
    pub const fn try_new(raw: u64) -> Option<Self> {
        // !BADNODE == 0, rejected by NonZeroU64; every other id is non-zero.
        match NonZeroU64::new(!raw) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    /// The raw node id.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u64 {
        !self.0.get()
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeId({:#x})", self.get())
    }
}

impl std::fmt::LowerHex for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(&self.get(), f)
    }
}

impl Ord for NodeId {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.get().cmp(&other.get())
    }
}

impl PartialOrd for NodeId {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<NodeId> for u64 {
    #[inline]
    fn from(id: NodeId) -> Self {
        id.get()
    }
}

// Serialize the real id, not the inverted niche a derive would emit: a `NodeId` round-trips as
// its `get()` value, and any non-sentinel `u64` deserializes back.
impl Serialize for NodeId {
    #[inline]
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.get())
    }
}

impl<'de> Deserialize<'de> for NodeId {
    #[inline]
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = u64::deserialize(deserializer)?;
        Self::try_new(raw)
            .ok_or_else(|| serde::de::Error::custom("node id is the BADNODE sentinel"))
    }
}

/// The read accessors shared by [`Netnode`] and [`NetnodeMut`].
///
/// Both key a [`Database`] by a `db` field and a `NodeId` field; every accessor returns an owned
/// value, so it mirrors identically onto the read view and the write cursor.
macro_rules! netnode_reads {
    () => {
        /// The id this handle is keyed by.
        #[inline]
        #[must_use]
        pub const fn id(&self) -> NodeId {
            self.id
        }

        /// The node's name, or `None` if it is unnamed.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::get_name"))]
        pub fn name(&self) -> Option<String> {
            self.db.netnode_get_name(self.id.get())
        }

        /// Whether the node exists (carries a name or any data).
        #[inline]
        #[must_use]
        #[doc(alias("netnode_exist"))]
        pub fn exists(&self) -> bool {
            self.db.netnode_exists(self.id.get())
        }

        /// The node value as raw bytes, or `None` if unset.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::valobj"))]
        pub fn value(&self) -> Option<Vec<u8>> {
            self.db.netnode_value(self.id.get())
        }

        /// The node value as a string, or `None` if unset.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::valstr"))]
        pub fn value_str(&self) -> Option<String> {
            self.db.netnode_value_str(self.id.get())
        }

        /// The altval at `index`, or `0` when unset (the SDK does not distinguish the two).
        #[inline]
        #[must_use]
        #[doc(alias("netnode::altval"))]
        pub fn altval(&self, index: u64) -> u64 {
            self.db
                .netnode_altval(self.id.get(), index, $crate::netnode::Tag::ALTVAL.raw())
        }

        /// The supval byte object at `index`, or `None` if unset.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::supval"))]
        pub fn supval(&self, index: u64) -> Option<Vec<u8>> {
            self.db
                .netnode_supval(self.id.get(), index, $crate::netnode::Tag::SUPVAL.raw())
        }

        /// The hash value for `key` as raw bytes, or `None` if the key is unset.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::hashval"))]
        pub fn hash(&self, key: &str) -> Option<Vec<u8>> {
            self.db
                .netnode_hashval(self.id.get(), key, $crate::netnode::Tag::HASH.raw())
        }

        /// The hash value for `key` decoded as an integer, or `0` when unset.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::hashval_long"))]
        pub fn hash_integer(&self, key: &str) -> u64 {
            self.db
                .netnode_hashval_long(self.id.get(), key, $crate::netnode::Tag::HASH.raw())
        }

        /// The default blob (`start = 0`), or `None` if the node holds none.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::getblob"))]
        pub fn blob(&self) -> Option<Vec<u8>> {
            self.db
                .netnode_getblob(self.id.get(), 0, $crate::netnode::Tag::BLOB.raw())
        }

        /// The byte length of the default blob (`start = 0`), or `0` when absent.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::blobsize"))]
        pub fn blob_size(&self) -> usize {
            self.db
                .netnode_blobsize(self.id.get(), 0, $crate::netnode::Tag::BLOB.raw())
        }

        /// Lazily iterate the altval array as `(index, value)` pairs, in ascending index order.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::altfirst"))]
        pub fn altvals(&self) -> $crate::netnode::Altvals<'_> {
            $crate::netnode::Altvals::new(&*self.db, self.id, $crate::netnode::Tag::ALTVAL.raw())
        }

        /// Lazily iterate the supval array as `(index, bytes)` pairs, in ascending index order.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::supfirst"))]
        pub fn supvals(&self) -> $crate::netnode::Supvals<'_> {
            $crate::netnode::Supvals::new(&*self.db, self.id, $crate::netnode::Tag::SUPVAL.raw())
        }

        /// Lazily iterate the hash as `(key, bytes)` pairs, in lexical key order.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::hashfirst"))]
        pub fn hash_entries(&self) -> $crate::netnode::HashEntries<'_> {
            $crate::netnode::HashEntries::new(&*self.db, self.id, $crate::netnode::Tag::HASH.raw())
        }

        /// Read a typed value stored under hash `key`, or `None` if the key is absent or its bytes
        /// do not decode as `T`.
        ///
        /// The read half of [`put`](NetnodeMut::put); see [`Persist`].
        #[inline]
        #[must_use]
        pub fn get<T: $crate::netnode::Persist>(&self, key: &str) -> Option<T> {
            self.hash(key)
                .and_then(|bytes| T::from_netnode_bytes(&bytes))
        }

        /// Whether hash `key` is set.
        #[inline]
        #[must_use]
        pub fn contains(&self, key: &str) -> bool {
            self.hash(key).is_some()
        }

        /// The `serde` value under hash `key`, or `None` if absent or undecodable.
        #[cfg(feature = "serde")]
        #[inline]
        #[must_use]
        pub fn get_serde<T: ::serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
            self.hash(key)
                .and_then(|bytes| ::postcard::from_bytes(&bytes).ok())
        }

        /// The `serde` value in the blob at `index`, or `None` if absent or undecodable.
        #[cfg(feature = "serde")]
        #[inline]
        #[must_use]
        pub fn get_serde_at<T: ::serde::de::DeserializeOwned>(&self, index: u64) -> Option<T> {
            self.db
                .netnode_getblob(self.id.get(), index, $crate::netnode::Tag::BLOB.raw())
                .and_then(|bytes| ::postcard::from_bytes(&bytes).ok())
        }
    };
}

/// Emit the write-cursor methods shared in shape by [`NetnodeMut`] and [`TaggedNetnodeMut`].
///
/// Each entry binds the receiver (the first identifier, conventionally `this`, since macro hygiene
/// bars a passed-in `expr` from seeing the method's own `self`) and gives a `=> expr` yielding the
/// raw `bool` success flag; the body routes it through the cursor's own `checked`, tagging the
/// [`Error::WriteRejected`] with the method name. That keeps it agnostic to the default-tag vs
/// explicit-[`Tag`] split.
macro_rules! write_ops {
    ($(
        $(#[$meta:meta])*
        fn $name:ident($this:ident $(, $arg:ident: $aty:ty)* $(,)?) => $call:expr;
    )*) => {$(
        $(#[$meta])*
        pub fn $name(&mut self $(, $arg: $aty)*) -> $crate::error::Result<()> {
            let $this = self;
            let ok = $call;
            $crate::netnode::checked(&*$this.db, $this.id, ok, stringify!($name))
        }
    )*};
}
pub(crate) use write_ops;

/// Emit the delete methods shared in shape by [`NetnodeMut`] and [`TaggedNetnodeMut`].
///
/// Same binding convention as [`write_ops!`], but the `=> expr` yields the answer directly. The
/// kernel's delete calls carry a single bit meaning "there was something to remove", with no error
/// channel beside it, so these return it as a `bool` the way [`HashSet::remove`](std::collections::HashSet::remove)
/// does rather than reporting an empty slot as a failed write.
macro_rules! delete_ops {
    ($(
        $(#[$meta:meta])*
        fn $name:ident($this:ident $(, $arg:ident: $aty:ty)* $(,)?) => $call:expr;
    )*) => {$(
        $(#[$meta])*
        pub fn $name(&mut self $(, $arg: $aty)*) -> bool {
            let $this = self;
            $call
        }
    )*};
}
pub(crate) use delete_ops;

/// A borrowed view of one netnode, keyed by [`NodeId`].
///
/// A cheap `Copy` handle that borrows the [`Database`] and re-queries per accessor, from
/// [`Database::netnode`] / [`Database::netnode_at`]. [`NetnodeMut`] is its write cursor.
#[derive(Clone, Copy)]
#[doc(alias("netnode"))]
pub struct Netnode<'db> {
    db: &'db Database,
    id: NodeId,
}

impl<'db> Netnode<'db> {
    netnode_reads!();

    /// A read view of this node's arrays under `tag`, for reaching non-default tags.
    #[inline]
    #[must_use]
    pub fn tag(self, tag: Tag) -> TaggedNetnode<'db> {
        TaggedNetnode::new(self.db, self.id, tag)
    }
}

impl std::fmt::Debug for Netnode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Netnode")
            .field("id", &self.id)
            .field("name", &self.name())
            .finish()
    }
}

key_identity!(Netnode, id, ord);

/// A write cursor on one netnode, from [`Database::netnode_mut`].
///
/// Holds the database exclusively (`&mut Database`) and is read-capable: the scalar [`Netnode`]
/// accessors are inherent here, so a read-modify-write stays on one cursor. Not `Copy`, and not
/// obtainable from a borrowing [`Netnode`].
#[doc(alias("netnode"))]
pub struct NetnodeMut<'db> {
    db: &'db mut Database,
    id: NodeId,
}

impl std::fmt::Debug for NetnodeMut<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetnodeMut")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl NetnodeMut<'_> {
    netnode_reads!();

    /// A read-write view of this node's arrays under `tag`, for reaching non-default tags.
    #[inline]
    pub fn tag(&mut self, tag: Tag) -> TaggedNetnodeMut<'_> {
        TaggedNetnodeMut::new(&mut *self.db, self.id, tag)
    }

    write_ops! {
        /// Set the altval at `index`.
        ///
        /// # Errors
        /// [`Error::WriteRejected`] if the kernel rejects the write.
        #[doc(alias("netnode::altset"))]
        fn set_altval(this, index: u64, value: u64) => this.db.netnode_altset(this.id.get(), index, value, Tag::ALTVAL.raw());

        /// Set the hash value for `key` to an integer.
        ///
        /// # Errors
        /// [`Error::WriteRejected`] if the kernel rejects the write.
        #[doc(alias("netnode::hashset"))]
        fn set_hash_integer(this, key: &str, value: u64) => this.db.netnode_hashset_long(this.id.get(), key, value, Tag::HASH.raw());

        /// Store the default blob (`start = 0`), replacing any existing one.
        ///
        /// # Errors
        /// [`Error::WriteRejected`] if the kernel rejects the write.
        #[doc(alias("netnode::setblob"))]
        fn set_blob(this, value: &[u8]) => this.db.netnode_setblob(this.id.get(), value, 0, Tag::BLOB.raw());

        /// Rename the node (an empty name clears it).
        ///
        /// # Errors
        /// [`Error::WriteRejected`] if the name is already taken.
        #[doc(alias("netnode::rename"))]
        fn rename(this, name: &str) => this.db.netnode_rename(this.id.get(), name);
    }

    delete_ops! {
        /// Delete the node value, returning whether one was set.
        #[doc(alias("netnode::delvalue"))]
        fn clear_value(this) => this.db.netnode_del_value(this.id.get());

        /// Delete the altval at `index`, returning whether it was set.
        #[doc(alias("netnode::altdel"))]
        fn remove_altval(this, index: u64) => this.db.netnode_altdel(this.id.get(), index, Tag::ALTVAL.raw());

        /// Delete every altval, returning whether any were set.
        #[doc(alias("netnode::altdel_all"))]
        fn clear_altvals(this) => this.db.netnode_altdel_all(this.id.get(), Tag::ALTVAL.raw());

        /// Delete the supval byte object at `index`, returning whether it was set.
        #[doc(alias("netnode::supdel"))]
        fn remove_supval(this, index: u64) => this.db.netnode_supdel(this.id.get(), index, Tag::SUPVAL.raw());

        /// Delete every supval byte object, returning whether any were set.
        #[doc(alias("netnode::supdel_all"))]
        fn clear_supvals(this) => this.db.netnode_supdel_all(this.id.get(), Tag::SUPVAL.raw());

        /// Delete the hash value for `key`, returning whether it was set.
        #[doc(alias("netnode::hashdel"))]
        fn remove_hash(this, key: &str) => this.db.netnode_hashdel(this.id.get(), key, Tag::HASH.raw());

        /// Delete every hash entry, returning whether any were set.
        #[doc(alias("netnode::hashdel_all"))]
        fn clear_hash(this) => this.db.netnode_hashdel_all(this.id.get(), Tag::HASH.raw());

        /// Delete the default blob (`start = 0`), returning whether one was stored.
        ///
        /// The kernel answers with the number of slots it freed, which is the blob's storage
        /// footprint rather than anything the caller chose, so only its sign is surfaced.
        #[doc(alias("netnode::delblob"))]
        fn remove_blob(this) => this.db.netnode_delblob(this.id.get(), 0, Tag::BLOB.raw()) > 0;
    }

    /// Set the node value, from 1 to [`NetnodeBytes::MAX_SIZE`] bytes.
    ///
    /// # Errors
    /// [`Error::InvalidNetnodeBytes`] if `value` is empty or exceeds [`NetnodeBytes::MAX_SIZE`],
    /// or [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::set"))]
    pub fn set_value<'a>(
        &mut self,
        value: impl TryInto<NetnodeBytes<'a>, Error: Into<NetnodeBytesError>>,
    ) -> Result<()> {
        let bytes: NetnodeBytes<'_> = value.try_into().map_err(Into::into)?;
        let ok = self.db.netnode_set_value(self.id.get(), bytes.as_bytes());
        checked(&*self.db, self.id, ok, "set_value")
    }

    /// Set the supval byte object at `index`, from 1 to [`NetnodeBytes::MAX_SIZE`] bytes.
    ///
    /// # Errors
    /// [`Error::InvalidNetnodeBytes`] if `value` is empty or exceeds [`NetnodeBytes::MAX_SIZE`],
    /// or [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::supset"))]
    pub fn set_supval<'a>(
        &mut self,
        index: u64,
        value: impl TryInto<NetnodeBytes<'a>, Error: Into<NetnodeBytesError>>,
    ) -> Result<()> {
        let bytes: NetnodeBytes<'_> = value.try_into().map_err(Into::into)?;
        let ok = self
            .db
            .netnode_supset(self.id.get(), index, bytes.as_bytes(), Tag::SUPVAL.raw());
        checked(&*self.db, self.id, ok, "set_supval")
    }

    /// Set the hash value for `key` to raw bytes, from 1 to [`NetnodeBytes::MAX_SIZE`] bytes.
    ///
    /// # Errors
    /// [`Error::InvalidNetnodeBytes`] if `value` is empty or exceeds [`NetnodeBytes::MAX_SIZE`],
    /// or [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::hashset"))]
    pub fn set_hash<'a>(
        &mut self,
        key: &str,
        value: impl TryInto<NetnodeBytes<'a>, Error: Into<NetnodeBytesError>>,
    ) -> Result<()> {
        let bytes: NetnodeBytes<'_> = value.try_into().map_err(Into::into)?;
        let ok = self
            .db
            .netnode_hashset(self.id.get(), key, bytes.as_bytes(), Tag::HASH.raw());
        checked(&*self.db, self.id, ok, "set_hash")
    }

    /// Store a typed value under hash `key`.
    ///
    /// The write half of [`get`](Netnode::get); the value is serialized through [`Persist`] and
    /// stored in the hash.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    pub fn put<T: Persist>(&mut self, key: &str, value: &T) -> Result<()> {
        self.set_hash(key, &value.to_netnode_bytes())
    }

    /// Remove the typed value (or any hash bytes) under `key`, returning whether it was set.
    ///
    /// The inverse of [`put`](Self::put).
    pub fn remove(&mut self, key: &str) -> bool {
        self.remove_hash(key)
    }

    /// Store `value` under hash `key` via serde (postcard); capped at 1024 bytes.
    ///
    /// # Errors
    /// [`Error::SerializeFailed`] on an encoding failure, or [`Error::WriteRejected`] if the kernel
    /// rejects the write (e.g. over the cap).
    #[cfg(feature = "serde")]
    pub fn put_serde<T: ::serde::Serialize>(&mut self, key: &str, value: &T) -> Result<()> {
        let bytes = ::postcard::to_allocvec(value).map_err(|e| Error::SerializeFailed {
            reason: e.to_string(),
        })?;
        self.set_hash(key, &bytes)
    }

    /// Store `value` in the blob at `index` via serde (postcard); uncapped.
    ///
    /// # Errors
    /// [`Error::SerializeFailed`] on an encoding failure, or [`Error::WriteRejected`] if the kernel
    /// rejects the write.
    #[cfg(feature = "serde")]
    #[doc(alias("netnode::setblob"))]
    pub fn put_serde_at<T: ::serde::Serialize>(&mut self, index: u64, value: &T) -> Result<()> {
        let bytes = ::postcard::to_allocvec(value).map_err(|e| Error::SerializeFailed {
            reason: e.to_string(),
        })?;
        let ok = self
            .db
            .netnode_setblob(self.id.get(), &bytes, index, Tag::BLOB.raw());
        checked(&*self.db, self.id, ok, "put_serde_at")
    }

    /// Delete the node and every array attached to it.
    ///
    /// The cursor is left pointing at the now-absent id; further reads return `None`.
    #[doc(alias("netnode::kill"))]
    pub fn kill(&mut self) {
        self.db.netnode_kill(self.id.get());
    }
}

/// A lazy iterator over every netnode in the database, in ascending id order, from
/// [`Database::netnodes`].
pub struct Netnodes<'db> {
    db: &'db Database,
    next: Option<NodeId>,
}

impl std::fmt::Debug for Netnodes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Netnodes")
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl<'db> Netnodes<'db> {
    pub(crate) fn new(db: &'db Database) -> Self {
        Self {
            db,
            next: NodeId::try_new(db.netnode_first()),
        }
    }
}

impl<'db> Iterator for Netnodes<'db> {
    type Item = Netnode<'db>;

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.next?;
        self.next = NodeId::try_new(self.db.netnode_next(id.get()));
        Some(Netnode { db: self.db, id })
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn netnode_mut_debug_renders_the_id() {
        let mut db = Database::new();
        let id = NodeId::try_new(1).unwrap();
        let cursor = NetnodeMut { db: &mut db, id };
        assert!(format!("{cursor:?}").starts_with("NetnodeMut"));
    }

    #[test]
    fn netnodes_debug_renders_the_cursor() {
        let db = Database::new();
        let iter = Netnodes {
            db: &db,
            next: NodeId::try_new(1),
        };
        assert!(format!("{iter:?}").starts_with("Netnodes"));
    }

    #[test]
    fn node_id_debug_renders_the_hex_id() {
        let id = NodeId::try_new(0x1234).unwrap();
        assert!(format!("{id:?}") == "NodeId(0x1234)");
    }

    #[test]
    fn node_id_lower_hex_matches_get() {
        let id = NodeId::try_new(0x1234).unwrap();
        assert!(format!("{id:x}") == "1234");
    }

    #[test]
    fn node_id_partial_cmp_orders_by_the_real_id() {
        let a = NodeId::try_new(1).unwrap();
        let b = NodeId::try_new(2).unwrap();
        assert!(a.partial_cmp(&b) == Some(std::cmp::Ordering::Less));
    }

    #[test]
    fn node_id_into_u64_is_the_real_id() {
        let id = NodeId::try_new(0x1234).unwrap();
        assert!(u64::from(id) == 0x1234);
    }

    #[test]
    fn node_id_serde_round_trips_as_the_real_id() {
        let id = NodeId::try_new(0x1234).unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert!(json == id.get().to_string());
        let back: NodeId = serde_json::from_str(&json).unwrap();
        assert!(back == id);
    }

    #[test]
    fn node_id_serde_rejects_the_sentinel() {
        assert!(serde_json::from_str::<NodeId>(&BADNODE.to_string()).is_err());
    }
}
