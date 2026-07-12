//! Reads and writes IDA's persistent per-database store through the [`Netnode`] view and
//! [`NetnodeMut`] cursor.
//!
//! A netnode is IDA's lowest-level persistence primitive: a node, addressed by a [`NodeId`] or a
//! name, carrying a single value plus several typed arrays. idakit surfaces the arrays as native
//! Rust collections and hides IDA's 8-bit tag selectors behind fixed defaults:
//!
//! - the **alt** array ([`alts`](Netnode::alts)), a sparse map of [`u64`] indices to [`u64`] values;
//! - the **sup** array ([`sups`](Netnode::sups)), a sparse map of [`u64`] indices to byte objects;
//! - the **hash** ([`hash_entries`](Netnode::hash_entries)), a string-keyed map of byte objects, and
//!   the typed key/value store ([`get`](Netnode::get)/[`put`](NetnodeMut::put)) layered on it;
//! - **blobs** ([`blob`](Netnode::blob)), unlimited-size byte objects.
//!
//! [`Netnode`] reads (absence is [`None`], never an error); [`NetnodeMut`], acquired by
//! [`netnode_mut`](Database::netnode_mut) from `&mut Database`, writes. The whole layer holds no
//! kernel handle and needs no `unsafe`: a netnode is a value over its [`NodeId`], so the views are
//! plain `Database`-bound borrows over safe FFI.
//!
//! Char values and non-default tags are the raw-FFI surface's domain (`idakit_sys::netnode_*`);
//! this layer is the curated, idiomatic subset.

mod arrays;
mod persist;

use std::num::NonZeroU64;

use crate::Database;
use crate::error::{Error, Result};

pub use self::arrays::{Alts, HashEntries, Sups};
pub use self::persist::Persist;

/// The reserved tag of the alt array (`atag`).
const ATAG: u32 = b'A' as u32;
/// The reserved tag of the sup array (`stag`), also backing byte objects and blobs by default.
const STAG: u32 = b'S' as u32;
/// The reserved tag of the hash (`htag`), backing the string-keyed and typed stores.
const HTAG: u32 = b'H' as u32;
/// idakit's default blob tag, a free user tag kept distinct from [`STAG`] so [`Netnode::blob`]
/// never collides with the [`sups`](Netnode::sups) array.
const BTAG: u32 = b'B' as u32;

/// The bad-node sentinel (`BADNODE`), the niche of [`NodeId`].
const BADNODE: u64 = u64::MAX;

impl Database {
    /// The netnode named `name`, or `None` if no such node exists.
    ///
    /// Does not create the node. User nodes conventionally prefix their name with `"$ "` to avoid
    /// clashing with program symbol names.
    #[must_use]
    #[doc(alias("netnode::netnode", "netnode_check"))]
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
    #[doc(alias("netnode::create", "netnode_check"))]
    pub fn netnode_mut(&mut self, name: &str) -> NetnodeMut<'_> {
        let id = NodeId::try_new(self.netnode_create(name))
            .expect("netnode creation returned BADNODE for a valid name");
        NetnodeMut { db: self, id }
    }

    /// Lazily iterate every netnode in the database, in ascending id order.
    #[inline]
    #[must_use]
    #[doc(alias("netnode::start", "netnode_start"))]
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
        #[doc(alias("netnode::get_name", "netnode_get_name"))]
        pub fn name(&self) -> Option<String> {
            self.db.netnode_get_name(self.id.get())
        }

        /// Whether the node exists (carries a name or any data).
        #[inline]
        #[must_use]
        #[doc(alias("netnode_exist", "netnode_exists"))]
        pub fn exists(&self) -> bool {
            self.db.netnode_exists(self.id.get())
        }

        /// The node value as raw bytes, or `None` if unset.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::valobj", "netnode_value"))]
        pub fn value(&self) -> Option<Vec<u8>> {
            self.db.netnode_value(self.id.get())
        }

        /// The node value as a string, or `None` if unset.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::valstr", "netnode_value_str"))]
        pub fn value_str(&self) -> Option<String> {
            self.db.netnode_value_str(self.id.get())
        }

        /// The alt value at `index`, or `0` when unset (the SDK does not distinguish the two).
        #[inline]
        #[must_use]
        #[doc(alias("netnode::altval", "netnode_altval"))]
        pub fn alt(&self, index: u64) -> u64 {
            self.db
                .netnode_altval(self.id.get(), index, $crate::netnode::ATAG)
        }

        /// The sup byte object at `index`, or `None` if unset.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::supval", "netnode_supval"))]
        pub fn sup(&self, index: u64) -> Option<Vec<u8>> {
            self.db
                .netnode_supval(self.id.get(), index, $crate::netnode::STAG)
        }

        /// The hash value for `key` as raw bytes, or `None` if the key is unset.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::hashval", "netnode_hashval"))]
        pub fn hash(&self, key: &str) -> Option<Vec<u8>> {
            self.db
                .netnode_hashval(self.id.get(), key, $crate::netnode::HTAG)
        }

        /// The hash value for `key` decoded as an integer, or `0` when unset.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::hashval_long", "netnode_hashval_long"))]
        pub fn hash_int(&self, key: &str) -> u64 {
            self.db
                .netnode_hashval_long(self.id.get(), key, $crate::netnode::HTAG)
        }

        /// The default blob (`start = 0`), or `None` if the node holds none.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::getblob", "netnode_getblob"))]
        pub fn blob(&self) -> Option<Vec<u8>> {
            self.db
                .netnode_getblob(self.id.get(), 0, $crate::netnode::BTAG)
        }

        /// The byte length of the default blob (`start = 0`), or `0` when absent.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::blobsize", "netnode_blobsize"))]
        pub fn blob_size(&self) -> usize {
            self.db
                .netnode_blobsize(self.id.get(), 0, $crate::netnode::BTAG)
        }

        /// Lazily iterate the alt array as `(index, value)` pairs, in ascending index order.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::altfirst", "netnode_altfirst"))]
        pub fn alts(&self) -> $crate::netnode::Alts<'_> {
            $crate::netnode::Alts::new(&*self.db, self.id)
        }

        /// Lazily iterate the sup array as `(index, bytes)` pairs, in ascending index order.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::supfirst", "netnode_supfirst"))]
        pub fn sups(&self) -> $crate::netnode::Sups<'_> {
            $crate::netnode::Sups::new(&*self.db, self.id)
        }

        /// Lazily iterate the hash as `(key, bytes)` pairs, in lexical key order.
        #[inline]
        #[must_use]
        #[doc(alias("netnode::hashfirst", "netnode_hashfirst"))]
        pub fn hash_entries(&self) -> $crate::netnode::HashEntries<'_> {
            $crate::netnode::HashEntries::new(&*self.db, self.id)
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
                .netnode_getblob(self.id.get(), index, $crate::netnode::BTAG)
                .and_then(|bytes| ::postcard::from_bytes(&bytes).ok())
        }
    };
}

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

impl Netnode<'_> {
    netnode_reads!();
}

impl std::fmt::Debug for Netnode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Netnode")
            .field("id", &self.id)
            .field("name", &self.name())
            .finish()
    }
}

// Identity is the id alone; the `db` borrow is incidental and must not participate, so these are
// hand-written rather than derived.
impl PartialEq for Netnode<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.id == o.id
    }
}
impl Eq for Netnode<'_> {}
impl std::hash::Hash for Netnode<'_> {
    fn hash<H: std::hash::Hasher>(&self, s: &mut H) {
        self.id.hash(s);
    }
}
impl Ord for Netnode<'_> {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.id.cmp(&o.id)
    }
}
impl PartialOrd for Netnode<'_> {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

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

impl NetnodeMut<'_> {
    netnode_reads!();

    /// Set the node value (max 1024 bytes).
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::set", "netnode_set_value"))]
    pub fn set_value(&mut self, value: &[u8]) -> Result<()> {
        let ok = self.db.netnode_set_value(self.id.get(), value);
        self.checked(ok, "set_value")
    }

    /// Delete the node value.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::delvalue", "netnode_del_value"))]
    pub fn clear_value(&mut self) -> Result<()> {
        let ok = self.db.netnode_del_value(self.id.get());
        self.checked(ok, "clear_value")
    }

    /// Set the alt value at `index`.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::altset", "netnode_altset"))]
    pub fn set_alt(&mut self, index: u64, value: u64) -> Result<()> {
        let ok = self.db.netnode_altset(self.id.get(), index, value, ATAG);
        self.checked(ok, "set_alt")
    }

    /// Delete the alt value at `index`.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::altdel", "netnode_altdel"))]
    pub fn remove_alt(&mut self, index: u64) -> Result<()> {
        let ok = self.db.netnode_altdel(self.id.get(), index, ATAG);
        self.checked(ok, "remove_alt")
    }

    /// Delete every alt value.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::altdel_all", "netnode_altdel_all"))]
    pub fn clear_alts(&mut self) -> Result<()> {
        let ok = self.db.netnode_altdel_all(self.id.get(), ATAG);
        self.checked(ok, "clear_alts")
    }

    /// Set the sup byte object at `index` (max 1024 bytes).
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::supset", "netnode_supset"))]
    pub fn set_sup(&mut self, index: u64, value: &[u8]) -> Result<()> {
        let ok = self.db.netnode_supset(self.id.get(), index, value, STAG);
        self.checked(ok, "set_sup")
    }

    /// Delete the sup byte object at `index`.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::supdel", "netnode_supdel"))]
    pub fn remove_sup(&mut self, index: u64) -> Result<()> {
        let ok = self.db.netnode_supdel(self.id.get(), index, STAG);
        self.checked(ok, "remove_sup")
    }

    /// Delete every sup byte object.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::supdel_all", "netnode_supdel_all"))]
    pub fn clear_sups(&mut self) -> Result<()> {
        let ok = self.db.netnode_supdel_all(self.id.get(), STAG);
        self.checked(ok, "clear_sups")
    }

    /// Set the hash value for `key` to raw bytes (max 1024 bytes).
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::hashset", "netnode_hashset"))]
    pub fn set_hash(&mut self, key: &str, value: &[u8]) -> Result<()> {
        let ok = self.db.netnode_hashset(self.id.get(), key, value, HTAG);
        self.checked(ok, "set_hash")
    }

    /// Set the hash value for `key` to an integer.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::hashset", "netnode_hashset_long"))]
    pub fn set_hash_int(&mut self, key: &str, value: u64) -> Result<()> {
        let ok = self
            .db
            .netnode_hashset_long(self.id.get(), key, value, HTAG);
        self.checked(ok, "set_hash_int")
    }

    /// Delete the hash value for `key`.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::hashdel", "netnode_hashdel"))]
    pub fn remove_hash(&mut self, key: &str) -> Result<()> {
        let ok = self.db.netnode_hashdel(self.id.get(), key, HTAG);
        self.checked(ok, "remove_hash")
    }

    /// Delete every hash entry.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::hashdel_all", "netnode_hashdel_all"))]
    pub fn clear_hash(&mut self) -> Result<()> {
        let ok = self.db.netnode_hashdel_all(self.id.get(), HTAG);
        self.checked(ok, "clear_hash")
    }

    /// Store the default blob (`start = 0`), replacing any existing one.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    #[doc(alias("netnode::setblob", "netnode_setblob"))]
    pub fn set_blob(&mut self, value: &[u8]) -> Result<()> {
        let ok = self.db.netnode_setblob(self.id.get(), value, 0, BTAG);
        self.checked(ok, "set_blob")
    }

    /// Delete the default blob (`start = 0`).
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write (returning no freed slots).
    #[doc(alias("netnode::delblob", "netnode_delblob"))]
    pub fn remove_blob(&mut self) -> Result<()> {
        let freed = self.db.netnode_delblob(self.id.get(), 0, BTAG);
        self.checked(freed >= 0, "remove_blob")
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

    /// Remove the typed value (or any hash bytes) under `key`, the inverse of [`put`](Self::put).
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    pub fn remove(&mut self, key: &str) -> Result<()> {
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
    pub fn put_serde_at<T: ::serde::Serialize>(&mut self, index: u64, value: &T) -> Result<()> {
        let bytes = ::postcard::to_allocvec(value).map_err(|e| Error::SerializeFailed {
            reason: e.to_string(),
        })?;
        let ok = self.db.netnode_setblob(self.id.get(), &bytes, index, BTAG);
        self.checked(ok, "put_serde_at")
    }

    /// Rename the node (an empty name clears it).
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the name is already taken.
    #[doc(alias("netnode::rename", "netnode_rename"))]
    pub fn rename(&mut self, name: &str) -> Result<()> {
        let ok = self.db.netnode_rename(self.id.get(), name);
        self.checked(ok, "rename")
    }

    /// Delete the node and every array attached to it.
    ///
    /// The cursor is left pointing at the now-absent id; further reads return `None`.
    #[doc(alias("netnode::kill", "netnode_kill"))]
    pub fn kill(&mut self) {
        self.db.netnode_kill(self.id.get());
    }

    /// Map a boolean write result to `Result`, building an [`Error::WriteRejected`] from the
    /// kernel's error channel on failure.
    fn checked(&self, ok: bool, op: &'static str) -> Result<()> {
        if ok {
            return Ok(());
        }
        let (qerrno, reason) = self.db.last_reason();
        Err(Error::WriteRejected {
            op,
            address: self.id.get(),
            qerrno,
            reason,
        })
    }
}

/// A lazy iterator over every netnode in the database, in ascending id order, from
/// [`Database::netnodes`].
pub struct Netnodes<'db> {
    db: &'db Database,
    next: Option<NodeId>,
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
