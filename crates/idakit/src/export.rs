//! Enumerates a database's exports and reads them through the [`Export`] view.

use crate::Database;
use crate::address::Address;

impl Database {
    /// Iterate every export (entry point) in the database, in kernel order.
    #[inline]
    #[must_use]
    #[doc(alias("get_entry_qty"))]
    pub fn exports(&self) -> Exports<'_> {
        Exports::new(self)
    }
}

/// A borrowed view of one export (entry point), keyed by kernel index.
///
/// A pure re-export has no local [`address`](Self::address) and resolves through a
/// [`forwarder`](Self::forwarder) instead.
#[derive(Clone, Copy)]
#[doc(alias("get_entry"))]
pub struct Export<'db> {
    index: usize,
    db: &'db Database,
}

impl<'db> Export<'db> {
    #[inline]
    pub(crate) fn new(index: usize, db: &'db Database) -> Self {
        Self { index, db }
    }

    /// The export's position in the entry table (not its [`ordinal`](Self::ordinal)).
    #[inline]
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// The export's address, or `None` for a pure forwarder that resolves elsewhere.
    #[inline]
    #[must_use]
    #[doc(alias("get_entry"))]
    pub fn address(&self) -> Option<Address> {
        Address::try_new(self.db.export_ea(self.index))
    }

    /// The export's ordinal, or, for a name-only entry with no ordinal, its entry index.
    #[inline]
    #[must_use]
    #[doc(alias("get_entry_ordinal"))]
    pub fn ordinal(&self) -> u64 {
        self.db.export_ordinal(self.index)
    }

    /// The export's name, or `None` if it is unnamed.
    #[must_use]
    #[doc(alias("get_entry_name"))]
    pub fn name(&self) -> Option<String> {
        self.db.export_name(self.index)
    }

    /// The forward target (e.g. `"OTHERLIB.func"`), or `None` when the export is defined here.
    #[must_use]
    #[doc(alias("get_entry_forwarder"))]
    pub fn forwarder(&self) -> Option<String> {
        self.db.export_forwarder(self.index)
    }
}

impl std::fmt::Debug for Export<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Export")
            .field("index", &self.index)
            .field("name", &self.name())
            .field("address", &self.address())
            .field("ordinal", &self.ordinal())
            .finish()
    }
}

key_identity!(Export, index);

/// A lazy iterator over every export in the database, in kernel order, from
/// [`Database::exports`].
pub struct Exports<'db> {
    db: &'db Database,
    next: usize,
    count: usize,
}

impl<'db> Exports<'db> {
    #[inline]
    pub(crate) fn new(db: &'db Database) -> Self {
        Self {
            db,
            next: 0,
            count: db.export_qty(),
        }
    }
}

impl<'db> Iterator for Exports<'db> {
    type Item = Export<'db>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.count {
            return None;
        }
        let export = Export::new(self.next, self.db);
        self.next += 1;
        Some(export)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.count - self.next;
        (rem, Some(rem))
    }
}

impl ExactSizeIterator for Exports<'_> {}
