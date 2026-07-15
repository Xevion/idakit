//! Reads a database's import table through [`Import`] and [`Imports`].

use idakit_sys as sys;
use serde::{Deserialize, Serialize};

use crate::Database;
use crate::address::Address;

impl Database {
    /// Iterate every imported symbol, across all import modules.
    ///
    /// Unlike [`segments`](Database::segments)/[`exports`](Database::exports), imports have no stable
    /// random-access index in IDA, so this materializes a snapshot of the whole import table and
    /// yields owned [`Import`]s from it.
    #[inline]
    #[must_use]
    #[doc(alias("enum_import_names", "get_import_module_qty"))]
    pub fn imports(&self) -> Imports {
        Imports::new(self.imports_build())
    }
}

/// An owned import-table slot (IAT entry / thunk) bound to a symbol in some module, read from
/// a snapshot of the import table.
///
/// Carries a [`name`](Self::name), an [`ordinal`](Self::ordinal), or, for a by-ordinal import
/// IDA has resolved a name for, both; they are not mutually exclusive. It outlives the
/// snapshot it was read from.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[doc(alias("enum_import_names"))]
pub struct Import {
    address: Address,
    ordinal: u64,
    name: Option<String>,
    module: String,
}

impl Import {
    /// The import-table slot address: the IAT entry / thunk this import resolves.
    #[inline]
    #[must_use]
    pub fn address(&self) -> Address {
        self.address
    }

    /// The imported symbol name, present for a by-name import, or when IDA has resolved a name
    /// for a by-ordinal one; `None` for a bare by-ordinal import.
    #[inline]
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The import ordinal, or `None` when imported by [`name`](Self::name).
    ///
    /// IDA encodes "by name" as ordinal `0`, which maps to `None` here.
    #[inline]
    #[must_use]
    pub fn ordinal(&self) -> Option<u64> {
        (self.ordinal != 0).then_some(self.ordinal)
    }

    /// The module the symbol is imported from (e.g. `"KERNEL32"`); may be empty if the input
    /// format records none.
    #[inline]
    #[must_use]
    #[doc(alias("get_import_module_name"))]
    pub fn module(&self) -> &str {
        &self.module
    }
}

/// A lazy iterator over the database's imports, from [`Database::imports`].
///
/// Owns a materialized snapshot of the import table, so it holds no database borrow while
/// iterating. `size_hint`'s lower bound is `0`: a slot with no valid address is skipped.
pub struct Imports {
    rows: std::vec::IntoIter<Import>,
}

impl Imports {
    #[inline]
    pub(crate) fn new(recs: Vec<sys::ImportRec>) -> Self {
        let rows = recs
            .into_iter()
            .filter_map(Import::from_rec)
            .collect::<Vec<_>>()
            .into_iter();
        Self { rows }
    }
}

impl Import {
    /// Builds an owned [`Import`] from a snapshot row, or `None` if its slot address is `BADADDR`
    /// (nothing usable to point at). IDA encodes an absent name as an empty string, folded to
    /// `None` here.
    fn from_rec(rec: sys::ImportRec) -> Option<Self> {
        let address = Address::try_new(rec.ea)?;
        Some(Self {
            address,
            ordinal: rec.ord,
            name: (!rec.name.is_empty()).then_some(rec.name),
            module: rec.module,
        })
    }
}

impl Iterator for Imports {
    type Item = Import;

    #[inline]
    fn next(&mut self) -> Option<Import> {
        self.rows.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.rows.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    fn import(ordinal: u64, name: Option<&str>) -> Import {
        Import {
            address: Address::new_const(0x1000),
            ordinal,
            name: name.map(str::to_owned),
            module: "KERNEL32".to_owned(),
        }
    }

    /// A by-name import (ordinal `0`) exposes its name and no ordinal.
    #[test]
    fn by_name_has_no_ordinal() {
        let i = import(0, Some("CreateFileW"));
        assert!(i.name() == Some("CreateFileW"));
        assert!(i.ordinal() == None);
    }

    /// A by-ordinal import (no name) exposes its ordinal and no name.
    #[test]
    fn by_ordinal_has_no_name() {
        let i = import(12, None);
        assert!(i.ordinal() == Some(12));
        assert!(i.name() == None);
    }

    #[test]
    fn module_is_exposed() {
        assert!(import(0, Some("f")).module() == "KERNEL32");
    }

    /// Ordering follows the address field first, matching the struct's declared field order.
    #[test]
    fn ord_follows_address() {
        let low = Import {
            address: Address::new_const(0x1000),
            ..import(0, None)
        };
        let high = Import {
            address: Address::new_const(0x2000),
            ..import(0, None)
        };
        assert!(low < high);
    }

    #[test]
    fn serde_round_trips() {
        let i = import(12, Some("CreateFileW"));
        let json = serde_json::to_string(&i).unwrap();
        let back: Import = serde_json::from_str(&json).unwrap();
        assert!(back == i);
    }
}
