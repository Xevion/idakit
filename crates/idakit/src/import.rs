//! [`Import`]: one imported symbol, read from the database's import table.

use std::ffi::c_void;
use std::marker::PhantomData;

use idakit_sys as sys;

use crate::Idb;
use crate::address::Address;
use crate::ffi::read_string;

impl Idb {
    /// Iterate every imported symbol, across all import modules.
    ///
    /// Unlike [`segments`](Idb::segments)/[`exports`](Idb::exports), imports have no stable
    /// random-access index in IDA, so this materializes a snapshot of the whole import table and
    /// yields owned [`Import`]s from it; the snapshot is released when the iterator drops.
    #[inline]
    #[must_use]
    pub fn imports(&self) -> Imports<'_> {
        Imports::new(self.imports_build())
    }
}

/// One imported symbol: an import-table slot (IAT entry / thunk) bound to a symbol in some
/// module. Carries a [`name`](Self::name), an [`ordinal`](Self::ordinal), or -- for a
/// by-ordinal import IDA has resolved a name for -- both; they are not mutually exclusive.
/// Owned, as it outlives the snapshot it was read from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Import {
    address: Address,
    ordinal: u64,
    name: Option<String>,
    module: String,
}

impl Import {
    /// The import-table slot address -- the IAT entry / thunk this import resolves.
    #[inline]
    #[must_use]
    pub fn address(&self) -> Address {
        self.address
    }

    /// The imported symbol name -- present for a by-name import, or when IDA has resolved a
    /// name for a by-ordinal one; `None` for a bare by-ordinal import.
    #[inline]
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The import ordinal, or `None` when imported by [`name`](Self::name). IDA encodes
    /// "by name" as ordinal `0`, which maps to `None` here.
    #[inline]
    #[must_use]
    pub fn ordinal(&self) -> Option<u64> {
        (self.ordinal != 0).then_some(self.ordinal)
    }

    /// The module the symbol is imported from (e.g. `"KERNEL32"`); may be empty if the input
    /// format records none.
    #[inline]
    #[must_use]
    pub fn module(&self) -> &str {
        &self.module
    }
}

/// Lazy iterator over the database's imports; frees the snapshot on drop. Borrows `&Idb`, so it
/// can't outlive the database or coexist with a write. `size_hint`'s lower bound is `0`: a slot
/// with no valid address is skipped.
pub struct Imports<'db> {
    handle: *mut c_void,
    next: usize,
    count: usize,
    _db: PhantomData<&'db Idb>,
}

impl Imports<'_> {
    #[inline]
    pub(crate) fn new(handle: *mut c_void) -> Self {
        // SAFETY: `handle` came from `idakit_imports_build` (never null) and is freed once, in Drop.
        let count = unsafe { sys::idakit_imports_qty(handle) };
        Self {
            handle,
            next: 0,
            count,
            _db: PhantomData,
        }
    }

    /// Read row `n` of the snapshot into an owned [`Import`], or `None` if its slot address is
    /// `BADADDR` (nothing usable to point at).
    fn row(&self, n: usize) -> Option<Import> {
        let (mut ea, mut ord) = (0u64, 0u64);
        // SAFETY: `handle` is live until Drop; `n < count`; the out-pointers are valid locals.
        if unsafe { sys::idakit_imports_item(self.handle, n, &mut ea, &mut ord) } == 0 {
            return None;
        }
        let address = Address::try_new(ea)?;
        // SAFETY (both): `handle` live, `n` in range; the getters fill `(buf, cap)` snprintf-style.
        let name =
            read_string(|buf, cap| unsafe { sys::idakit_imports_name(self.handle, n, buf, cap) });
        let module =
            read_string(|buf, cap| unsafe { sys::idakit_imports_module(self.handle, n, buf, cap) })
                .unwrap_or_default();
        Some(Import {
            address,
            ordinal: ord,
            name,
            module,
        })
    }
}

impl Iterator for Imports<'_> {
    type Item = Import;

    fn next(&mut self) -> Option<Import> {
        while self.next < self.count {
            let n = self.next;
            self.next += 1;
            if let Some(import) = self.row(n) {
                return Some(import);
            }
        }
        None
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.count - self.next))
    }
}

impl Drop for Imports<'_> {
    fn drop(&mut self) {
        // SAFETY: `handle` came from `idakit_imports_build` and is freed exactly once here.
        unsafe { sys::idakit_imports_free(self.handle) };
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
}
