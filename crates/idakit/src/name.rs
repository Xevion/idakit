//! Name lookup and enumeration: [`Idb::name`], [`Idb::address_of`], [`Idb::demangle`], and the
//! [`Names`] iterator over the database's name list.

use crate::Idb;
use crate::address::Address;
use crate::error::{Error, Result};
use crate::ffi::{read_string, with_cstr};

impl Idb {
    /// The name at `address` -- a label, function, or data name -- or `None` if the address is
    /// unnamed. This is the whole-database counterpart to [`Function::name`](crate::Function::name),
    /// which is specific to a function entry.
    #[must_use]
    pub fn name(&self, address: Address) -> Option<String> {
        read_string(|buf, cap| self.get_ea_name(address, buf, cap))
    }

    /// The address a name resolves to, or `None` if no such name exists. A name with an
    /// interior NUL can name nothing, so it too yields `None`. The inverse of
    /// [`name`](Self::name).
    #[must_use]
    pub fn address_of(&self, name: &str) -> Option<Address> {
        with_cstr(name, "name", |p| Address::try_new(self.get_name_ea(p)))
            .ok()
            .flatten()
    }

    /// Demangle a mangled symbol into readable form, or `None` if `name` is not a mangled
    /// name (or carries an interior NUL). Names read from the database are already display
    /// form; this is for turning a raw linker symbol back into source-level text.
    #[must_use]
    pub fn demangle(&self, name: &str) -> Option<String> {
        with_cstr(name, "name", |p| {
            read_string(|buf, cap| self.demangle_name(p, buf, cap))
        })
        .ok()
        .flatten()
    }

    /// Lazily iterate every named address in the database, in the kernel's name-list order.
    #[must_use]
    pub fn names(&self) -> Names<'_> {
        Names::new(self)
    }

    /// Rename the item at `address`.
    pub fn rename(&mut self, address: Address, name: &str) -> Result<()> {
        let ok = with_cstr(name, "name", |p| self.set_name(address, p))?;
        if ok {
            Ok(())
        } else {
            let (qerrno, reason) = self.last_reason();
            Err(Error::WriteRejected {
                op: "rename",
                address: address.get(),
                qerrno,
                reason,
            })
        }
    }

    // TODO: enumerate strings, imports/exports, and entry points.
}

/// A named address from the database's name list, yielded by [`Names`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name {
    /// The named address.
    pub address: Address,
    /// The name at that address.
    pub name: String,
}

/// Lazy iterator over every named address, in the kernel's name-list order, from
/// [`Idb::names`].
pub struct Names<'db> {
    db: &'db Idb,
    next: usize,
    count: usize,
}

impl<'db> Names<'db> {
    #[inline]
    pub(crate) fn new(db: &'db Idb) -> Self {
        Self {
            db,
            next: 0,
            count: db.nlist_size(),
        }
    }
}

impl Iterator for Names<'_> {
    type Item = Name;

    fn next(&mut self) -> Option<Name> {
        while self.next < self.count {
            let idx = self.next;
            self.next += 1;
            if let Some(address) = Address::try_new(self.db.nlist_ea(idx)) {
                let name =
                    read_string(|buf, cap| self.db.nlist_name(idx, buf, cap)).unwrap_or_default();
                return Some(Name { address, name });
            }
        }
        None
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.count - self.next))
    }
}

#[cfg(test)]
mod tests {
    use super::Name;

    const fn assert_send<T: Send>() {}

    // A `Name` owns its string and address, so it can travel off the kernel thread.
    const _: () = assert_send::<Name>();
}
