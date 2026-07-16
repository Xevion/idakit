//! Looks up and enumerates a database's names through [`Database::name`],
//! [`Database::name_with`] (and its dedicated wrappers [`Database::visible_name`],
//! [`Database::short_name`], [`Database::long_name`], [`Database::demangled_name`]),
//! [`Database::address_of`], [`Database::demangle`], [`Database::is_public_name`],
//! [`Database::is_weak_name`], and the [`Names`] iterator.

pub use idakit_sys::GnFlags;
use serde::{Deserialize, Serialize};

use crate::Database;
use crate::address::Address;

impl Database {
    /// The name at `address` (a label, function, or data name), or `None` if the address is
    /// unnamed.
    ///
    /// This is the whole-database counterpart to
    /// [`Function::name`](crate::function::Function::name), which is specific to a function
    /// entry.
    #[must_use]
    #[doc(alias("get_ea_name"))]
    pub fn name(&self, address: Address) -> Option<String> {
        self.get_ea_name(address)
    }

    /// The name at `address` under `flags`, or `None` if the address has no matching name.
    ///
    /// Collapses the SDK's `get_visible_name`/`get_short_name`/`get_long_name`/
    /// `get_demangled_name` convenience wrappers into one call: reach for
    /// [`Database::visible_name`], [`Database::short_name`], [`Database::long_name`], or
    /// [`Database::demangled_name`] for those directly, and use this to compose a flag
    /// combination none of them cover. [`Database::name`] is the plain, zero-flag form of this
    /// call.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// use idakit::GnFlags;
    ///
    /// let address = db.functions().next().unwrap().address();
    /// let flags = GnFlags::VISIBLE | GnFlags::DEMANGLED | GnFlags::SHORT;
    /// assert_eq!(db.name_with(address, flags), db.short_name(address));
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[must_use]
    #[doc(alias(
        "get_ea_name",
        "get_visible_name",
        "get_short_name",
        "get_long_name",
        "get_demangled_name"
    ))]
    pub fn name_with(&self, address: Address, flags: GnFlags) -> Option<String> {
        self.get_ea_name_flags(address, flags.bits())
    }

    /// The display-safe name at `address`, with forbidden characters substituted, or `None` if
    /// the address is unnamed.
    ///
    /// The SDK's `get_visible_name` convenience wrapper: [`Database::name_with`] under
    /// [`GnFlags::VISIBLE`].
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let address = db.functions().next().unwrap().address();
    /// let _ = db.visible_name(address);
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[must_use]
    #[doc(alias("get_visible_name"))]
    pub fn visible_name(&self, address: Address) -> Option<String> {
        self.name_with(address, GnFlags::VISIBLE)
    }

    /// The short demangled name at `address`, or `None` if the address is unnamed.
    ///
    /// The SDK's `get_short_name` convenience wrapper: [`Database::name_with`] under
    /// [`GnFlags::VISIBLE`] `|` [`GnFlags::DEMANGLED`] `|` [`GnFlags::SHORT`].
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let address = db.functions().next().unwrap().address();
    /// let _ = db.short_name(address);
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[must_use]
    #[doc(alias("get_short_name"))]
    pub fn short_name(&self, address: Address) -> Option<String> {
        self.name_with(
            address,
            GnFlags::VISIBLE | GnFlags::DEMANGLED | GnFlags::SHORT,
        )
    }

    /// The long demangled name at `address`, or `None` if the address is unnamed.
    ///
    /// The SDK's `get_long_name` convenience wrapper: [`Database::name_with`] under
    /// [`GnFlags::VISIBLE`] `|` [`GnFlags::DEMANGLED`] `|` [`GnFlags::LONG`].
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let address = db.functions().next().unwrap().address();
    /// let _ = db.long_name(address);
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[must_use]
    #[doc(alias("get_long_name"))]
    pub fn long_name(&self, address: Address) -> Option<String> {
        self.name_with(
            address,
            GnFlags::VISIBLE | GnFlags::DEMANGLED | GnFlags::LONG,
        )
    }

    /// The demangled name at `address`, or `None` if the address is unnamed or its name does
    /// not demangle.
    ///
    /// Approximates the SDK's `get_demangled_name`, which additionally takes demangling
    /// inhibitor/form arguments this crate does not yet expose: [`Database::name_with`] under
    /// plain [`GnFlags::DEMANGLED`].
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let address = db.functions().next().unwrap().address();
    /// let _ = db.demangled_name(address);
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[must_use]
    #[doc(alias("get_demangled_name"))]
    pub fn demangled_name(&self, address: Address) -> Option<String> {
        self.name_with(address, GnFlags::DEMANGLED)
    }

    /// Whether the name at `address` is public (exported for external linkage), or `false` if
    /// the address is unnamed.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let address = db.functions().next().unwrap().address();
    /// let _ = db.is_public_name(address);
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[must_use]
    pub fn is_public_name(&self, address: Address) -> bool {
        self.is_public_name_ea(address)
    }

    /// Whether the name at `address` is weak (may be overridden by another definition), or
    /// `false` if the address is unnamed.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let address = db.functions().next().unwrap().address();
    /// let _ = db.is_weak_name(address);
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[must_use]
    pub fn is_weak_name(&self, address: Address) -> bool {
        self.is_weak_name_ea(address)
    }

    /// The address a name resolves to, or `None` if no such name exists.
    ///
    /// A name with an interior NUL can name nothing, so it too yields `None`. The inverse of
    /// [`name`](Self::name).
    #[must_use]
    #[doc(alias("get_name_ea"))]
    pub fn address_of(&self, name: impl AsRef<str>) -> Option<Address> {
        Address::try_new(self.get_name_ea(name.as_ref()))
    }

    /// Demangle a mangled symbol into readable form, or `None` if `name` is not a mangled name
    /// (or carries an interior NUL).
    ///
    /// Names read from the database are already display form. This is for turning a raw linker
    /// symbol back into source-level text.
    #[must_use]
    #[doc(alias("demangle_name"))]
    pub fn demangle(&self, name: impl AsRef<str>) -> Option<String> {
        self.demangle_name(name.as_ref())
    }

    /// Lazily iterate every named address in the database, in the kernel's name-list order.
    #[must_use]
    #[doc(alias("get_nlist_size", "get_nlist_ea", "get_nlist_name"))]
    pub fn names(&self) -> Names<'_> {
        Names::new(self)
    }
}

/// A named address from the database's name list, yielded by [`Names`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Name {
    /// The named address.
    pub address: Address,
    /// The name at that address.
    pub name: String,
}

/// A lazy iterator over every named address, in the kernel's name-list order, from
/// [`Database::names`].
#[doc(alias("get_nlist_size"))]
pub struct Names<'db> {
    db: &'db Database,
    next: usize,
    count: usize,
}

impl<'db> Names<'db> {
    #[inline]
    pub(crate) fn new(db: &'db Database) -> Self {
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
                let name = self.db.nlist_name(idx).unwrap_or_default();
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
    use assert2::assert;

    use super::Name;
    use crate::address::Address;

    const fn assert_send<T: Send>() {}

    // A `Name` owns its string and address, so it can travel off the kernel thread.
    const _: () = assert_send::<Name>();

    #[test]
    fn serde_round_trips() {
        let name = Name {
            address: Address::new_const(0x1400_1000),
            name: "main".to_owned(),
        };
        let json = serde_json::to_string(&name).unwrap();
        let back: Name = serde_json::from_str(&json).unwrap();
        assert!(back == name);
    }
}
