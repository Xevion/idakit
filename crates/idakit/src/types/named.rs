//! Enumerates and resolves a database's local named types through [`NamedType`] and
//! [`NamedTypes`].
//!
//! The database's local type library is addressed by ordinal; [`NamedTypes`] walks the live
//! ordinals, skipping the anonymous ones (structural types with no tag) so a caller sees only the
//! named types it would reason about. Each [`NamedType`] is a cheap `Copy` view keyed by ordinal:
//! read its [`name`](NamedType::name) freely, and [`resolve`](NamedType::resolve) the ones worth
//! the walk into an owned [`Type`].

use idakit_sys as sys;

use super::diff::{CanonicalOptions, CanonicalType};
use super::{Type, walk_type};
use crate::Database;
use crate::error::{Error, Result};

impl Database {
    /// Enumerates the database's local named types, in ordinal order.
    ///
    /// Each item is a cheap [`NamedType`] view: reading its [`name`](NamedType::name) is a
    /// metadata lookup, while [`resolve`](NamedType::resolve) walks it into an owned [`Type`].
    /// Anonymous types (structural, with no tag) are skipped.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let names: Vec<String> = db.named_types().map(|t| t.name()).collect();
    /// assert!(names.iter().all(|n| !n.is_empty()));
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[inline]
    #[must_use]
    #[doc(alias("get_ordinal_limit"))]
    pub fn named_types(&self) -> NamedTypes<'_> {
        NamedTypes::new(self)
    }
}

/// A borrowed view of one local named type, keyed by its type-library ordinal.
///
/// Cheap to hold and copy; [`resolve`](Self::resolve) performs the structural walk.
#[derive(Clone, Copy)]
#[doc(alias("get_numbered_type"))]
pub struct NamedType<'db> {
    db: &'db Database,
    ordinal: u32,
}

impl<'db> NamedType<'db> {
    #[inline]
    fn new(db: &'db Database, ordinal: u32) -> Self {
        Self { db, ordinal }
    }

    /// The type-library ordinal identifying this type within the database.
    #[inline]
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// The type's name: a metadata read, no structural walk.
    #[must_use]
    #[doc(alias("get_numbered_type_name"))]
    pub fn name(&self) -> String {
        self.db.type_name_at(self.ordinal)
    }

    /// Walks this type into an owned, `Send` [`Type`] snapshot.
    ///
    /// The structured form [`Database::type_named`] yields, keyed by ordinal instead of name.
    ///
    /// # Errors
    /// [`Error::TypeNotFound`] if a live ordinal refuses to walk (near-unreachable), or
    /// [`Error::Extract`] if the walked table is malformed.
    #[doc(alias("get_numbered_type"))]
    pub fn resolve(&self) -> Result<Type> {
        // The kernel is claimed for `self.db`; the driver walks the ordinal's type into the sink.
        match walk_type(|sink| sys::walk_type_ordinal(self.ordinal, sink)) {
            Ok(Some(ty)) => Ok(ty),
            // A live ordinal that refuses to walk is near-unreachable; report it addressless.
            Ok(None) => Err(Error::TypeNotFound { name: self.name() }),
            Err(source) => Err(Error::Extract { address: 0, source }),
        }
    }

    /// Resolves this type and reduces it to its table-free [`CanonicalType`] under the strict
    /// (ABI-exact) policy, in one step.
    ///
    /// The common case when snapshotting a database's types for cross-database comparison.
    ///
    /// # Errors
    /// Propagates [`resolve`](Self::resolve)'s error when the type can't be walked.
    pub fn canonical(&self) -> Result<CanonicalType> {
        Ok(self.resolve()?.canonical())
    }

    /// [`canonical`](Self::canonical) under an explicit [`CanonicalOptions`] lens.
    ///
    /// E.g. [`logical`](CanonicalOptions::logical) for a cross-architecture comparison.
    ///
    /// # Errors
    /// Propagates [`resolve`](Self::resolve)'s error when the type can't be walked.
    pub fn canonical_with(&self, opts: CanonicalOptions) -> Result<CanonicalType> {
        Ok(self.resolve()?.canonical_with(opts))
    }
}

impl std::fmt::Debug for NamedType<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamedType")
            .field("ordinal", &self.ordinal)
            .finish_non_exhaustive()
    }
}

key_identity!(NamedType, ordinal);

/// A lazy iterator over a database's local named types, from [`Database::named_types`].
#[doc(alias("get_ordinal_limit"))]
pub struct NamedTypes<'db> {
    db: &'db Database,
    next: u32,
    limit: u32,
}

impl<'db> NamedTypes<'db> {
    fn new(db: &'db Database) -> Self {
        // Ordinals run 1..limit; u32::MAX means "ordinals disabled" (never for local types), so
        // fold it to an empty range rather than iterating four billion phantom slots.
        let limit = match db.type_ordinal_limit() {
            u32::MAX => 0,
            n => n,
        };
        Self { db, next: 1, limit }
    }
}

impl std::fmt::Debug for NamedTypes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamedTypes")
            .field("next", &self.next)
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl<'db> Iterator for NamedTypes<'db> {
    type Item = NamedType<'db>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next < self.limit {
            let candidate = NamedType::new(self.db, self.next);
            self.next += 1;
            if !candidate.name().is_empty() {
                return Some(candidate);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn named_type_identity_compares_by_ordinal() {
        let db = Database::new();
        assert!(NamedType::new(&db, 3) == NamedType::new(&db, 3));
        assert!(NamedType::new(&db, 3) != NamedType::new(&db, 4));
    }

    #[test]
    fn named_type_debug_renders_the_ordinal() {
        let db = Database::new();
        let ty = NamedType::new(&db, 7);
        assert!(format!("{ty:?}") == "NamedType { ordinal: 7, .. }");
    }

    #[test]
    fn named_types_debug_renders_progress() {
        let db = Database::new();
        let iter = NamedTypes {
            db: &db,
            next: 1,
            limit: 5,
        };
        assert!(format!("{iter:?}") == "NamedTypes { next: 1, limit: 5, .. }");
    }
}
