//! [`NamedType`]: a borrowed cursor over one local named type, plus [`NamedTypes`], the lazy
//! enumeration behind [`Database::named_types`].
//!
//! The database's local type library is addressed by ordinal; [`NamedTypes`] walks the live
//! ordinals, skipping the anonymous ones (structural types with no tag) so a caller sees only the
//! named types it would reason about. Each [`NamedType`] is a cheap `Copy` view keyed by ordinal:
//! read its [`name`](NamedType::name) freely, and [`resolve`](NamedType::resolve) the ones worth
//! the walk into an owned [`Type`].

use idakit_sys as sys;

use super::{CanonicalOptions, CanonicalType, Type, walk_type};
use crate::Database;
use crate::error::{Error, Result};
use crate::ffi::read_string;

impl Database {
    /// Enumerate the database's local named types, in ordinal order. Each item is a cheap
    /// [`NamedType`] cursor: reading its [`name`](NamedType::name) is a metadata lookup, while
    /// [`resolve`](NamedType::resolve) walks it into an owned [`Type`]. Anonymous types are
    /// skipped.
    #[inline]
    #[must_use]
    pub fn named_types(&self) -> NamedTypes<'_> {
        NamedTypes::new(self)
    }
}

/// A borrowed view of one local named type, keyed by its type-library ordinal. Cheap to hold and
/// copy; [`resolve`](Self::resolve) performs the structural walk.
#[derive(Clone, Copy)]
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
    pub fn name(&self) -> String {
        read_string(|buf, cap| self.db.type_name_at(self.ordinal, buf, cap)).unwrap_or_default()
    }

    /// Walk this type into an owned, `Send` [`Type`] snapshot: the structured form
    /// [`Database::type_named`] yields, keyed by ordinal instead of name. `Err` if the walked
    /// table is malformed.
    pub fn resolve(&self) -> Result<Type> {
        // SAFETY: the kernel is claimed for `self.db`; the walk's out-params are valid locals.
        match walk_type(|v, ctx, root| unsafe {
            sys::idakit_type_walk_ordinal(self.ordinal, v, ctx, root)
        }) {
            Ok(Some(ty)) => Ok(ty),
            // A live ordinal that refuses to walk is near-unreachable; report it addressless.
            Ok(None) => Err(Error::TypeNotFound { name: self.name() }),
            Err(source) => Err(Error::Extract { address: 0, source }),
        }
    }

    /// [`resolve`](Self::resolve) this type and reduce it to its table-free [`CanonicalType`] under
    /// the strict (ABI-exact) policy, in one step. The common case when snapshotting a database's
    /// types for cross-database comparison.
    pub fn canonical(&self) -> Result<CanonicalType> {
        Ok(self.resolve()?.canonical())
    }

    /// [`canonical`](Self::canonical) under an explicit [`CanonicalOptions`] lens (e.g.
    /// [`logical`](CanonicalOptions::logical) for a cross-architecture comparison).
    pub fn canonical_with(&self, opts: CanonicalOptions) -> Result<CanonicalType> {
        Ok(self.resolve()?.canonical_with(opts))
    }
}

/// Lazy enumeration of a database's local named types. See [`Database::named_types`].
pub struct NamedTypes<'db> {
    db: &'db Database,
    next: u32,
    limit: u32,
}

impl<'db> NamedTypes<'db> {
    fn new(db: &'db Database) -> Self {
        // Ordinals run 1..limit; u32::MAX means "ordinals disabled" (never for local types) -- fold
        // it to an empty range rather than iterating four billion phantom slots.
        let limit = match db.type_ordinal_limit() {
            u32::MAX => 0,
            n => n,
        };
        Self { db, next: 1, limit }
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
