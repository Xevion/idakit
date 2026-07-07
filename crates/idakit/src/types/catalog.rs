//! [`TypeCatalog`]: an owned, `Send` snapshot of a database's named types, and [`CatalogDiff`],
//! the name-paired comparison of two catalogs.
//!
//! [`Database::type_catalog`] resolves every named type into a table-free [`CanonicalType`] and
//! keys them by name, caching each type's [`TypeKey`] so the pairwise identity test a diff runs is
//! a `u128` compare rather than a structural walk. The catalog is detached from the kernel thread,
//! so two catalogs (from two databases opened in turn) coexist for an in-memory
//! [`diff`](TypeCatalog::diff).

use std::collections::BTreeMap;

use super::{CanonicalOptions, CanonicalType, TypeDiff, TypeKey};
use crate::Database;

impl Database {
    /// Snapshot every named type in the database into an owned [`TypeCatalog`] under the strict
    /// (ABI-exact) policy. Types that fail to resolve are dropped and counted in
    /// [`skipped`](TypeCatalog::skipped).
    #[must_use]
    pub fn type_catalog(&self) -> TypeCatalog {
        self.type_catalog_with(CanonicalOptions::strict())
    }

    /// [`type_catalog`](Self::type_catalog) under an explicit [`CanonicalOptions`] lens, e.g.
    /// [`logical`](CanonicalOptions::logical) to compare two databases across architectures.
    #[must_use]
    pub fn type_catalog_with(&self, opts: CanonicalOptions) -> TypeCatalog {
        let mut types = BTreeMap::new();
        let mut skipped = 0;
        for ty in self.named_types() {
            let name = ty.name();
            match ty.canonical_with(opts) {
                Ok(canonical) => {
                    let key = canonical.key();
                    types.insert(name, Entry { canonical, key });
                }
                Err(_) => skipped += 1,
            }
        }
        TypeCatalog {
            types,
            opts,
            skipped,
        }
    }
}

/// One catalog entry: a type's canonical form plus its pre-computed [`TypeKey`], the cheap identity
/// test a [`diff`](TypeCatalog::diff) pairs on.
#[derive(Clone, Debug)]
struct Entry {
    canonical: CanonicalType,
    key: TypeKey,
}

/// An owned, `Send` snapshot of a database's named types, each reduced to a table-free
/// [`CanonicalType`] and keyed by name, built under one [`CanonicalOptions`] lens. Survives the
/// database that produced it, so two catalogs compare in memory with [`diff`](Self::diff).
#[derive(Clone, Debug)]
pub struct TypeCatalog {
    types: BTreeMap<String, Entry>,
    opts: CanonicalOptions,
    skipped: usize,
}

impl TypeCatalog {
    /// The canonical form of the named type, or `None` if the catalog has no such name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&CanonicalType> {
        self.types.get(name).map(|e| &e.canonical)
    }

    /// Whether the catalog holds a type of this name.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.types.contains_key(name)
    }

    /// The type names, in sorted order.
    pub fn names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.types.keys().map(String::as_str)
    }

    /// The `(name, canonical)` pairs, in sorted order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &CanonicalType)> {
        self.types.iter().map(|(n, e)| (n.as_str(), &e.canonical))
    }

    /// Number of named types captured.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Whether the catalog is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// How many named types failed to resolve and were dropped when the catalog was built.
    #[inline]
    #[must_use]
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// The [`CanonicalOptions`] lens this catalog was built under.
    #[inline]
    #[must_use]
    pub fn options(&self) -> CanonicalOptions {
        self.opts
    }

    /// Pair this catalog's types against `other`'s by name and classify each: identical (equal
    /// key), drifted (a structural [`TypeDiff`]), or unique to one side. Both catalogs should be
    /// built under the same [`CanonicalOptions`] (an ABI catalog and a logical one are not
    /// comparable), which a debug build asserts.
    #[must_use]
    pub fn diff(&self, other: &TypeCatalog) -> CatalogDiff {
        debug_assert_eq!(
            self.opts, other.opts,
            "diffing catalogs built under different canonicalization lenses"
        );
        let mut identical = Vec::new();
        let mut drifted = Vec::new();
        let mut only_left = Vec::new();
        for (name, left) in &self.types {
            match other.types.get(name) {
                Some(right) if left.key == right.key => identical.push(name.clone()),
                Some(right) => drifted.push((name.clone(), left.canonical.diff(&right.canonical))),
                None => only_left.push(name.clone()),
            }
        }
        let only_right = other
            .types
            .keys()
            .filter(|n| !self.types.contains_key(*n))
            .cloned()
            .collect();
        CatalogDiff {
            identical,
            drifted,
            only_left,
            only_right,
        }
    }
}

/// The result of [`TypeCatalog::diff`]: the two catalogs' types partitioned by name into those
/// that agree, those that drifted, and those unique to each side. Every list is name-sorted.
#[derive(Clone, Debug, Default)]
pub struct CatalogDiff {
    identical: Vec<String>,
    drifted: Vec<(String, TypeDiff)>,
    only_left: Vec<String>,
    only_right: Vec<String>,
}

impl CatalogDiff {
    /// Names present in both catalogs with an identical structure (equal key).
    #[inline]
    #[must_use]
    pub fn identical(&self) -> &[String] {
        &self.identical
    }

    /// Names present in both catalogs whose structure differs, each with the diff explaining how.
    #[inline]
    #[must_use]
    pub fn drifted(&self) -> &[(String, TypeDiff)] {
        &self.drifted
    }

    /// Names present only in the left (`self`) catalog.
    #[inline]
    #[must_use]
    pub fn only_left(&self) -> &[String] {
        &self.only_left
    }

    /// Names present only in the right (`other`) catalog.
    #[inline]
    #[must_use]
    pub fn only_right(&self) -> &[String] {
        &self.only_right
    }

    /// How many names the two catalogs share (identical plus drifted).
    #[inline]
    #[must_use]
    pub fn shared(&self) -> usize {
        self.identical.len() + self.drifted.len()
    }

    /// Whether the catalogs agree completely: every shared type identical, and neither side has a
    /// type the other lacks.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.drifted.is_empty() && self.only_left.is_empty() && self.only_right.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn type_catalog_is_send() {
        const fn assert_send<T: Send>() {}
        assert_send::<super::TypeCatalog>();
        assert_send::<super::CatalogDiff>();
    }
}
