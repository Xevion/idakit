//! Reduces a type to a table-free [`CanonicalType`] for cross-database comparison and diffing.
//!
//! A [`Type`](crate::types::Type)'s identity is only meaningful within its own database. To ask
//! whether a type matches one from *another* database, [`canonicalize`] walks it into a
//! [`CanonicalType`] that carries no table, from which fall a stable 128-bit [`TypeKey`], a
//! canonical [`Display`](std::fmt::Display) string, and a nominal [`TypeIdentity`] for pairing.
//! [`TypeCatalog`] snapshots every named type of a database this way, so two catalogs
//! [`diff`](TypeCatalog::diff) in memory.

mod canonical;
mod catalog;

pub use canonical::{
    AggregateKind, CanonicalMember, CanonicalOptions, CanonicalType, Change, ChangeKind, TypeDiff,
    TypeIdentity, TypeKey, canonicalize,
};
pub use catalog::{CatalogDiff, TypeCatalog};
