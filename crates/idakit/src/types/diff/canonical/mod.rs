//! Reduces a type to [`CanonicalType`], a table-free structural form, and diffs two canonical
//! types into a [`TypeDiff`].
//!
//! A [`TypeValue`](crate::types::TypeValue) references its children by [`TypeId`], an arena index that
//! only means something within its own [`TypeTable`]. So the derived `PartialEq` answers "same type
//! *in this database*" and nothing more. The type-diff workflow asks a harder question: is this
//! type the same as one from *another* database? That needs a representation carrying no table.
//! [`canonicalize`] walks a `(table, id)` into a [`CanonicalType`] whose children are inlined by
//! value, cutting each named aggregate to a nominal reference ([`Named`](CanonicalType::Named)).
//! Recursion bottoms out on that cut, or on a De Bruijn [`BackRef`](CanonicalType::BackRef).
//!
//! The nominal cut is both correct C semantics (a named aggregate *is* its tag) and what makes the
//! walk terminate, since C recursion almost always passes through a named aggregate. The De Bruijn
//! guard covers the rest: the rare synthetic-named or anonymous cycle. Termination is total either
//! way.
//!
//! Four projections fall out of the one value: structural equality (the derive), a stable 128-bit
//! [`key`](CanonicalType::key) for map and dedup use, a canonical [`Display`] string for reading a
//! diff, and a nominal [`identity`](CanonicalType::identity) for pairing types across databases
//! before comparing their bodies.

mod engine;
mod model;

pub use engine::{Change, ChangeKind, TypeDiff};
pub use model::{
    AggregateKind, CanonicalMember, CanonicalOptions, CanonicalType, RecordKind, TypeIdentity,
    TypeKey, canonicalize,
};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "property.rs"]
mod property;
