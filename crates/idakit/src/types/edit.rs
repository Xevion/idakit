//! Writes to the database's type library through the [`TypesMut`] capability cursor.
//!
//! [`TypesMut`], from [`Database::types_mut`], is the write half of the type subsystem. Today it
//! exposes [`define`](TypesMut::define), which parses C declarations into the local type library;
//! member edits and til-slot surgery layer on later. Editing an attached typeref auto-propagates
//! to every reference, so a struct fixed once reflows everywhere it is used.

use crate::Database;
use crate::error::{Error, Result};
use crate::ffi::{reason_or, with_cstr};

impl Database {
    /// A write cursor over the database's local type library.
    ///
    /// The capability counterpart to the read enumeration
    /// [`named_types`](Self::named_types); acquired by capability, not by a coordinate key.
    #[inline]
    #[must_use]
    pub fn types_mut(&mut self) -> TypesMut<'_> {
        TypesMut { db: self }
    }
}

/// A write cursor over the database's local type library, from [`Database::types_mut`].
///
/// Holds the database exclusively. Today it exposes [`define`](Self::define); member and til-slot
/// edits (`edit`, `entry`, `remove`) follow later.
pub struct TypesMut<'db> {
    db: &'db mut Database,
}

impl TypesMut<'_> {
    /// Parse the C declaration(s) in `decl` into the database's local type library.
    ///
    /// A struct, union, enum, or typedef declaration becomes a named type that later
    /// [`set_type`](crate::LocationMut::set_type) calls can reference by name, and that
    /// [`named_types`](Database::named_types) then enumerates. Redeclarations are tolerated.
    ///
    /// `decl` may hold several declarations. It is not atomic: on an error, declarations that
    /// parsed before the failure are already defined.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// db.types_mut().define("struct Point { int x; int y; };")?;
    /// assert!(db.named_types().any(|t| t.name() == "Point"));
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// [`Error::TypeDefineFailed`] if IDA rejects any declaration (with its own diagnostics), or
    /// [`Error::InteriorNul`] if `decl` contains a NUL byte.
    #[doc(alias("parse_decls"))]
    pub fn define(&mut self, decl: impl AsRef<str>) -> Result<()> {
        let decl = decl.as_ref();
        let (errors, reason) = with_cstr(decl, "decl", |p| self.db.define_type(p))?;
        if errors == 0 {
            Ok(())
        } else {
            Err(Error::TypeDefineFailed {
                decl: decl.to_owned(),
                reason: reason_or(reason, "the declaration is not valid"),
            })
        }
    }
}
