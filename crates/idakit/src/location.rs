//! Reads and writes the item at one address through the [`Location`] view and [`LocationMut`]
//! cursor.
//!
//! [`Location`] is the address-keyed join: it ties a raw address to the name, comment, bytes, and
//! cross-references living there, without routing through a noun view first. [`LocationMut`] is
//! its write cursor, with [`rename`](LocationMut::rename),
//! [`set_comment`](LocationMut::set_comment), and [`patch`](LocationMut::patch). It is acquired by
//! [`at_mut`](Database::at_mut) from the `&mut Database` and never by promoting a [`Location`]: a
//! live read borrow forbids the exclusive one (`location.edit(&mut db)` is a compile error, not a
//! runtime check). The cursor is read-capable, so every scalar [`Location`] accessor is inherent
//! on it too and a read-modify-write needs no re-borrow.

use idakit_sys as sys;

use crate::Database;
use crate::address::Address;
use crate::error::{Error, Result};
use crate::ffi::{reason_or, with_cstr};
use crate::types::TypeExpr;
use crate::xref::Xrefs;

/// Emits the scalar read accessors shared by [`Location`] and [`LocationMut`].
///
/// Both key a [`Database`] by a `db` field and an `address` field; every accessor returns an owned
/// value, so it borrows nothing and mirrors identically onto the read view and the write cursor.
macro_rules! location_reads {
    () => {
        /// The address this handle is keyed by.
        #[inline]
        #[must_use]
        pub const fn address(&self) -> Address {
            self.address
        }

        /// The name at this address, or `None` if it is unnamed.
        #[inline]
        #[must_use]
        #[doc(alias("get_ea_name"))]
        pub fn name(&self) -> Option<String> {
            self.db.name(self.address)
        }

        /// The regular comment at this address, or `None` when that channel carries none.
        #[inline]
        #[must_use]
        #[doc(alias("get_cmt"))]
        pub fn comment(&self) -> Option<String> {
            self.db.comment(self.address, false)
        }

        /// The repeatable comment at this address, or `None` when that channel carries none.
        #[inline]
        #[must_use]
        #[doc(alias("get_cmt"))]
        pub fn repeatable_comment(&self) -> Option<String> {
            self.db.comment(self.address, true)
        }

        /// Read up to `len` bytes at this address into a fresh vector (empty on failure).
        #[inline]
        #[must_use]
        #[doc(alias("get_bytes"))]
        pub fn bytes(&self, len: usize) -> Vec<u8> {
            self.db.bytes(self.address, len)
        }

        /// Read bytes at this address into `buf`, returning how many were supplied.
        #[inline]
        #[doc(alias("get_bytes"))]
        pub fn read_into(&self, buf: &mut [u8]) -> usize {
            self.db.read_into(self.address, buf)
        }

        /// Whether the kernel classifies the item here as an instruction.
        #[inline]
        #[must_use]
        #[doc(alias("FF_CODE"))]
        pub fn is_code(&self) -> bool {
            self.db.is_code(self.address)
        }

        /// Whether the kernel classifies the item here as a data definition.
        #[inline]
        #[must_use]
        #[doc(alias("FF_DATA"))]
        pub fn is_data(&self) -> bool {
            self.db.is_data(self.address)
        }

        /// The C string at this address, decoded as UTF-8, or `None` if it holds no string.
        #[inline]
        #[must_use]
        #[doc(alias("get_strlit"))]
        pub fn string_literal(&self) -> Option<String> {
            self.db.read_string(self.address)
        }
    };
}

impl Database {
    /// A read view of the item at `address`.
    ///
    /// The address-keyed join ([`name`](Location::name), [`comment`](Location::comment),
    /// [`bytes`](Location::bytes), cross-references) without a noun view. Does not verify anything
    /// is defined there; absence surfaces per accessor.
    #[inline]
    #[must_use]
    pub fn at(&self, address: Address) -> Location<'_> {
        Location { db: self, address }
    }

    /// A write cursor at `address`.
    ///
    /// The write half of [`at`](Self::at): [`rename`](LocationMut::rename),
    /// [`set_comment`](LocationMut::set_comment), [`patch`](LocationMut::patch). It is
    /// read-capable, so the scalar [`Location`] accessors work on it directly and a
    /// read-modify-write never re-borrows. Acquired by the address key, not by promoting a
    /// [`Location`]: the live read borrow inside a view forbids the exclusive one.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let entry = db.functions().next().unwrap().address();
    /// db.at_mut(entry).set_comment("noted by idakit", false)?;
    /// assert_eq!(db.at(entry).comment().as_deref(), Some("noted by idakit"));
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// The cursor is acquired by the address key, so a read view held across the write is a
    /// compile error, not a runtime check:
    ///
    /// ```compile_fail,E0502
    /// # use idakit::Database;
    /// fn oops(db: &mut Database) {
    ///     for function in db.functions() {   // borrows `&db` for the whole loop
    ///         db.at_mut(function.address()); // E0502: `&mut db` while `&db` is live
    ///     }
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn at_mut(&mut self, address: Address) -> LocationMut<'_> {
        LocationMut { db: self, address }
    }

    /// Runs `f` against a write cursor at `address`.
    ///
    /// The scoped-closure companion to [`at_mut`](Self::at_mut) for a multi-step edit, mirroring
    /// [`call`](crate::kernel::Ida::call) one level down.
    pub fn with_location_mut<R>(
        &mut self,
        address: Address,
        f: impl FnOnce(&mut LocationMut<'_>) -> R,
    ) -> R {
        let mut cursor = self.at_mut(address);
        f(&mut cursor)
    }

    /// Applies `ty` at `address`, the shared router behind [`LocationMut::set_type`] and
    /// [`FunctionEdit::set_type`](crate::function::FunctionEdit::set_type).
    ///
    /// A named reference takes the by-name path (clean [`Error::TypeNotFound`]); a declaration is
    /// parsed, so a bad one is [`Error::TypeParseFailed`] with IDA's own reason. A scalar leaf or a
    /// built composite lowers through the recipe interpreter, reporting [`Error::TypeApplyFailed`]
    /// if the kernel cannot build or apply it.
    pub(crate) fn apply_type_at(&mut self, address: Address, ty: &TypeExpr) -> Result<()> {
        match ty {
            TypeExpr::Named(name) => {
                let code = with_cstr(name, "name", |p| self.apply_named_type(address, p))?;
                match code {
                    sys::IDAKIT_TYPE_OK => Ok(()),
                    sys::IDAKIT_TYPE_ERR_INPUT => Err(Error::TypeNotFound { name: name.clone() }),
                    _ => Err(Error::TypeApplyFailed {
                        address: address.get(),
                        reason: format!("the kernel rejected named type {name:?}"),
                    }),
                }
            }
            TypeExpr::Decl(decl) => {
                let (code, reason) =
                    with_cstr(decl, "decl", |p| self.apply_type_decl(address, p, 0))?;
                match code {
                    sys::IDAKIT_TYPE_OK => Ok(()),
                    sys::IDAKIT_TYPE_ERR_INPUT => Err(Error::TypeParseFailed {
                        decl: decl.clone(),
                        reason: reason_or(reason, "the declaration is not valid"),
                    }),
                    _ => Err(Error::TypeApplyFailed {
                        address: address.get(),
                        reason: reason_or(reason, "the kernel could not apply the parsed type"),
                    }),
                }
            }
            // A scalar leaf or a pointer/array/qualifier composite lowers through the recipe
            // interpreter: serialize to postfix bytecode, build the tinfo bottom-up, then apply.
            other => {
                let (code, reason) = self.apply_type_recipe(address, &other.serialize(), 0);
                match code {
                    sys::IDAKIT_TYPE_OK => Ok(()),
                    sys::IDAKIT_TYPE_ERR_INPUT => Err(Error::TypeApplyFailed {
                        address: address.get(),
                        reason: reason_or(
                            reason,
                            &format!(
                                "could not build `{other}` (an unknown named type or invalid \
                                 declaration within it)"
                            ),
                        ),
                    }),
                    _ => Err(Error::TypeApplyFailed {
                        address: address.get(),
                        reason: reason_or(
                            reason,
                            &format!("the kernel could not apply the built type `{other}`"),
                        ),
                    }),
                }
            }
        }
    }
}

/// A borrowed view of one address's item, keyed by that address.
///
/// A cheap `Copy` handle that borrows the [`Database`] and re-queries per accessor, from
/// [`Database::at`]. The address-keyed counterpart to the noun views ([`Function`](crate::Function),
/// [`Segment`](crate::Segment)); [`LocationMut`] is its write cursor.
#[derive(Clone, Copy)]
pub struct Location<'db> {
    db: &'db Database,
    address: Address,
}

impl<'db> Location<'db> {
    location_reads!();

    /// Lazily iterates cross-references targeting this address.
    #[inline]
    #[must_use]
    pub fn xrefs_to(&self) -> Xrefs<'db> {
        self.db.xrefs_to(self.address)
    }

    /// Lazily iterates cross-references originating at this address.
    #[inline]
    #[must_use]
    pub fn xrefs_from(&self) -> Xrefs<'db> {
        self.db.xrefs_from(self.address)
    }
}

/// A write cursor at one address, from [`Database::at_mut`].
///
/// Holds the database exclusively (`&mut Database`) and is read-capable: the scalar [`Location`]
/// accessors are inherent here, so a read-modify-write ([`comment`](Self::comment) then
/// [`set_comment`](Self::set_comment)) stays on one cursor. Not `Copy`, and not obtainable from a
/// borrowing [`Location`].
pub struct LocationMut<'db> {
    db: &'db mut Database,
    address: Address,
}

impl LocationMut<'_> {
    location_reads!();

    /// Rename the item at this address.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the rename (e.g. a name already in use), or
    /// [`Error::InteriorNul`] if `name` contains a NUL byte.
    #[doc(alias("set_name"))]
    pub fn rename(&mut self, name: impl AsRef<str>) -> Result<()> {
        let ok = with_cstr(name.as_ref(), "name", |p| self.db.set_name(self.address, p))?;
        if ok {
            Ok(())
        } else {
            Err(self.rejected("rename"))
        }
    }

    /// Set the comment at this address; `repeatable` repeats it at every reference.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write, or [`Error::InteriorNul`] if
    /// `text` contains a NUL byte.
    #[doc(alias("set_cmt"))]
    pub fn set_comment(&mut self, text: impl AsRef<str>, repeatable: bool) -> Result<()> {
        let ok = with_cstr(text.as_ref(), "comment", |p| {
            self.db.set_cmt(self.address, p, repeatable)
        })?;
        if ok {
            Ok(())
        } else {
            Err(self.rejected("set_comment"))
        }
    }

    /// Patch `bytes` over the image at this address, saving the originals.
    ///
    /// The write is all-or-nothing, so a bad address leaves the database untouched; IDA can
    /// recover the originals, and a later save writes the patch into the `.i64`.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if any target byte is unmapped.
    #[doc(alias("patch_bytes"))]
    pub fn patch(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        if self
            .db
            .patch_bytes(self.address, bytes.as_ptr().cast(), bytes.len())
            != 0
        {
            return Ok(());
        }
        // patch_bytes has no kernel error channel; the facade rejects an unmapped range, so there
        // is usually no error code set. Fall back to naming the actual failure.
        let (qerrno, reason) = self.db.last_reason();
        Err(Error::WriteRejected {
            op: "patch",
            address: self.address.get(),
            qerrno,
            reason: reason.or_else(|| Some("target range is not fully mapped".to_owned())),
        })
    }

    /// Apply a type to the item at this address (IDA's "Set type", GUI shortcut Y).
    ///
    /// Input is any [`Into<TypeExpr>`]: a `&str` classifies itself (a bare name applies an
    /// existing type, a declarator is parsed), or pass
    /// [`expr::named`](crate::types::expr::named)/[`expr::decl`](crate::types::expr::decl) to force
    /// one path.
    ///
    /// # Errors
    /// [`Error::TypeNotFound`] for an unknown named type, [`Error::TypeParseFailed`] for an
    /// unparseable declaration, [`Error::TypeApplyFailed`] if the kernel rejects reshaping the item
    /// to the type, or [`Error::InteriorNul`] if the input contains a NUL byte.
    #[doc(alias("apply_tinfo", "apply_cdecl", "apply_named_type"))]
    pub fn set_type(&mut self, ty: impl Into<TypeExpr>) -> Result<()> {
        self.db.apply_type_at(self.address, &ty.into())
    }

    /// Builds an [`Error::WriteRejected`] for `op` from the kernel's current error channel.
    fn rejected(&self, op: &'static str) -> Error {
        let (qerrno, reason) = self.db.last_reason();
        Error::WriteRejected {
            op,
            address: self.address.get(),
            qerrno,
            reason,
        }
    }
}
