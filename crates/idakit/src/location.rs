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
use idakit_sys::TypeApplyCode;

use crate::Database;
use crate::address::Address;
use crate::error::{Error, Result};
use crate::ffi::{nul_checked, reason_or, with_cstr};
use crate::types::{TypeExpr, TypeInfo, TypeWriteError};
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
        #[doc(alias("get_strlit_contents"))]
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
        LocationMut {
            db: self,
            address,
            auto_invalidate: true,
            pending: PendingInvalidation::None,
        }
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
    /// A named reference takes the by-name path (clean [`TypeWriteError::NoType`]); a declaration
    /// is parsed, so a bad one is [`TypeWriteError::ParseFailed`] with IDA's own reason. A scalar
    /// leaf or a built composite lowers through the recipe interpreter, reporting
    /// [`TypeWriteError::BuildFailed`]/[`TypeWriteError::ApplyRejected`] if the kernel cannot
    /// build or apply it.
    pub(crate) fn apply_type_at(&mut self, address: Address, ty: &TypeExpr) -> Result<()> {
        match ty {
            TypeExpr::Named(name) => {
                let result = self.apply_named_type(address, nul_checked(name, "name")?);
                match TypeApplyCode::try_from(result.code) {
                    Ok(TypeApplyCode::Ok) => Ok(()),
                    Ok(TypeApplyCode::ErrInput) => {
                        Err(TypeWriteError::NoType { name: name.clone() }.into())
                    }
                    Ok(TypeApplyCode::ErrApply) | Err(_) => Err(TypeWriteError::ApplyRejected {
                        address: address.get(),
                        reason: format!("the kernel rejected named type {name:?}"),
                    }
                    .into()),
                }
            }
            TypeExpr::Decl(decl) => {
                let result = self.apply_type_decl(address, nul_checked(decl, "decl")?, 0);
                match TypeApplyCode::try_from(result.code) {
                    Ok(TypeApplyCode::Ok) => Ok(()),
                    Ok(TypeApplyCode::ErrInput) => Err(TypeWriteError::ParseFailed {
                        decl: decl.clone(),
                        reason: reason_or(&result.reason, "the declaration is not valid"),
                    }
                    .into()),
                    Ok(TypeApplyCode::ErrApply) | Err(_) => Err(TypeWriteError::ApplyRejected {
                        address: address.get(),
                        reason: reason_or(
                            &result.reason,
                            "the kernel could not apply the parsed type",
                        ),
                    }
                    .into()),
                }
            }
            // A scalar leaf or a pointer/array/qualifier composite lowers through the recipe
            // interpreter: serialize to postfix bytecode, build the tinfo bottom-up, then apply.
            other => {
                let recipe = other.checked_serialize()?;
                let result = self.apply_type_recipe(address, &recipe, 0);
                match TypeApplyCode::try_from(result.code) {
                    Ok(TypeApplyCode::Ok) => Ok(()),
                    Ok(TypeApplyCode::ErrInput) => Err(TypeWriteError::BuildFailed {
                        reason: reason_or(
                            &result.reason,
                            &format!(
                                "could not build `{other}` (an unknown named type or invalid \
                                 declaration within it)"
                            ),
                        ),
                    }
                    .into()),
                    Ok(TypeApplyCode::ErrApply) | Err(_) => Err(TypeWriteError::ApplyRejected {
                        address: address.get(),
                        reason: reason_or(
                            &result.reason,
                            &format!("the kernel could not apply the built type `{other}`"),
                        ),
                    }
                    .into()),
                }
            }
        }
    }
}

/// Maps a [`sys::tinfo_apply`] result to a [`Result`], the shared tail behind
/// [`LocationMut::apply_type`] and
/// [`FunctionEdit::apply_type`](crate::function::FunctionEdit::apply_type).
///
/// A pre-built handle is never a parse or build failure, so the only non-OK outcome is the kernel
/// refusing to reshape the item: [`TypeWriteError::ApplyRejected`].
pub(crate) fn tinfo_apply_result(res: &sys::TypeWriteResult, address: Address) -> Result<()> {
    match TypeApplyCode::try_from(res.code) {
        Ok(TypeApplyCode::Ok) => Ok(()),
        _ => Err(TypeWriteError::ApplyRejected {
            address: address.get(),
            reason: reason_or(&res.reason, "the kernel could not apply the built type"),
        }
        .into()),
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

impl Location<'_> {
    location_reads!();

    /// Lazily iterates cross-references targeting this address.
    #[inline]
    #[must_use]
    #[doc(alias("xrefblk_t", "first_to"))]
    pub fn xrefs_to(&self) -> Xrefs {
        self.db.xrefs_to(self.address)
    }

    /// Lazily iterates cross-references originating at this address.
    #[inline]
    #[must_use]
    #[doc(alias("xrefblk_t", "first_from"))]
    pub fn xrefs_from(&self) -> Xrefs {
        self.db.xrefs_from(self.address)
    }
}

impl std::fmt::Debug for Location<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Location")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

key_identity!(Location, address);

/// A write cursor at one address, from [`Database::at_mut`].
///
/// Holds the database exclusively (`&mut Database`) and is read-capable: the scalar [`Location`]
/// accessors are inherent here, so a read-modify-write ([`comment`](Self::comment) then
/// [`set_comment`](Self::set_comment)) stays on one cursor. Not `Copy`, and not obtainable from a
/// borrowing [`Location`].
///
/// Rename and retype writes evict this address's cached decompilation and every function that
/// directly references it, so the next [`decompile`](Database::decompile) reflects the change.
/// Eviction is coalesced to when the cursor drops, so a read-modify-write sweeps dependents once
/// regardless of how many writes it made; opt out with
/// [`auto_invalidate(false)`](Self::auto_invalidate).
pub struct LocationMut<'db> {
    db: &'db mut Database,
    address: Address,
    auto_invalidate: bool,
    pending: PendingInvalidation,
}

impl LocationMut<'_> {
    /// The database this cursor holds exclusively.
    #[inline]
    pub(crate) fn db(&self) -> &Database {
        self.db
    }

    /// The database this cursor holds exclusively, mutably.
    #[inline]
    pub(crate) fn db_mut(&mut self) -> &mut Database {
        self.db
    }
}

impl LocationMut<'_> {
    location_reads!();

    /// Toggle automatic decompilation-cache invalidation on the writes this cursor performs.
    ///
    /// On by default: this cursor's rename and retype writes evict this address's cached
    /// decompilation and every function whose pseudocode renders it when the cursor drops, so the
    /// next [`decompile`](Database::decompile) reflects the change. Disable it for a bulk edit
    /// where you will invalidate once at the end (see [`Database::clear_decompilation_cache`]).
    #[must_use]
    pub fn auto_invalidate(mut self, on: bool) -> Self {
        self.auto_invalidate = on;
        self
    }

    /// Widen the eviction this cursor will apply on drop to at least `level`.
    pub(crate) fn queue_invalidation(&mut self, level: PendingInvalidation) {
        self.pending = self.pending.max(level);
    }

    /// Route a write's result through the queue: on success, widen the queued eviction to `level`;
    /// an error passes through untouched. The single choke point every mutating method funnels
    /// through (including [`FunctionEdit`](crate::function::FunctionEdit), via its inner cursor), so
    /// a new write can't silently ship without invalidation.
    pub(crate) fn queued<T>(&mut self, out: Result<T>, level: PendingInvalidation) -> Result<T> {
        if out.is_ok() {
            self.queue_invalidation(level);
        }
        out
    }

    /// Rename the item at this address.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the rename (e.g. a name already in use), or
    /// [`Error::InteriorNul`] if `name` contains a NUL byte.
    #[doc(alias("set_name"))]
    pub fn rename(&mut self, name: impl AsRef<str>) -> Result<()> {
        let ok = with_cstr(name.as_ref(), "name", |p| self.db.set_name(self.address, p))?;
        let out = if ok {
            Ok(())
        } else {
            Err(self.rejected("rename"))
        };
        self.queued(out, PendingInvalidation::Dependents)
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
        // Deliberately queues no invalidation, unlike the other writes on this cursor: disassembly
        // comments live in a separate channel from Hex-Rays pseudocode (user_cmts, keyed by
        // treeloc), so a set_cmt never changes cached decompiled text.
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
        let out = if self.db.patch_bytes(self.address, bytes) {
            Ok(())
        } else {
            // patch_bytes has no kernel error channel; the facade rejects an unmapped range, so
            // there is usually no error code set. Fall back to naming the actual failure.
            let (errno, reason) = self.db.last_reason();
            Err(Error::WriteRejected {
                op: "patch",
                address: self.address.get(),
                errno,
                reason: reason.or_else(|| Some("target range is not fully mapped".to_owned())),
            })
        };
        // Dependents, not SelfOnly: patching data a function inlined (a constant, a jump table)
        // restales every referrer, and the kernel's byte_patched hook self-evicts only a containing
        // function, missing data addresses that have none.
        self.queued(out, PendingInvalidation::Dependents)
    }

    /// Apply a type to the item at this address (IDA's "Set type", GUI shortcut Y).
    ///
    /// Input is any [`Into<TypeExpr>`]: a `&str` classifies itself (a bare name applies an
    /// existing type, a declarator is parsed), or pass
    /// [`expr::named`](crate::types::expr::named)/[`expr::decl`](crate::types::expr::decl) to force
    /// one path.
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`] for an unknown named type, [`TypeWriteError::ParseFailed`] for
    /// an unparseable declaration, [`TypeWriteError::ApplyRejected`] if the kernel rejects
    /// reshaping the item to the type, or [`Error::InteriorNul`] if the input contains a NUL byte.
    #[doc(alias("apply_tinfo", "apply_cdecl", "apply_named_type"))]
    pub fn set_type(&mut self, ty: impl Into<TypeExpr>) -> Result<()> {
        let out = self.db.apply_type_at(self.address, &ty.into());
        self.queued(out, PendingInvalidation::Dependents)
    }

    /// Apply a pre-built [`TypeInfo`] handle to the item at this address.
    ///
    /// The eager-handle counterpart to [`set_type`](Self::set_type): where `set_type` lowers a
    /// [`TypeExpr`] recipe, this writes a live handle built through [`Database::type_int`] and
    /// friends. `ty` is borrowed, so one handle applies to many addresses.
    ///
    /// # Errors
    /// [`TypeWriteError::ApplyRejected`] if the kernel rejects reshaping the item to the type.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let entry = db.functions().next().unwrap().address();
    /// // A function-typed handle sets the prototype at the entry, so this apply succeeds.
    /// let proto = db.parse_type("int handler(int code)")?;
    /// db.at_mut(entry).apply_type(&proto)?;
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[doc(alias("apply_tinfo"))]
    pub fn apply_type(&mut self, ty: &TypeInfo) -> Result<()> {
        let res = self.db.apply_tinfo(self.address, ty.tinfo(), 0);
        let out = tinfo_apply_result(&res, self.address);
        self.queued(out, PendingInvalidation::Dependents)
    }

    /// Clear any type applied to the item at this address, the inverse of [`set_type`](Self::set_type).
    ///
    /// Idempotent: an address that carries no type stays untyped and still succeeds. On a function
    /// entry this removes the prototype.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel refuses to remove an existing type.
    #[doc(alias("del_tinfo", "set_tinfo"))]
    pub fn clear_type(&mut self) -> Result<()> {
        let out = match TypeApplyCode::try_from(self.db.clear_type(self.address).code) {
            Ok(TypeApplyCode::Ok) => Ok(()),
            _ => Err(self.rejected("clear_type")),
        };
        self.queued(out, PendingInvalidation::Dependents)
    }

    /// Builds an [`Error::WriteRejected`] for `op` from the kernel's current error channel.
    fn rejected(&self, op: &'static str) -> Error {
        let (errno, reason) = self.db.last_reason();
        Error::WriteRejected {
            op,
            address: self.address.get(),
            errno,
            reason,
        }
    }
}

impl std::fmt::Debug for LocationMut<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocationMut")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl Drop for LocationMut<'_> {
    /// Applies the queued decompilation-cache eviction once, after all of this cursor's writes.
    fn drop(&mut self) {
        if !self.auto_invalidate {
            return;
        }
        match self.pending {
            PendingInvalidation::None => {}
            PendingInvalidation::SelfOnly => {
                self.db.invalidate_decompilation(self.address);
            }
            PendingInvalidation::Dependents => {
                self.db.invalidate_decompilation_dependents(self.address);
            }
        }
    }
}

/// The strongest decompilation-cache eviction a cursor's writes have queued, applied once on
/// [`Drop`] so a multi-write read-modify-write sweeps dependents at most once.
///
/// Ordered by breadth: a later write can only widen the pending eviction, never narrow it. Nothing
/// can observe the cache between a write and the cursor's drop, since the cursor holds the database
/// exclusively, so deferring is invisible apart from the coalescing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PendingInvalidation {
    /// No write needs eviction.
    None,
    /// Only this address's own decompilation is stale (e.g. a parameter rename, invisible outside
    /// the function itself).
    SelfOnly,
    /// This address and its dependents are stale (a rename or retype re-renders every reference
    /// site).
    Dependents,
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::zero(0)]
    #[case::small(0x1000)]
    #[case::large(0xdead_beef)]
    fn location_identity_compares_by_address(#[case] raw: u64) {
        let db = Database::new();
        let a = Address::new_const(raw);
        let other = Address::new_const(raw.wrapping_add(1).max(1));
        assert!(db.at(a) == db.at(a));
        assert!(db.at(a) != db.at(other));
    }

    #[test]
    fn location_debug_renders_the_address() {
        let db = Database::new();
        let loc = db.at(Address::new_const(0xdead_beef));
        assert!(format!("{loc:?}") == "Location { address: Address(0xdeadbeef), .. }");
    }

    #[test]
    fn location_mut_debug_renders_the_address() {
        let mut db = Database::new();
        let cursor = db.at_mut(Address::new_const(0xdead_beef));
        assert!(format!("{cursor:?}") == "LocationMut { address: Address(0xdeadbeef), .. }");
    }

    /// `None < SelfOnly < Dependents`, so `.max()` always widens toward `Dependents`.
    #[test]
    fn pending_invalidation_orders_by_breadth() {
        assert!(PendingInvalidation::None < PendingInvalidation::SelfOnly);
        assert!(PendingInvalidation::SelfOnly < PendingInvalidation::Dependents);
        assert!(
            PendingInvalidation::None.max(PendingInvalidation::Dependents)
                == PendingInvalidation::Dependents
        );
        assert!(
            PendingInvalidation::Dependents.max(PendingInvalidation::None)
                == PendingInvalidation::Dependents
        );
    }

    /// Builds a cursor with `auto_invalidate: false`, so `Drop` never touches the (unopened)
    /// database regardless of the pending state a test leaves behind.
    fn cursor(db: &mut Database) -> LocationMut<'_> {
        LocationMut {
            db,
            address: Address::new_const(0x1000),
            auto_invalidate: false,
            pending: PendingInvalidation::None,
        }
    }

    /// A successful write only ever widens the queued eviction toward `Dependents`, never
    /// narrows it back down.
    #[test]
    fn queued_ok_widens_but_never_narrows() {
        let mut db = Database::new();
        let mut c = cursor(&mut db);

        let _: Result<()> = c.queued(Ok(()), PendingInvalidation::SelfOnly);
        assert!(c.pending == PendingInvalidation::SelfOnly);

        let _: Result<()> = c.queued(Ok(()), PendingInvalidation::Dependents);
        assert!(c.pending == PendingInvalidation::Dependents);

        // A later, narrower request does not walk the eviction back down.
        let _: Result<()> = c.queued(Ok(()), PendingInvalidation::SelfOnly);
        assert!(c.pending == PendingInvalidation::Dependents);
    }

    /// A failed write passes the error through untouched and queues no eviction.
    #[test]
    fn queued_err_leaves_pending_untouched() {
        let mut db = Database::new();
        let mut c = cursor(&mut db);
        c.pending = PendingInvalidation::SelfOnly;

        let out = c.queued(
            Err::<(), _>(Error::InteriorNul { arg: "name" }),
            PendingInvalidation::Dependents,
        );

        assert!(out == Err(Error::InteriorNul { arg: "name" }));
        assert!(c.pending == PendingInvalidation::SelfOnly);
    }

    /// `queue_invalidation` alone applies the same widen-only rule as `queued`.
    #[test]
    fn queue_invalidation_widens_only() {
        let mut db = Database::new();
        let mut c = cursor(&mut db);

        c.queue_invalidation(PendingInvalidation::Dependents);
        assert!(c.pending == PendingInvalidation::Dependents);

        c.queue_invalidation(PendingInvalidation::None);
        assert!(c.pending == PendingInvalidation::Dependents);
    }
}
