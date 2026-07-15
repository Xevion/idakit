//! Writes to the database's type library through the [`TypesMut`] capability cursor.
//!
//! [`TypesMut`], from [`Database::types_mut`], is the write half of the type subsystem. It exposes
//! [`define`](TypesMut::define), which parses C declarations into the local type library, and
//! [`edit`](TypesMut::edit), which opens a named type for member surgery through [`TypeEdit`] and
//! its [`MemberEdit`] (struct/union fields) and [`ConstantEdit`] (enum constants) sub-cursors.
//! Editing an attached typeref auto-propagates to every reference, so a struct fixed once reflows
//! everywhere it is used.

use std::collections::hash_map::DefaultHasher;
use std::ffi::c_int;
use std::fmt;
use std::hash::{Hash, Hasher};

use num_enum::{IntoPrimitive, TryFromPrimitive};
use snafu::Snafu;
use strum::VariantArray;

use idakit_sys as sys;

use crate::Database;
use crate::error::{Error, Result};
use crate::ffi::{nul_checked, reason_or};
use crate::types::diff::AggregateKind;
use crate::types::{TypeExpr, ValueRepr};

/// The SDK's `DEFMASK64` (`bmask64_t(-1)`, `typeinf.hpp`): passed as `enum_add_member`'s `bmask`
/// so a bitmask enum falls back to using the constant's own value as its group mask; ignored by
/// an ordinary enum.
const DEFMASK64: u64 = u64::MAX;

/// The SDK's `ETF_COMPATIBLE` (`etf_flag_t`, `typeinf.hpp`): passed to `set_udm_type` so the
/// kernel additionally checks the new type against the member's old one before applying it,
/// rejecting an incompatible replacement as [`TypeEditCode::NotCompatible`].
const ETF_COMPATIBLE: u32 = 0x0000_0008;

/// The SDK's `ETF_FORCENAME` (`etf_flag_t`, `typeinf.hpp`): passed to `add_edm`/`rename_edm` to
/// force an enum constant name through a [`TypeEditCode::AlienName`] collision (the name is
/// already used by another enum).
const ETF_FORCENAME: u32 = 0x0000_0020;

/// The SDK's `BTF_STRUCT`/`BTF_UNION`/`BTF_ENUM` (`type_t`, `typeinf.hpp`): the aggregate-kind
/// byte `create_forward_decl` takes to select what a forward declaration reserves.
const BTF_STRUCT: u32 = 0x0D;
/// The SDK's `BTF_UNION` (`type_t`, `typeinf.hpp`).
const BTF_UNION: u32 = 0x1D;
/// The SDK's `BTF_ENUM` (`type_t`, `typeinf.hpp`).
const BTF_ENUM: u32 = 0x2D;

/// Maps an [`AggregateKind`] to the raw `type_t` `create_forward_decl` expects.
const fn decl_type_of(kind: AggregateKind) -> u32 {
    match kind {
        AggregateKind::Struct => BTF_STRUCT,
        AggregateKind::Union => BTF_UNION,
        AggregateKind::Enum => BTF_ENUM,
    }
}

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
/// Holds the database exclusively. Exposes [`define`](Self::define) for whole declarations and
/// [`edit`](Self::edit) for member surgery on an existing named type.
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
        let result = self.db.define_type(nul_checked(decl, "decl")?);
        if result.code == 0 {
            Ok(())
        } else {
            Err(Error::TypeDefineFailed {
                decl: decl.to_owned(),
                reason: reason_or(&result.reason, "the declaration is not valid"),
            })
        }
    }

    /// Delete the named type `name` from the database's local type library.
    ///
    /// The til-level inverse of [`define`](Self::define): removes a struct, union, enum, or
    /// typedef entry outright. Not idempotent: deleting a name that does not exist is
    /// [`TypeWriteError::NoType`], the same treatment [`MemberEdit::delete`] gives an
    /// unresolved member.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// db.types_mut().define("struct Scratch { int x; };")?;
    /// db.types_mut().delete("Scratch")?;
    /// assert!(!db.named_types().any(|t| t.name() == "Scratch"));
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`] if no type named `name` exists, [`TypeWriteError::Rejected`]
    /// if the kernel refuses the deletion, or [`Error::InteriorNul`] if `name` contains a NUL
    /// byte.
    #[doc(alias("del_named_type"))]
    pub fn delete(&mut self, name: impl AsRef<str>) -> Result<()> {
        let name = name.as_ref();
        let result = self.db.delete_type(nul_checked(name, "name")?);
        edit_result(result.code, &result.reason, name, None)
    }

    /// Rename the named type `name` to `new_name`, in place.
    ///
    /// Preserves the type's ordinal and every reference to it: the underlying SDK call
    /// (`rename_type`) updates the til entry's name without reallocating it.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// db.types_mut().define("struct Old { int x; };")?;
    /// db.types_mut().rename("Old", "New")?;
    /// assert!(db.named_types().any(|t| t.name() == "New"));
    /// assert!(!db.named_types().any(|t| t.name() == "Old"));
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`] if no type named `name` exists, [`TypeWriteError::Rejected`]
    /// (e.g. [`TypeEditCode::DupName`] if `new_name` is already taken), or
    /// [`Error::InteriorNul`] if either name contains a NUL byte.
    #[doc(alias("rename_type"))]
    pub fn rename(&mut self, name: impl AsRef<str>, new_name: impl AsRef<str>) -> Result<()> {
        let name = name.as_ref();
        let new_name = nul_checked(new_name.as_ref(), "new name")?;
        let result = self.db.rename_type(nul_checked(name, "name")?, new_name);
        edit_result(result.code, &result.reason, name, None)
    }

    /// Reserve `name` in the local type library as an incomplete `kind` aggregate, with no body.
    ///
    /// The explicit counterpart to the `"struct Foo;"` idiom through [`define`](Self::define):
    /// reserves the tag without describing its members, so a later [`define`](Self::define) with
    /// a full body over the same name completes it. Until then, the type reads back as
    /// [`TypeShape::Opaque`](crate::types::TypeShape::Opaque), the same shape any other unresolved
    /// or bodyless named type takes.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// use idakit::types::diff::AggregateKind;
    ///
    /// db.types_mut()
    ///     .forward_declare("idakit_fwd_probe", AggregateKind::Struct)?;
    /// assert!(db.named_types().any(|t| t.name() == "idakit_fwd_probe"));
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// [`TypeWriteError::Rejected`] if the kernel refuses the declaration (e.g. `name` is already
    /// taken by an incompatible type), or [`Error::InteriorNul`] if `name` contains a NUL byte.
    #[doc(alias("create_forward_decl"))]
    pub fn forward_declare(&mut self, name: impl AsRef<str>, kind: AggregateKind) -> Result<()> {
        let name = name.as_ref();
        let result = self
            .db
            .forward_declare_type(nul_checked(name, "name")?, decl_type_of(kind));
        edit_result(result.code, &result.reason, name, None)
    }

    /// Open the existing named type `name` for member surgery.
    ///
    /// Infallible to acquire: a missing type surfaces as [`TypeWriteError::NoType`] from the first
    /// edit, so `edit(...).member(...).set_type(...)` chains without an intermediate check. Each
    /// verb is a self-contained load, mutate, and auto-save against the live type.
    #[inline]
    #[must_use]
    pub fn edit(&mut self, name: impl Into<String>) -> TypeEdit<'_> {
        TypeEdit {
            db: self.db,
            name: name.into(),
        }
    }
}

impl fmt::Debug for TypesMut<'_> {
    // Skips the exclusively-held `&mut Database`; a capability cursor has no other field.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypesMut").finish_non_exhaustive()
    }
}

/// A write cursor over one named type, from [`TypesMut::edit`].
///
/// Adds struct/union members and hands out a [`MemberEdit`] sub-cursor keyed by member name or bit
/// offset; adds enum constants and hands out a [`ConstantEdit`] sub-cursor keyed by name. Every
/// edit is a fresh load of the named type, one mutation, and an auto-save back to the local til, so
/// nothing is held across calls.
pub struct TypeEdit<'db> {
    db: &'db mut Database,
    name: String,
}

impl TypeEdit<'_> {
    /// Append a member named `name` of type `ty` after the current last member.
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`] if the type does not exist, [`TypeWriteError::BuildFailed`] if
    /// `ty` cannot be built, or [`TypeWriteError::Rejected`] if the kernel rejects the member
    /// (e.g. a duplicate name); or [`Error::InteriorNul`] for a NUL byte in a name.
    #[doc(alias("add_udm"))]
    pub fn add_member(&mut self, name: impl AsRef<str>, ty: impl Into<TypeExpr>) -> Result<()> {
        self.add_member_impl(name.as_ref(), &ty.into(), sys::MEMBER_APPEND)
    }

    /// Add a member named `name` of type `ty` at `bit_offset` from the start of the aggregate.
    ///
    /// The offset is in bits, matching [`TypeMember::bit_offset`](crate::types::TypeMember). The
    /// kernel keeps members offset-sorted, so an offset that would collide is rejected.
    ///
    /// # Errors
    /// As [`add_member`](Self::add_member); [`TypeWriteError::Rejected`] additionally covers an
    /// offset the kernel will not place (e.g. an overlap).
    #[doc(alias("add_udm"))]
    pub fn add_member_at(
        &mut self,
        bit_offset: u64,
        name: impl AsRef<str>,
        ty: impl Into<TypeExpr>,
    ) -> Result<()> {
        self.add_member_impl(name.as_ref(), &ty.into(), bit_offset)
    }

    fn add_member_impl(&mut self, name: &str, ty: &TypeExpr, member_bit: u64) -> Result<()> {
        let recipe = ty.checked_serialize()?;
        let type_name = self.name.clone();
        let result = self.db.udt_add_member(
            nul_checked(&type_name, "type name")?,
            nul_checked(name, "member name")?,
            &recipe,
            member_bit,
        );
        edit_result(result.code, &result.reason, &type_name, None)
    }

    /// Select the member named `name` for editing.
    #[inline]
    #[must_use]
    pub fn member(&mut self, name: impl Into<String>) -> MemberEdit<'_> {
        let type_name = self.name.clone();
        MemberEdit {
            db: &mut *self.db,
            type_name,
            key: MemberKey::Name(name.into()),
        }
    }

    /// Select the member at `bit_offset` (bits from the start of the aggregate, as in
    /// [`TypeMember::bit_offset`](crate::types::TypeMember)) for editing.
    #[inline]
    #[must_use]
    pub fn member_at(&mut self, bit_offset: u64) -> MemberEdit<'_> {
        let type_name = self.name.clone();
        MemberEdit {
            db: &mut *self.db,
            type_name,
            key: MemberKey::Offset(bit_offset),
        }
    }

    /// Add an enum constant named `name` with `value` to this enum.
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`] if the enum does not exist, or [`TypeWriteError::Rejected`] if
    /// the kernel rejects the constant (e.g. a duplicate name); or [`Error::InteriorNul`] for a
    /// NUL byte in a name.
    #[doc(alias("add_edm"))]
    pub fn add_constant(&mut self, name: impl AsRef<str>, value: u64) -> Result<()> {
        self.add_member_at_mask(name.as_ref(), value, DEFMASK64, 0)
    }

    /// Add an enum constant named `name` with `value`, forcing the name through an alien-name
    /// collision.
    ///
    /// As [`add_constant`](Self::add_constant), with `ETF_FORCENAME` set: a name already used by
    /// another enum ([`TypeEditCode::AlienName`]) is accepted instead of rejected.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// db.types_mut().define("enum idakit_forcename_a { IDAKIT_SHARED_NAME = 1 };")?;
    /// db.types_mut()
    ///     .define("enum idakit_forcename_b { IDAKIT_OTHER = 1 };")?;
    /// db.types_mut()
    ///     .edit("idakit_forcename_b")
    ///     .add_constant_forced("IDAKIT_SHARED_NAME", 2)?;
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// As [`add_constant`](Self::add_constant).
    #[doc(alias("add_edm"))]
    pub fn add_constant_forced(&mut self, name: impl AsRef<str>, value: u64) -> Result<()> {
        self.add_member_at_mask(name.as_ref(), value, DEFMASK64, ETF_FORCENAME)
    }

    /// Add an enum constant named `name` with `value`, in the explicit bitmask group `mask`.
    ///
    /// The masked sibling of [`add_constant`](Self::add_constant): where `add_constant` lets a
    /// bitmask enum fall back to using `value` itself as its group mask, `add_flag` names the
    /// group explicitly, so several constants can share one bit range. `mask` is ignored on an
    /// enum that is not a bitmask enum (see [`set_bitmask`](Self::set_bitmask)).
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// db.types_mut().define("enum Flags { RESERVED = 8 };")?;
    /// let mut types = db.types_mut();
    /// let mut edit = types.edit("Flags");
    /// edit.set_bitmask(true)?;
    /// edit.add_flag("READ", 1, 1)?;
    /// edit.add_flag("WRITE", 2, 2)?;
    /// let ty = db.type_named("Flags")?;
    /// let idakit::types::TypeShape::Enum { members, .. } = ty.shape() else {
    ///     unreachable!()
    /// };
    /// assert!(members.iter().any(|m| m.name == "READ" && m.value == 1));
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// As [`add_constant`](Self::add_constant); [`TypeWriteError::Rejected`] additionally covers
    /// a mask the kernel will not accept (e.g. [`TypeEditCode::BadBitmask`] or
    /// [`TypeEditCode::BadMaskValue`]).
    #[doc(alias("add_edm"))]
    pub fn add_flag(&mut self, name: impl AsRef<str>, value: u64, mask: u64) -> Result<()> {
        self.add_member_at_mask(name.as_ref(), value, mask, 0)
    }

    /// Add an enum constant named `name` with `value`, in the explicit bitmask group `mask`,
    /// forcing the name through an alien-name collision.
    ///
    /// The `ETF_FORCENAME` sibling of [`add_flag`](Self::add_flag), as
    /// [`add_constant_forced`](Self::add_constant_forced) is to [`add_constant`](Self::add_constant).
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// db.types_mut().define("enum idakit_flag_forcename { IDAKIT_FLAG_RESERVED = 8 };")?;
    /// let mut types = db.types_mut();
    /// let mut edit = types.edit("idakit_flag_forcename");
    /// edit.set_bitmask(true)?;
    /// edit.add_flag_forced("IDAKIT_FLAG_READ", 1, 1)?;
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// As [`add_flag`](Self::add_flag).
    #[doc(alias("add_edm"))]
    pub fn add_flag_forced(&mut self, name: impl AsRef<str>, value: u64, mask: u64) -> Result<()> {
        self.add_member_at_mask(name.as_ref(), value, mask, ETF_FORCENAME)
    }

    /// Add an enum constant, sharing the mask-add path between [`add_constant`](Self::add_constant),
    /// [`add_constant_forced`](Self::add_constant_forced), [`add_flag`](Self::add_flag), and
    /// [`add_flag_forced`](Self::add_flag_forced).
    fn add_member_at_mask(
        &mut self,
        name: &str,
        value: u64,
        mask: u64,
        etf_flags: u32,
    ) -> Result<()> {
        let type_name = self.name.clone();
        let result = self.db.enum_add_member(
            nul_checked(&type_name, "type name")?,
            nul_checked(name, "constant name")?,
            value,
            mask,
            etf_flags,
        );
        edit_result(result.code, &result.reason, &type_name, None)
    }

    /// Mark this enum as a bitmask (flag) enum, or clear that marking.
    ///
    /// A bitmask enum groups its constants by shared bit ranges; [`add_flag`](Self::add_flag)
    /// then takes an explicit group mask instead of falling back to the constant's own value.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// db.types_mut().define("enum Flags { RESERVED = 8 };")?;
    /// db.types_mut().edit("Flags").set_bitmask(true)?;
    /// let ty = db.type_named("Flags")?;
    /// let idakit::types::TypeShape::Enum { is_bitmask, .. } = ty.shape() else {
    ///     unreachable!()
    /// };
    /// assert!(*is_bitmask);
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`] if the enum does not exist, or [`TypeWriteError::Rejected`] if
    /// the kernel rejects the conversion; or [`Error::InteriorNul`] for a NUL byte in the type
    /// name.
    #[doc(alias("set_enum_is_bitmask"))]
    pub fn set_bitmask(&mut self, on: bool) -> Result<()> {
        let type_name = self.name.clone();
        let result = self
            .db
            .enum_set_bitmask(nul_checked(&type_name, "type name")?, on);
        edit_result(result.code, &result.reason, &type_name, None)
    }

    /// Set this enum's value representation: radix or char format, forced sign, and leading
    /// zeros.
    ///
    /// The enum-level sibling of [`MemberEdit::set_repr`]: `MemberEdit` edits one struct/union
    /// field, `set_repr` here edits the whole enum's own representation. Limited to the numeric
    /// subset [`ValueRepr`] models; see [`MemberEdit::set_repr`] for the info-carrying forms out
    /// of scope.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// use idakit::types::{NumberFormat, ValueRepr};
    ///
    /// db.types_mut().define("enum idakit_enum_repr_probe { PROBE_A = 1 };")?;
    /// let repr = ValueRepr {
    ///     format: NumberFormat::Hexadecimal,
    ///     signed: true,
    ///     leading_zeros: false,
    /// };
    /// db.types_mut()
    ///     .edit("idakit_enum_repr_probe")
    ///     .set_repr(repr)?;
    /// let ty = db.type_named("idakit_enum_repr_probe")?;
    /// let idakit::types::TypeShape::Enum { repr: got, .. } = ty.shape() else {
    ///     unreachable!()
    /// };
    /// assert!(*got == Some(repr));
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`] if the enum does not exist, or [`TypeWriteError::Rejected`]
    /// (e.g. [`TypeEditCode::BadRepr`] if the kernel rejects the combination); or
    /// [`Error::InteriorNul`] for a NUL byte in the type name.
    #[doc(alias("set_enum_repr"))]
    pub fn set_repr(&mut self, repr: ValueRepr) -> Result<()> {
        let type_name = self.name.clone();
        let result = self.db.enum_set_repr(
            nul_checked(&type_name, "type name")?,
            repr.format.to_frb(),
            repr.signed,
            repr.leading_zeros,
        );
        edit_result(result.code, &result.reason, &type_name, None)
    }

    /// Set the storage width, in bytes, of this enum's underlying integer type.
    ///
    /// `nbytes` is `0` (unspecified) or one of `1`/`2`/`4`/`8`/`16`/`32`/`64`; the width shows
    /// through the enum's own byte size and its underlying type on the read side.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// db.types_mut().define("enum idakit_enum_width_probe { PROBE_A = 1 };")?;
    /// db.types_mut()
    ///     .edit("idakit_enum_width_probe")
    ///     .set_enum_width(8)?;
    /// let ty = db.type_named("idakit_enum_width_probe")?;
    /// assert!(ty.size() == Some(8));
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`] if the enum does not exist, or [`TypeWriteError::Rejected`]
    /// (e.g. [`TypeEditCode::EnumSize`] if the kernel rejects the width); or
    /// [`Error::InteriorNul`] for a NUL byte in the type name.
    pub fn set_enum_width(&mut self, nbytes: i32) -> Result<()> {
        let type_name = self.name.clone();
        let result = self
            .db
            .enum_set_width(nul_checked(&type_name, "type name")?, nbytes);
        edit_result(result.code, &result.reason, &type_name, None)
    }

    /// Delete the enum constant carrying `value` from this enum.
    ///
    /// The value-keyed sibling of [`ConstantEdit::delete`]: where that selects a constant by
    /// name, this selects whichever constant carries `value` directly, for a value-aliased
    /// serial with no name a caller already knows.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// db.types_mut()
    ///     .define("enum idakit_del_by_value_probe { PROBE_A = 1, PROBE_B = 2 };")?;
    /// db.types_mut()
    ///     .edit("idakit_del_by_value_probe")
    ///     .delete_constant_by_value(1)?;
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`] if the enum does not exist, or [`TypeWriteError::Rejected`]
    /// with [`TypeEditCode::NotFound`] if no constant carries `value`; or
    /// [`Error::InteriorNul`] for a NUL byte in the type name.
    #[doc(alias("del_edm_by_value"))]
    pub fn delete_constant_by_value(&mut self, value: u64) -> Result<()> {
        let type_name = self.name.clone();
        let result = self
            .db
            .enum_del_member_by_value(nul_checked(&type_name, "type name")?, value);
        edit_result(result.code, &result.reason, &type_name, None)
    }

    /// Select the enum constant named `name` for editing.
    #[inline]
    #[must_use]
    pub fn constant(&mut self, name: impl Into<String>) -> ConstantEdit<'_> {
        let type_name = self.name.clone();
        ConstantEdit {
            db: &mut *self.db,
            type_name,
            name: name.into(),
        }
    }

    /// Mint a durable [`MemberRef`] to the struct/union member at `index` (declaration order).
    ///
    /// Unlike [`member`](Self::member)/[`member_at`](Self::member_at), which re-resolve a key each
    /// call, a [`MemberRef`] is a stable index handle that carries a structural fingerprint of the
    /// type's layout: each member's bit offset plus its type's size and shape kind. It survives a
    /// rename of any member, but adding, removing, resizing, or retyping a member invalidates it, so
    /// [`member_by_ref`](Self::member_by_ref) then returns [`TypeWriteError::StaleMemberRef`] instead
    /// of silently editing the wrong member. Chiefly for members a name key cannot address (anonymous
    /// fields).
    ///
    /// A member deleted and replaced by a gap of the same shape kind and size (e.g. a same-width
    /// array member) may not be detected as stale.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// db.types_mut().define("struct Pt { int x; int y; };")?;
    /// let y = db.types_mut().edit("Pt").member_ref(1)?;
    /// // Adding a member changes the layout, so the ref no longer resolves.
    /// db.types_mut().edit("Pt").add_member("z", idakit::types::expr::int32())?;
    /// assert!(db.types_mut().edit("Pt").member_by_ref(&y).is_err());
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`] if no struct/union with this name exists, or
    /// [`TypeWriteError::MemberIndexOutOfRange`] if `index` is past the last member.
    pub fn member_ref(&self, index: usize) -> Result<MemberRef> {
        let (count, generation, _) = self.read_layout(index)?;
        if index >= count {
            return Err(TypeWriteError::MemberIndexOutOfRange {
                type_name: self.name.clone(),
                index,
                count,
            }
            .into());
        }
        Ok(MemberRef {
            type_name: self.name.clone(),
            index,
            generation,
        })
    }

    /// Select the member a [`MemberRef`] points at, checking it against the current layout first.
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`] if the type no longer exists, or
    /// [`TypeWriteError::StaleMemberRef`] if the ref was minted against a different type or the
    /// layout changed since (see [`member_ref`](Self::member_ref)).
    pub fn member_by_ref(&mut self, member: &MemberRef) -> Result<MemberEdit<'_>> {
        let name = self.name.clone();
        let (count, generation, key) = self.read_layout(member.index)?;
        let stale =
            member.type_name != name || member.generation != generation || member.index >= count;
        match key {
            Some(key) if !stale => Ok(MemberEdit {
                db: &mut *self.db,
                type_name: name,
                key,
            }),
            _ => Err(TypeWriteError::StaleMemberRef { type_name: name }.into()),
        }
    }

    /// Read the named type's struct/union layout: its member count, a structural fingerprint (the
    /// count plus each member's bit offset, size, and shape kind, so a rename does not change it
    /// but adding, removing, resizing, or retyping a member does), and the selection key for
    /// `index` when in range.
    fn read_layout(&self, index: usize) -> Result<(usize, u64, Option<MemberKey>)> {
        let ty = self
            .db
            .type_named(&self.name)
            .map_err(|_| TypeWriteError::NoType {
                name: self.name.clone(),
            })?;
        let members = ty.members().ok_or_else(|| TypeWriteError::NoType {
            name: self.name.clone(),
        })?;
        let mut hasher = DefaultHasher::new();
        members.len().hash(&mut hasher);
        for member in members {
            member.bit_offset.hash(&mut hasher);
            // Deleting a non-tail member leaves a same-offset gap of the same byte size, so offset
            // alone can't see it; the gap's shape (an array) differs from what it replaced. Hash
            // the shape's discriminant only, not its fields, since child TypeIds are interning-order
            // dependent and would make the fingerprint unstable across equivalent layouts.
            let tv = ty.get(member.ty);
            tv.size.hash(&mut hasher);
            std::mem::discriminant(&tv.shape).hash(&mut hasher);
        }
        let key = members.get(index).map(|member| {
            if member.name.is_empty() {
                MemberKey::Offset(member.bit_offset)
            } else {
                MemberKey::Name(member.name.clone())
            }
        });
        Ok((members.len(), hasher.finish(), key))
    }
}

impl fmt::Debug for TypeEdit<'_> {
    // Skips the exclusively-held `&mut Database`; only the key is printable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypeEdit")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// A durable handle to a struct/union member by index, from [`TypeEdit::member_ref`].
///
/// Carries a structural fingerprint of the type's layout at mint time (each member's bit offset,
/// size, and shape kind); resolve it with [`TypeEdit::member_by_ref`], which returns
/// [`TypeWriteError::StaleMemberRef`] once the layout has changed. Holds no borrow, so it can
/// outlive the cursor it came from.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MemberRef {
    type_name: String,
    index: usize,
    generation: u64,
}

impl MemberRef {
    /// The member's index (declaration order) at mint time.
    #[inline]
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// The name of the type this ref was minted against.
    #[inline]
    #[must_use]
    pub fn type_name(&self) -> &str {
        &self.type_name
    }
}

/// A write cursor over one struct/union member, from [`TypeEdit::member`]/[`TypeEdit::member_at`].
///
/// Keyed by member name or bit offset, resolved fresh on each edit against the live type (a member
/// that no longer resolves surfaces as [`TypeWriteError::NoMember`]).
pub struct MemberEdit<'db> {
    db: &'db mut Database,
    type_name: String,
    key: MemberKey,
}

impl MemberEdit<'_> {
    /// Replace this member's type.
    ///
    /// A retype that shrinks or grows the member does not repack the aggregate: a following
    /// member keeps its offset, so a shrink can leave an unlabeled gap and a grow that would
    /// overlap a following member is rejected ([`TypeEditCode::Overlap`]).
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`], [`TypeWriteError::NoMember`], [`TypeWriteError::BuildFailed`]
    /// if `ty` cannot be built, or [`TypeWriteError::Rejected`] if the kernel rejects the type; or
    /// [`Error::InteriorNul`] for a NUL byte in a name or type.
    #[doc(alias("set_udm_type"))]
    pub fn set_type(&mut self, ty: impl Into<TypeExpr>) -> Result<()> {
        self.set_type_with_flags(ty, 0)
    }

    /// Replace this member's type, additionally passing `ETF_COMPATIBLE` so the kernel checks the
    /// replacement against the old type before applying it.
    ///
    /// As [`set_type`](Self::set_type), with the SDK's own compatibility check
    /// ([`TypeEditCode::NotCompatible`]) also enforced.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// use idakit::types::expr;
    ///
    /// db.types_mut().define("struct idakit_compat_probe { int a; };")?;
    /// db.types_mut()
    ///     .edit("idakit_compat_probe")
    ///     .member("a")
    ///     .set_type_compatible(expr::decl("unsigned int"))?;
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// As [`set_type`](Self::set_type); additionally [`TypeEditCode::NotCompatible`] if the
    /// kernel's compatibility check rejects the new type.
    #[doc(alias("set_udm_type"))]
    pub fn set_type_compatible(&mut self, ty: impl Into<TypeExpr>) -> Result<()> {
        self.set_type_with_flags(ty, ETF_COMPATIBLE)
    }

    /// Replace this member's type, sharing the recipe-build-and-apply path between
    /// [`set_type`](Self::set_type) and [`set_type_compatible`](Self::set_type_compatible).
    fn set_type_with_flags(&mut self, ty: impl Into<TypeExpr>, etf_flags: u32) -> Result<()> {
        let recipe = ty.into().checked_serialize()?;
        let result = self
            .dispatch(|db, tp, mp, bit| db.udt_set_member_type(tp, mp, bit, &recipe, etf_flags))?;
        edit_result(
            result.code,
            &result.reason,
            &self.type_name,
            Some(&self.key),
        )
    }

    /// Rename this member. The new name must be unique within the aggregate.
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`], [`TypeWriteError::NoMember`], or [`TypeWriteError::Rejected`]
    /// (e.g. [`TypeEditCode::DupName`]); or [`Error::InteriorNul`] for a NUL byte in a name.
    #[doc(alias("rename_udm"))]
    pub fn rename(&mut self, new_name: impl AsRef<str>) -> Result<()> {
        let new_name = nul_checked(new_name.as_ref(), "new member name")?;
        let result =
            self.dispatch(|db, tp, mp, bit| db.udt_rename_member(tp, mp, bit, new_name))?;
        edit_result(
            result.code,
            &result.reason,
            &self.type_name,
            Some(&self.key),
        )
    }

    /// Set this member's comment.
    ///
    /// A plain member comment (`is_regcmt=false`), not a repeatable one; idakit does not expose
    /// the repeatable flag.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// db.types_mut().define("struct Widget { int hp; };")?;
    /// db.types_mut().edit("Widget").member("hp").comment("current health")?;
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`], [`TypeWriteError::NoMember`], or [`TypeWriteError::Rejected`];
    /// or [`Error::InteriorNul`] for a NUL byte in `text`.
    #[doc(alias("set_udm_cmt"))]
    pub fn comment(&mut self, text: impl AsRef<str>) -> Result<()> {
        let text = nul_checked(text.as_ref(), "comment")?;
        let result =
            self.dispatch(|db, tp, mp, bit| db.udt_set_member_comment(tp, mp, bit, text))?;
        edit_result(
            result.code,
            &result.reason,
            &self.type_name,
            Some(&self.key),
        )
    }

    /// Set this member's value representation: radix or char format, forced sign, and leading
    /// zeros.
    ///
    /// Limited to the numeric subset [`ValueRepr`] models; setting an info-carrying
    /// representation (enum-linked, offset, string literal, struct offset, custom) is out of
    /// scope.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// use idakit::types::{NumberFormat, ValueRepr};
    ///
    /// db.types_mut().define("struct Widget { int hp; };")?;
    /// let repr = ValueRepr {
    ///     format: NumberFormat::Hexadecimal,
    ///     signed: true,
    ///     leading_zeros: false,
    /// };
    /// db.types_mut().edit("Widget").member("hp").set_repr(repr)?;
    /// let ty = db.type_named("Widget")?;
    /// let idakit::types::TypeShape::Struct { members, .. } = ty.shape() else {
    ///     unreachable!()
    /// };
    /// assert!(members[0].repr == Some(repr));
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`], [`TypeWriteError::NoMember`], or [`TypeWriteError::Rejected`]
    /// (e.g. [`TypeEditCode::BadRepr`] if the kernel rejects the combination); or
    /// [`Error::InteriorNul`] for a NUL byte in the type name.
    #[doc(alias("set_udm_repr"))]
    pub fn set_repr(&mut self, repr: ValueRepr) -> Result<()> {
        let result = self.dispatch(|db, tp, mp, bit| {
            db.udt_set_member_repr(
                tp,
                mp,
                bit,
                repr.format.to_frb(),
                repr.signed,
                repr.leading_zeros,
            )
        })?;
        edit_result(
            result.code,
            &result.reason,
            &self.type_name,
            Some(&self.key),
        )
    }

    /// Delete this member from its aggregate.
    ///
    /// Deleting a non-tail member leaves a `TAFLD_GAP` padding member in its place (IDA names it
    /// `gapN` and types it as a byte array) rather than shifting later members up, so the aggregate
    /// keeps its size and later members keep their offsets. Deleting the tail member shrinks the
    /// aggregate normally.
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`], [`TypeWriteError::NoMember`], or [`TypeWriteError::Rejected`];
    /// or [`Error::InteriorNul`] for a NUL byte in a name.
    #[doc(alias("del_udm"))]
    pub fn delete(&mut self) -> Result<()> {
        let result = self.dispatch(Database::udt_del_member)?;
        edit_result(
            result.code,
            &result.reason,
            &self.type_name,
            Some(&self.key),
        )
    }

    /// Resolve the type-name and member-name from the key, then run `f`. An offset key passes an
    /// empty member name (the generated fn's by-bit selector) and the offset instead.
    fn dispatch(
        &mut self,
        f: impl FnOnce(&mut Database, &str, &str, u64) -> sys::TypeWriteResult,
    ) -> Result<sys::TypeWriteResult> {
        let type_name = nul_checked(&self.type_name, "type name")?;
        let (member, bit) = match &self.key {
            MemberKey::Name(n) => (nul_checked(n, "member name")?, 0),
            MemberKey::Offset(o) => ("", *o),
        };
        Ok(f(&mut *self.db, type_name, member, bit))
    }
}

impl fmt::Debug for MemberEdit<'_> {
    // Skips the exclusively-held `&mut Database`; only the key is printable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemberEdit")
            .field("type_name", &self.type_name)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// A write cursor over one enum constant, from [`TypeEdit::constant`].
///
/// Keyed by name, resolved fresh on each edit against the live enum (a constant that no longer
/// resolves surfaces as [`TypeWriteError::NoMember`]).
pub struct ConstantEdit<'db> {
    db: &'db mut Database,
    type_name: String,
    name: String,
}

impl ConstantEdit<'_> {
    /// Set this constant's value.
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`], [`TypeWriteError::NoMember`], or [`TypeWriteError::Rejected`];
    /// or [`Error::InteriorNul`] for a NUL byte in a name.
    #[doc(alias("edit_edm"))]
    pub fn set_value(&mut self, value: u64) -> Result<()> {
        let result = self.dispatch(|db, tp, np| db.enum_set_member_value(tp, np, value))?;
        self.result(result.code, &result.reason)
    }

    /// Rename this constant. The new name must be unique.
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`], [`TypeWriteError::NoMember`], or [`TypeWriteError::Rejected`]
    /// (e.g. [`TypeEditCode::DupName`] or [`TypeEditCode::AlienName`]); or [`Error::InteriorNul`]
    /// for a NUL byte in a name.
    #[doc(alias("rename_edm"))]
    pub fn rename(&mut self, new_name: impl AsRef<str>) -> Result<()> {
        self.rename_with_flags(new_name.as_ref(), 0)
    }

    /// Rename this constant, forcing the name through an alien-name collision.
    ///
    /// As [`rename`](Self::rename), with `ETF_FORCENAME` set: a name already used by another
    /// enum ([`TypeEditCode::AlienName`]) is accepted instead of rejected.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// db.types_mut().define("enum idakit_rename_forcename { IDAKIT_RENAME_OLD = 1 };")?;
    /// db.types_mut()
    ///     .edit("idakit_rename_forcename")
    ///     .constant("IDAKIT_RENAME_OLD")
    ///     .rename_forced("IDAKIT_RENAME_NEW")?;
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// As [`rename`](Self::rename).
    #[doc(alias("rename_edm"))]
    pub fn rename_forced(&mut self, new_name: impl AsRef<str>) -> Result<()> {
        self.rename_with_flags(new_name.as_ref(), ETF_FORCENAME)
    }

    /// Rename this constant, sharing the resolve-and-rename path between
    /// [`rename`](Self::rename) and [`rename_forced`](Self::rename_forced).
    fn rename_with_flags(&mut self, new_name: &str, etf_flags: u32) -> Result<()> {
        let new_name = nul_checked(new_name, "new constant name")?;
        let result =
            self.dispatch(|db, tp, np| db.enum_rename_member(tp, np, new_name, etf_flags))?;
        self.result(result.code, &result.reason)
    }

    /// Delete this constant from its enum.
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`], [`TypeWriteError::NoMember`], or [`TypeWriteError::Rejected`];
    /// or [`Error::InteriorNul`] for a NUL byte in a name.
    #[doc(alias("del_edm"))]
    pub fn delete(&mut self) -> Result<()> {
        let result = self.dispatch(Database::enum_del_member)?;
        self.result(result.code, &result.reason)
    }

    /// Resolve the type-name and constant-name, then run `f`.
    fn dispatch(
        &mut self,
        f: impl FnOnce(&mut Database, &str, &str) -> sys::TypeWriteResult,
    ) -> Result<sys::TypeWriteResult> {
        let type_name = nul_checked(&self.type_name, "type name")?;
        let name = nul_checked(&self.name, "constant name")?;
        Ok(f(&mut *self.db, type_name, name))
    }

    fn result(&self, code: c_int, reason: &str) -> Result<()> {
        edit_result(
            code,
            reason,
            &self.type_name,
            Some(&MemberKey::Name(self.name.clone())),
        )
    }
}

impl fmt::Debug for ConstantEdit<'_> {
    // Skips the exclusively-held `&mut Database`; only the key is printable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConstantEdit")
            .field("type_name", &self.type_name)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// How a [`MemberEdit`] selects its member: by name or by bit offset.
#[derive(Clone, Debug, PartialEq, Eq)]
enum MemberKey {
    Name(String),
    Offset(u64),
}

impl fmt::Display for MemberKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(n) => write!(f, "named {n:?}"),
            Self::Offset(o) => write!(f, "at bit offset {o}"),
        }
    }
}

/// Maps a member-edit return code and any captured reason to a crate [`Result`]. `key` is the
/// member selector for a [`TypeWriteError::NoMember`] (absent when adding a new member).
fn edit_result(code: c_int, reason: &str, type_name: &str, key: Option<&MemberKey>) -> Result<()> {
    match code {
        0 => Ok(()),
        sys::TEDIT_NO_TYPE => Err(TypeWriteError::NoType {
            name: type_name.to_owned(),
        }
        .into()),
        sys::TEDIT_NO_MEMBER => Err(TypeWriteError::NoMember {
            type_name: type_name.to_owned(),
            key: key.map(MemberKey::to_string).unwrap_or_default(),
        }
        .into()),
        sys::TEDIT_BUILD => Err(TypeWriteError::BuildFailed {
            reason: reason_or(
                reason,
                "an unknown named type or invalid declaration within it",
            ),
        }
        .into()),
        n => match TypeEditCode::try_from(n) {
            Ok(code) => Err(TypeWriteError::Rejected {
                type_name: type_name.to_owned(),
                code,
            }
            .into()),
            Err(_) => Err(TypeWriteError::UnknownCode {
                type_name: type_name.to_owned(),
                code: n,
            }
            .into()),
        },
    }
}

/// The single error for the whole type-write surface.
///
/// Covers applying a type at an address ([`LocationMut::set_type`](crate::LocationMut::set_type),
/// [`FunctionEdit::set_type`](crate::function::FunctionEdit::set_type)), function-prototype
/// surgery ([`FunctionEdit`](crate::function::FunctionEdit)'s field-at-a-time verbs), and til
/// member/constant edits ([`TypeEdit`]/[`MemberEdit`]/[`ConstantEdit`]).
///
/// Carried by [`Error::TypeWrite`], which `?` flattens into the crate [`Result`]. Only til
/// member/constant edits carry a structured [`TypeEditCode`] ([`Rejected`](Self::Rejected)):
/// whole-item apply and prototype surgery route through kernel ops (`apply_tinfo`, `create_func`)
/// that return only a bool, so their rejections carry a reason string
/// ([`ApplyRejected`](Self::ApplyRejected)) instead.
#[derive(Debug, Snafu, PartialEq, Eq)]
#[snafu(visibility(pub(crate)))]
pub enum TypeWriteError {
    /// No type with the given name exists in the local type library.
    #[snafu(display("no type named {name:?} in the local type library"))]
    NoType {
        /// The type name that was not found.
        name: String,
    },

    /// The selected member did not resolve in the type.
    #[snafu(display("no member {key} in type {type_name:?}"))]
    NoMember {
        /// The type whose member was sought.
        type_name: String,
        /// The member selector, rendered (`named "hp"` or `at bit offset 64`).
        key: String,
    },

    /// A member index was past the last member when minting a [`MemberRef`].
    #[snafu(display(
        "member index {index} out of range ({count} member(s)) in type {type_name:?}"
    ))]
    MemberIndexOutOfRange {
        /// The type the ref was minted against.
        type_name: String,
        /// The out-of-range index.
        index: usize,
        /// The type's actual member count.
        count: usize,
    },

    /// A parameter index was past the last parameter in a function-prototype surgery edit.
    #[snafu(display(
        "parameter index {index} out of range ({arity} parameter(s)) at {address:#x}"
    ))]
    ArgIndexOutOfRange {
        /// The function entry.
        address: u64,
        /// The out-of-range index.
        index: usize,
        /// The prototype's actual parameter count.
        arity: usize,
    },

    /// A [`MemberRef`] no longer matches the type's layout (a structural edit since it was minted,
    /// or a ref from a different type).
    #[snafu(display(
        "member reference into {type_name:?} is stale (the layout changed since it was minted)"
    ))]
    StaleMemberRef {
        /// The type the ref was minted against.
        type_name: String,
    },

    /// The address carries no function prototype to edit.
    #[snafu(display("no function prototype to edit at {address:#x}"))]
    NoPrototype {
        /// The function entry with no editable prototype.
        address: u64,
    },

    /// A type declaration could not be parsed. `reason` is IDA's own parser message, captured off
    /// the message channel.
    #[snafu(display("could not parse type declaration {decl:?}: {reason}"))]
    ParseFailed {
        /// The declaration text that failed to parse.
        decl: String,
        /// IDA's parser message.
        reason: String,
    },

    /// A replacement or new type could not be built from its recipe.
    #[snafu(display("could not build the type: {reason}"))]
    BuildFailed {
        /// Why the type could not be built.
        reason: String,
    },

    /// A til member/constant edit was rejected; carries the structured [`TypeEditCode`].
    #[snafu(display("editing {type_name:?} was rejected: {code}"))]
    Rejected {
        /// The type being edited.
        type_name: String,
        /// The kernel's `tinfo_code_t`, mirrored.
        code: TypeEditCode,
    },

    /// A whole-item type apply or a function-prototype surgery edit was rejected. `reason` is
    /// IDA's own diagnostics when the kernel left any, since the underlying bool-returning op
    /// (`apply_tinfo`, `create_func`) carries no structured code.
    #[snafu(display("could not apply type at {address:#x}: {reason}"))]
    ApplyRejected {
        /// The address the apply or surgery targeted.
        address: u64,
        /// Why the apply was rejected.
        reason: String,
    },

    /// The kernel returned a `tinfo_code_t` outside the modelled set (version drift). A loud guard
    /// carrying the raw code rather than a silently absorbed catch-all.
    #[snafu(display("editing {type_name:?} returned an unmodeled type-edit code {code}"))]
    UnknownCode {
        /// The type being edited.
        type_name: String,
        /// The raw code outside the modelled set.
        code: i32,
    },
}

/// A structured type-edit result code, mirroring IDA's `tinfo_code_t` (`typeinf.hpp`, IDA 9.3).
///
/// Returned inside [`TypeWriteError::Rejected`] so a caller matches the exact cause of a rejected
/// til member/constant edit. The complete closed SDK set: a code outside it is version drift,
/// surfaced as [`TypeWriteError::UnknownCode`] rather than folded in here.
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Debug, TryFromPrimitive, IntoPrimitive, VariantArray,
)]
#[repr(i32)]
#[doc(alias("tinfo_code_t"))]
pub enum TypeEditCode {
    /// `TERR_OK`: no error. Never carried by an error; present for a faithful, round-trippable
    /// mirror of the SDK enum.
    Ok = 0,
    /// `TERR_SAVE_ERROR`: failed to save.
    SaveError = -1,
    /// `TERR_SERIALIZE`: failed to serialize.
    Serialize = -2,
    /// `TERR_BAD_NAME`: the name is not acceptable.
    BadName = -3,
    /// `TERR_BAD_ARG`: bad argument.
    BadArg = -4,
    /// `TERR_BAD_TYPE`: bad type.
    BadType = -5,
    /// `TERR_BAD_SIZE`: bad size.
    BadSize = -6,
    /// `TERR_BAD_INDEX`: bad index.
    BadIndex = -7,
    /// `TERR_BAD_ARRAY`: arrays are forbidden as function arguments.
    BadArray = -8,
    /// `TERR_BAD_BF`: bitfields are forbidden as function arguments.
    BadBitfield = -9,
    /// `TERR_BAD_OFFSET`: bad member offset.
    BadOffset = -10,
    /// `TERR_BAD_UNIVAR`: unions cannot have variable-sized members.
    BadUnionVar = -11,
    /// `TERR_BAD_VARLAST`: a variable-sized member must be the last member.
    BadVarLast = -12,
    /// `TERR_OVERLAP`: the member overlaps with members that cannot be deleted.
    Overlap = -13,
    /// `TERR_BAD_SUBTYPE`: recursive structure nesting is forbidden.
    BadSubtype = -14,
    /// `TERR_BAD_VALUE`: the value is not acceptable.
    BadValue = -15,
    /// `TERR_NO_BMASK`: the bitmask was not found.
    NoBitmask = -16,
    /// `TERR_BAD_BMASK`: bad enum member mask.
    BadBitmask = -17,
    /// `TERR_BAD_MSKVAL`: bad bitmask and value combination.
    BadMaskValue = -18,
    /// `TERR_BAD_REPR`: bad or incompatible field representation.
    BadRepr = -19,
    /// `TERR_GRP_NOEMPTY`: could not delete the group mask of a non-empty group.
    GroupNotEmpty = -20,
    /// `TERR_DUPNAME`: duplicate name.
    DupName = -21,
    /// `TERR_UNION_BF`: unions cannot have bitfields.
    UnionBitfield = -22,
    /// `TERR_BAD_TAH`: bad type-attribute bits.
    BadTah = -23,
    /// `TERR_BAD_BASE`: bad base class.
    BadBase = -24,
    /// `TERR_BAD_GAP`: bad gap.
    BadGap = -25,
    /// `TERR_NESTED`: recursive structure nesting is forbidden.
    Nested = -26,
    /// `TERR_NOT_COMPAT`: the new type is not compatible with the old type.
    NotCompatible = -27,
    /// `TERR_BAD_LAYOUT`: failed to calculate the structure/union layout.
    BadLayout = -28,
    /// `TERR_BAD_GROUPS`: bad group sizes for a bitmask enum.
    BadGroups = -29,
    /// `TERR_BAD_SERIAL`: the enum value has too many serials.
    BadSerial = -30,
    /// `TERR_ALIEN_NAME`: the enum member name is used in another enum.
    AlienName = -31,
    /// `TERR_STOCK`: stock type info cannot be modified.
    Stock = -32,
    /// `TERR_ENUM_SIZE`: bad enum size.
    EnumSize = -33,
    /// `TERR_NOT_IMPL`: not implemented.
    NotImplemented = -34,
    /// `TERR_TYPE_WORSE`: the new type is worse than the old type.
    TypeWorse = -35,
    /// `TERR_BAD_FX_SIZE`: cannot extend the struct beyond its fixed size.
    BadFixedSize = -36,
    /// `TERR_STRUCT_SIZE`: bad fixed structure size.
    StructSize = -37,
    /// `TERR_NOT_FOUND`: the member was not found.
    NotFound = -38,
}

impl TypeEditCode {
    /// A short human message for this code.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::SaveError => "failed to save",
            Self::Serialize => "failed to serialize",
            Self::BadName => "the name is not acceptable",
            Self::BadArg => "bad argument",
            Self::BadType => "bad type",
            Self::BadSize => "bad size",
            Self::BadIndex => "bad index",
            Self::BadArray => "arrays are forbidden as function arguments",
            Self::BadBitfield => "bitfields are forbidden as function arguments",
            Self::BadOffset => "bad member offset",
            Self::BadUnionVar => "unions cannot have variable-sized members",
            Self::BadVarLast => "a variable-sized member must be the last member",
            Self::Overlap => "the member overlaps with members that cannot be deleted",
            Self::BadValue => "the value is not acceptable",
            Self::NoBitmask => "the bitmask was not found",
            Self::BadBitmask => "bad enum member mask",
            Self::BadMaskValue => "bad bitmask and value combination",
            Self::BadRepr => "bad or incompatible field representation",
            Self::GroupNotEmpty => "could not delete the group mask of a non-empty group",
            Self::DupName => "duplicate name",
            Self::UnionBitfield => "unions cannot have bitfields",
            Self::BadTah => "bad type-attribute bits",
            Self::BadBase => "bad base class",
            Self::BadGap => "bad gap",
            Self::BadSubtype | Self::Nested => "recursive structure nesting is forbidden",
            Self::NotCompatible => "the new type is not compatible with the old type",
            Self::BadLayout => "failed to calculate the structure/union layout",
            Self::BadGroups => "bad group sizes for a bitmask enum",
            Self::BadSerial => "the enum value has too many serials",
            Self::AlienName => "the enum member name is used in another enum",
            Self::Stock => "stock type info cannot be modified",
            Self::EnumSize => "bad enum size",
            Self::NotImplemented => "not implemented",
            Self::TypeWorse => "the new type is worse than the old type",
            Self::BadFixedSize => "cannot extend the struct beyond its fixed size",
            Self::StructSize => "bad fixed structure size",
            Self::NotFound => "the member was not found",
        }
    }
}

impl fmt::Display for TypeEditCode {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    /// Every modelled code round-trips through its raw `tinfo_code_t` value, so a drifted
    /// discriminant fails here.
    #[test]
    fn type_edit_code_round_trips() {
        for &v in TypeEditCode::VARIANTS {
            let raw = i32::from(v);
            assert!(TypeEditCode::try_from(raw) == Ok(v));
        }
    }

    /// The discriminants are pinned to the SDK's literal `TERR_*` values.
    #[rstest]
    #[case(TypeEditCode::Ok, 0)]
    #[case(TypeEditCode::DupName, -21)]
    #[case(TypeEditCode::Stock, -32)]
    #[case(TypeEditCode::NotFound, -38)]
    fn type_edit_code_pins_terr_values(#[case] code: TypeEditCode, #[case] expected: i32) {
        assert!(i32::from(code) == expected);
    }

    /// A code outside the modelled set is rejected, not absorbed.
    #[test]
    fn type_edit_code_rejects_unknown() {
        assert!(TypeEditCode::try_from(-39).is_err());
        assert!(TypeEditCode::try_from(1).is_err());
    }

    /// `MemberRef` orders by type name, then index, then generation.
    #[test]
    fn member_ref_ord_sorts_by_type_then_index_then_generation() {
        let a = MemberRef {
            type_name: "Pt".to_owned(),
            index: 0,
            generation: 1,
        };
        let b = MemberRef {
            type_name: "Pt".to_owned(),
            index: 1,
            generation: 0,
        };
        let c = MemberRef {
            type_name: "Zz".to_owned(),
            index: 0,
            generation: 0,
        };
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    /// The member selector renders both keyings for a [`TypeWriteError::NoMember`].
    #[test]
    fn member_key_renders() {
        assert!(MemberKey::Name("hp".to_owned()).to_string() == "named \"hp\"");
        assert!(MemberKey::Offset(64).to_string() == "at bit offset 64");
    }
}
