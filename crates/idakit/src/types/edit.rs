//! Writes to the database's type library through the [`TypesMut`] capability cursor.
//!
//! [`TypesMut`], from [`Database::types_mut`], is the write half of the type subsystem. It exposes
//! [`define`](TypesMut::define), which parses C declarations into the local type library, and
//! [`edit`](TypesMut::edit), which opens a named type for member surgery through [`TypeEdit`] and
//! its [`MemberEdit`] (struct/union fields) and [`ConstantEdit`] (enum constants) sub-cursors.
//! Editing an attached typeref auto-propagates to every reference, so a struct fixed once reflows
//! everywhere it is used.

use std::collections::hash_map::DefaultHasher;
use std::ffi::{CString, c_char, c_int};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ptr;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use snafu::Snafu;
use strum::VariantArray;

use idakit_sys as sys;

use crate::Database;
use crate::error::{Error, Result};
use crate::ffi::{reason_or, with_cstr};
use crate::types::TypeExpr;

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

    /// Open the existing named type `name` for member surgery.
    ///
    /// Infallible to acquire: a missing type surfaces as [`TypeEditError::NoType`] from the first
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
    /// [`Error::TypeEdit`] wrapping [`TypeEditError::NoType`] if the type does not exist,
    /// [`TypeEditError::BuildFailed`] if `ty` cannot be built, or [`TypeEditError::Rejected`] if
    /// the kernel rejects the member (e.g. a duplicate name); or [`Error::InteriorNul`] for a NUL
    /// byte in a name.
    #[doc(alias("add_udm"))]
    pub fn add_member(&mut self, name: impl AsRef<str>, ty: impl Into<TypeExpr>) -> Result<()> {
        self.add_member_impl(name.as_ref(), ty.into(), sys::IDAKIT_MEMBER_APPEND)
    }

    /// Add a member named `name` of type `ty` at `bit_offset` from the start of the aggregate.
    ///
    /// The offset is in bits, matching [`TypeMember::bit_offset`](crate::types::TypeMember). The
    /// kernel keeps members offset-sorted, so an offset that would collide is rejected.
    ///
    /// # Errors
    /// As [`add_member`](Self::add_member); [`TypeEditError::Rejected`] additionally covers an
    /// offset the kernel will not place (e.g. an overlap).
    #[doc(alias("add_udm"))]
    pub fn add_member_at(
        &mut self,
        bit_offset: u64,
        name: impl AsRef<str>,
        ty: impl Into<TypeExpr>,
    ) -> Result<()> {
        self.add_member_impl(name.as_ref(), ty.into(), bit_offset)
    }

    fn add_member_impl(&mut self, name: &str, ty: TypeExpr, member_bit: u64) -> Result<()> {
        let recipe = ty.serialize();
        let type_name = self.name.clone();
        let db = &mut *self.db;
        let (code, reason) = with_cstr(&type_name, "type name", |tp| {
            with_cstr(name, "member name", |mp| {
                db.udt_add_member(tp, mp, &recipe, member_bit)
            })
        })??;
        edit_result(code, reason, &type_name, None)
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
    /// [`Error::TypeEdit`] wrapping [`TypeEditError::NoType`] if the enum does not exist, or
    /// [`TypeEditError::Rejected`] if the kernel rejects the constant (e.g. a duplicate name); or
    /// [`Error::InteriorNul`] for a NUL byte in a name.
    #[doc(alias("add_edm"))]
    pub fn add_constant(&mut self, name: impl AsRef<str>, value: u64) -> Result<()> {
        let type_name = self.name.clone();
        let db = &mut *self.db;
        let (code, reason) = with_cstr(&type_name, "type name", |tp| {
            with_cstr(name.as_ref(), "constant name", |np| {
                db.enum_add_member(tp, np, value)
            })
        })??;
        edit_result(code, reason, &type_name, None)
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
    /// type's layout. It survives renames of other members, but any layout change (adding, removing,
    /// or resizing a member) invalidates it, so [`member_by_ref`](Self::member_by_ref) then returns
    /// [`TypeEditError::StaleMemberRef`] instead of silently editing the wrong member. Chiefly for
    /// members a name key cannot address (anonymous fields).
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
    /// [`Error::TypeEdit`] wrapping [`TypeEditError::NoType`] if no struct/union with this name
    /// exists, or [`TypeEditError::MemberIndexOutOfRange`] if `index` is past the last member.
    pub fn member_ref(&self, index: usize) -> Result<MemberRef> {
        let (count, generation, _) = self.read_layout(index)?;
        if index >= count {
            return Err(TypeEditError::MemberIndexOutOfRange {
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
    /// [`Error::TypeEdit`] wrapping [`TypeEditError::NoType`] if the type no longer exists, or
    /// [`TypeEditError::StaleMemberRef`] if the ref was minted against a different type or the
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
            _ => Err(TypeEditError::StaleMemberRef { type_name: name }.into()),
        }
    }

    /// Read the named type's struct/union layout: its member count, a structural fingerprint (the
    /// count plus each member's bit offset, so a rename does not change it but any layout edit
    /// does), and the selection key for `index` when in range.
    fn read_layout(&self, index: usize) -> Result<(usize, u64, Option<MemberKey>)> {
        let ty = self
            .db
            .type_named(&self.name)
            .map_err(|_| TypeEditError::NoType {
                name: self.name.clone(),
            })?;
        let members = ty.members().ok_or_else(|| TypeEditError::NoType {
            name: self.name.clone(),
        })?;
        let mut hasher = DefaultHasher::new();
        members.len().hash(&mut hasher);
        for member in members {
            member.bit_offset.hash(&mut hasher);
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

/// A durable handle to a struct/union member by index, from [`TypeEdit::member_ref`].
///
/// Carries a structural fingerprint of the type's layout at mint time; resolve it with
/// [`TypeEdit::member_by_ref`], which returns [`TypeEditError::StaleMemberRef`] once the layout has
/// changed. Holds no borrow, so it can outlive the cursor it came from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
/// that no longer resolves surfaces as [`TypeEditError::NoMember`]).
pub struct MemberEdit<'db> {
    db: &'db mut Database,
    type_name: String,
    key: MemberKey,
}

impl MemberEdit<'_> {
    /// Replace this member's type.
    ///
    /// # Errors
    /// [`Error::TypeEdit`] wrapping [`TypeEditError::NoType`], [`TypeEditError::NoMember`],
    /// [`TypeEditError::BuildFailed`] if `ty` cannot be built, or [`TypeEditError::Rejected`] if
    /// the kernel rejects the type; or [`Error::InteriorNul`] for a NUL byte in a name.
    #[doc(alias("set_udm_type"))]
    pub fn set_type(&mut self, ty: impl Into<TypeExpr>) -> Result<()> {
        let recipe = ty.into().serialize();
        let (code, reason) =
            self.dispatch(|db, tp, mp, bit| db.udt_set_member_type(tp, mp, bit, &recipe))?;
        edit_result(code, reason, &self.type_name, Some(&self.key))
    }

    /// Rename this member. The new name must be unique within the aggregate.
    ///
    /// # Errors
    /// [`Error::TypeEdit`] wrapping [`TypeEditError::NoType`], [`TypeEditError::NoMember`], or
    /// [`TypeEditError::Rejected`] (e.g. [`TypeEditCode::DupName`]); or [`Error::InteriorNul`] for
    /// a NUL byte in a name.
    #[doc(alias("rename_udm"))]
    pub fn rename(&mut self, new_name: impl AsRef<str>) -> Result<()> {
        let nn = CString::new(new_name.as_ref()).map_err(|_| Error::InteriorNul {
            arg: "new member name",
        })?;
        let (code, reason) =
            self.dispatch(|db, tp, mp, bit| db.udt_rename_member(tp, mp, bit, nn.as_ptr()))?;
        edit_result(code, reason, &self.type_name, Some(&self.key))
    }

    /// Delete this member from its aggregate.
    ///
    /// # Errors
    /// [`Error::TypeEdit`] wrapping [`TypeEditError::NoType`], [`TypeEditError::NoMember`], or
    /// [`TypeEditError::Rejected`]; or [`Error::InteriorNul`] for a NUL byte in a name.
    #[doc(alias("del_udm"))]
    pub fn delete(&mut self) -> Result<()> {
        let (code, reason) = self.dispatch(|db, tp, mp, bit| db.udt_del_member(tp, mp, bit))?;
        edit_result(code, reason, &self.type_name, Some(&self.key))
    }

    /// Resolve the type-name and member-name C pointers from the key, then run `f`. For an offset
    /// key the member pointer is null and the offset is passed instead. The C strings outlive the
    /// synchronous `f`.
    fn dispatch(
        &mut self,
        f: impl FnOnce(&mut Database, *const c_char, *const c_char, u64) -> (c_int, String),
    ) -> Result<(c_int, String)> {
        let tn = CString::new(self.type_name.as_str())
            .map_err(|_| Error::InteriorNul { arg: "type name" })?;
        let (member_c, bit) = match &self.key {
            MemberKey::Name(n) => (
                Some(
                    CString::new(n.as_str())
                        .map_err(|_| Error::InteriorNul { arg: "member name" })?,
                ),
                0,
            ),
            MemberKey::Offset(o) => (None, *o),
        };
        let member_p = member_c.as_ref().map_or(ptr::null(), |c| c.as_ptr());
        Ok(f(&mut *self.db, tn.as_ptr(), member_p, bit))
    }
}

/// A write cursor over one enum constant, from [`TypeEdit::constant`].
///
/// Keyed by name, resolved fresh on each edit against the live enum (a constant that no longer
/// resolves surfaces as [`TypeEditError::NoMember`]).
pub struct ConstantEdit<'db> {
    db: &'db mut Database,
    type_name: String,
    name: String,
}

impl ConstantEdit<'_> {
    /// Set this constant's value.
    ///
    /// # Errors
    /// [`Error::TypeEdit`] wrapping [`TypeEditError::NoType`], [`TypeEditError::NoMember`], or
    /// [`TypeEditError::Rejected`]; or [`Error::InteriorNul`] for a NUL byte in a name.
    #[doc(alias("edit_edm"))]
    pub fn set_value(&mut self, value: u64) -> Result<()> {
        let (code, reason) = self.dispatch(|db, tp, np| db.enum_set_member_value(tp, np, value))?;
        self.result(code, reason)
    }

    /// Rename this constant. The new name must be unique.
    ///
    /// # Errors
    /// [`Error::TypeEdit`] wrapping [`TypeEditError::NoType`], [`TypeEditError::NoMember`], or
    /// [`TypeEditError::Rejected`] (e.g. [`TypeEditCode::DupName`] or [`TypeEditCode::AlienName`]);
    /// or [`Error::InteriorNul`] for a NUL byte in a name.
    #[doc(alias("rename_edm"))]
    pub fn rename(&mut self, new_name: impl AsRef<str>) -> Result<()> {
        let nn = CString::new(new_name.as_ref()).map_err(|_| Error::InteriorNul {
            arg: "new constant name",
        })?;
        let (code, reason) =
            self.dispatch(|db, tp, np| db.enum_rename_member(tp, np, nn.as_ptr()))?;
        self.result(code, reason)
    }

    /// Delete this constant from its enum.
    ///
    /// # Errors
    /// [`Error::TypeEdit`] wrapping [`TypeEditError::NoType`], [`TypeEditError::NoMember`], or
    /// [`TypeEditError::Rejected`]; or [`Error::InteriorNul`] for a NUL byte in a name.
    #[doc(alias("del_edm"))]
    pub fn delete(&mut self) -> Result<()> {
        let (code, reason) = self.dispatch(|db, tp, np| db.enum_del_member(tp, np))?;
        self.result(code, reason)
    }

    /// Resolve the type-name and constant-name C pointers, then run `f`. The C strings outlive the
    /// synchronous `f`.
    fn dispatch(
        &mut self,
        f: impl FnOnce(&mut Database, *const c_char, *const c_char) -> (c_int, String),
    ) -> Result<(c_int, String)> {
        let tn = CString::new(self.type_name.as_str())
            .map_err(|_| Error::InteriorNul { arg: "type name" })?;
        let np = CString::new(self.name.as_str()).map_err(|_| Error::InteriorNul {
            arg: "constant name",
        })?;
        Ok(f(&mut *self.db, tn.as_ptr(), np.as_ptr()))
    }

    fn result(&self, code: c_int, reason: String) -> Result<()> {
        edit_result(
            code,
            reason,
            &self.type_name,
            Some(&MemberKey::Name(self.name.clone())),
        )
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
/// member selector for a [`TypeEditError::NoMember`] (absent when adding a new member).
fn edit_result(
    code: c_int,
    reason: String,
    type_name: &str,
    key: Option<&MemberKey>,
) -> Result<()> {
    match code {
        0 => Ok(()),
        sys::IDAKIT_TEDIT_NO_TYPE => Err(TypeEditError::NoType {
            name: type_name.to_owned(),
        }
        .into()),
        sys::IDAKIT_TEDIT_NO_MEMBER => Err(TypeEditError::NoMember {
            type_name: type_name.to_owned(),
            key: key.map(MemberKey::to_string).unwrap_or_default(),
        }
        .into()),
        sys::IDAKIT_TEDIT_BUILD => Err(TypeEditError::BuildFailed {
            reason: reason_or(
                reason,
                "an unknown named type or invalid declaration within it",
            ),
        }
        .into()),
        n => match TypeEditCode::try_from(n) {
            Ok(code) => Err(TypeEditError::Rejected {
                type_name: type_name.to_owned(),
                code,
            }
            .into()),
            Err(_) => Err(TypeEditError::UnknownCode {
                type_name: type_name.to_owned(),
                code: n,
            }
            .into()),
        },
    }
}

/// Why a type-library member edit failed, from the [`TypeEdit`]/[`MemberEdit`] verbs.
///
/// Carried by [`Error::TypeEdit`], which `?` flattens into the crate [`Result`]. A kernel rejection
/// carries the structured [`TypeEditCode`] so a caller can match the cause.
#[derive(Debug, Snafu, PartialEq, Eq)]
#[snafu(visibility(pub(crate)))]
pub enum TypeEditError {
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

    /// A [`MemberRef`] no longer matches the type's layout (a structural edit since it was minted,
    /// or a ref from a different type).
    #[snafu(display(
        "member reference into {type_name:?} is stale (the layout changed since it was minted)"
    ))]
    StaleMemberRef {
        /// The type the ref was minted against.
        type_name: String,
    },

    /// A replacement or new member type could not be built from its recipe.
    #[snafu(display("could not build the member type: {reason}"))]
    BuildFailed {
        /// Why the member type could not be built.
        reason: String,
    },

    /// The kernel rejected the edit; carries the structured [`TypeEditCode`].
    #[snafu(display("editing {type_name:?} was rejected: {code}"))]
    Rejected {
        /// The type being edited.
        type_name: String,
        /// The kernel's `tinfo_code_t`, mirrored.
        code: TypeEditCode,
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
/// Returned inside [`TypeEditError::Rejected`] so a caller matches the exact cause of a rejected
/// member edit. The complete closed SDK set: a code outside it is version drift, surfaced as
/// [`TypeEditError::UnknownCode`] rather than folded in here.
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
            Self::BadSubtype => "recursive structure nesting is forbidden",
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
            Self::Nested => "recursive structure nesting is forbidden",
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
    #[test]
    fn type_edit_code_pins_terr_values() {
        assert!(i32::from(TypeEditCode::Ok) == 0);
        assert!(i32::from(TypeEditCode::DupName) == -21);
        assert!(i32::from(TypeEditCode::Stock) == -32);
        assert!(i32::from(TypeEditCode::NotFound) == -38);
    }

    /// A code outside the modelled set is rejected, not absorbed.
    #[test]
    fn type_edit_code_rejects_unknown() {
        assert!(TypeEditCode::try_from(-39).is_err());
        assert!(TypeEditCode::try_from(1).is_err());
    }

    /// The member selector renders both keyings for a [`TypeEditError::NoMember`].
    #[test]
    fn member_key_renders() {
        assert!(MemberKey::Name("hp".to_owned()).to_string() == "named \"hp\"");
        assert!(MemberKey::Offset(64).to_string() == "at bit offset 64");
    }
}
