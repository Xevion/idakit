//! [`TypeImage`]: an owned, `Send` snapshot of one resolved type -- a named type or a function
//! prototype -- walked out of the kernel into an interned [`TypeTable`].
//!
//! The structured counterpart to a rendered declaration string: the root [`TypeId`] and every
//! member/parameter it references are real handles into [`types`](TypeImage::types), so a caller
//! inspects a struct's fields or a prototype's parameters by shape, not by parsing text.
//! Materialized on the kernel thread and handed back owned, so it analyzes anywhere -- the type
//! analogue of the decompiler's [`Ctree`](crate::ctree::Ctree).

use std::ffi::{c_int, c_void};

use idakit_sys as sys;

use crate::Idb;
use crate::ctree::ExtractError;
use crate::error::{Error, Result};
use crate::ffi::with_cstr;
use crate::types::{
    TypeBuilder, TypeData, TypeId, TypeKind, TypeMember, TypeSink, TypeTable, tid, type_vtbl,
};

impl Idb {
    /// Resolve a named type into an owned [`TypeImage`]: its structured shape and every member's
    /// type, interned in one [`TypeTable`]. `Err` if no such type exists.
    pub fn type_named(&self, name: &str) -> Result<TypeImage> {
        let walked = with_cstr(name, "name", |p| {
            // SAFETY: `p` is a valid C string for the call; the kernel is claimed for `&self`.
            walk_type(|v, ctx, root| unsafe { sys::idakit_type_walk(p, v, ctx, root) })
        })?;
        match walked {
            Ok(Some(image)) => Ok(image),
            Ok(None) => Err(Error::TypeNotFound {
                name: name.to_owned(),
            }),
            // A malformed local type is near-unreachable and address-less; 0 stands in.
            Err(source) => Err(Error::Extract { address: 0, source }),
        }
    }
}

/// An owned, `Send` snapshot of one resolved type: a [`root`](Self::root) [`TypeId`] into an
/// interned [`TypeTable`] holding it and every type it references. Build with
/// [`Idb::type_named`] or [`Function::prototype_type`](crate::Function::prototype_type), then
/// walk it via [`kind`](Self::kind)/[`members`](Self::members) and resolve child handles with
/// [`get`](Self::get). Detached from the kernel, so it inspects on any thread.
#[derive(Debug)]
pub struct TypeImage {
    types: TypeTable,
    root: TypeId,
}

impl TypeImage {
    /// The handle of the type this image was built for -- the named type, or the function
    /// prototype (a [`TypeKind::Function`]).
    #[inline]
    #[must_use]
    pub const fn root(&self) -> TypeId {
        self.root
    }

    /// The interned table backing every handle in this image. Its own arena, materialized on the
    /// kernel thread, so it resolves types on any thread.
    #[inline]
    #[must_use]
    pub const fn types(&self) -> &TypeTable {
        &self.types
    }

    /// Resolve any handle from this image to its type. Handles come from this image's own
    /// [`types`](Self::types) table, so this never panics on a handle taken from `self`.
    #[inline]
    #[must_use]
    pub fn get(&self, id: TypeId) -> &TypeData {
        self.types.get(id)
    }

    /// The [`root`](Self::root) type's shape -- a shortcut for `self.get(self.root()).kind`.
    #[inline]
    #[must_use]
    pub fn kind(&self) -> &TypeKind {
        &self.types.get(self.root).kind
    }

    /// The root type's size in bytes, or `None` for an incomplete/sizeless type.
    #[inline]
    #[must_use]
    pub fn size(&self) -> Option<u64> {
        self.types.get(self.root).size
    }

    /// The root's fields when it is a struct or union, in declaration order; `None` for any other
    /// shape. Each [`TypeMember::ty`] resolves against [`get`](Self::get).
    #[inline]
    #[must_use]
    pub fn members(&self) -> Option<&[TypeMember]> {
        match self.kind() {
            TypeKind::Struct { members, .. } | TypeKind::Union { members, .. } => Some(members),
            _ => None,
        }
    }
}

/// Accumulates a standalone type walk: the shared [`TypeBuilder`] the walker interns into.
struct TypeImageBuilder {
    types: TypeBuilder,
}

impl TypeSink for TypeImageBuilder {
    fn type_builder(&mut self) -> &mut TypeBuilder {
        &mut self.types
    }
}

/// Drive a standalone-type facade walk into a [`TypeImage`]. `run` invokes the chosen facade entry
/// (a named-type or function-prototype walk) with the shared type vtbl, its context, and the
/// root-handle out-param, returning the entry's rc. `Ok(None)` when the entry reports no such type
/// (non-zero rc); `Err` when the walked table is malformed. Callers map the [`ExtractError`] to
/// their own boundary (an address, a type name).
pub(crate) fn walk_type(
    run: impl FnOnce(*const sys::TypeVtbl, *mut c_void, *mut u32) -> c_int,
) -> core::result::Result<Option<TypeImage>, ExtractError> {
    let mut b = TypeImageBuilder {
        types: TypeBuilder::new(),
    };
    let vtbl = type_vtbl::<TypeImageBuilder>();
    let mut root = 0u32;
    let rc = run(&vtbl, (&mut b as *mut TypeImageBuilder).cast(), &mut root);
    if rc != 0 {
        return Ok(None);
    }
    // The builder is error-type-agnostic (see the ctree walk): surface an over-wide scalar or an
    // unfilled placeholder rather than shipping a malformed table.
    if let Some(bytes) = b.types.too_wide() {
        return Err(ExtractError::ScalarTooWide { bytes });
    }
    let unfilled = b.types.unfilled();
    if unfilled != 0 {
        return Err(ExtractError::UnfilledType { count: unfilled });
    }
    Ok(Some(TypeImage {
        root: tid(root),
        types: b.types.into_table(),
    }))
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    const fn assert_send<T: Send>() {}

    // A TypeImage must cross the kernel thread; a later non-Send field would fail this.
    const _: () = assert_send::<TypeImage>();

    fn u32_type(types: &mut TypeTable) -> TypeId {
        types.intern(TypeData {
            kind: TypeKind::Int {
                bytes: 4,
                signed: false,
            },
            size: Some(4),
        })
    }

    /// A struct root exposes its shape, size, and members, and member handles resolve against the
    /// same table.
    #[test]
    fn image_exposes_root_shape_and_members() {
        let mut types = TypeTable::new();
        let field = u32_type(&mut types);
        let root = types.intern(TypeData {
            kind: TypeKind::Struct {
                name: Some("pt".into()),
                members: vec![TypeMember {
                    name: "x".into(),
                    bit_offset: 0,
                    ty: field,
                    bitfield_width: None,
                }],
            },
            size: Some(4),
        });
        let img = TypeImage { types, root };

        assert!(img.root() == root);
        assert!(img.size() == Some(4));
        assert!(let TypeKind::Struct { .. } = img.kind());
        let members = img.members().expect("a struct has members");
        assert!(members.len() == 1);
        assert!(
            img.get(members[0].ty).kind
                == TypeKind::Int {
                    bytes: 4,
                    signed: false,
                }
        );
    }

    /// A non-aggregate root has no members.
    #[test]
    fn scalar_root_has_no_members() {
        let mut types = TypeTable::new();
        let root = u32_type(&mut types);
        let img = TypeImage { types, root };
        assert!(img.members().is_none());
    }
}
