//! Structured types: a third interned arena alongside the node arenas.
//!
//! Every expression carries a [`TypeId`] into a [`TypeTable`]. Types are interned, so
//! identical types share one handle, and recursion (a struct pointing at itself) is
//! represented by a [`TypeId`] back-reference -- a named aggregate reserves its handle
//! via [`alloc_placeholder`](TypeTable::alloc_placeholder) before its body is filled, so
//! a member can point back at it -- rather than by nesting. The table stays flat, finite,
//! and `Send`, so a materialized ctree carries its full type information off the kernel
//! thread.

use std::collections::HashMap;

use super::arena::{Arena, Idx};

/// Handle to a [`TypeData`] in a [`TypeTable`].
pub type TypeId = Idx<TypeData>;

/// A resolved type: its shape plus byte size when known.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TypeData {
    pub kind: TypeKind,
    /// Size in bytes, or `None` for an incomplete/sizeless type.
    pub size: Option<u64>,
}

/// One field of a struct or union.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TypeMember {
    pub name: String,
    /// Offset from the start of the aggregate, in bits.
    pub bit_offset: u64,
    pub ty: TypeId,
    /// Width in bits for a bitfield member; `None` for an ordinary field.
    pub bitfield_width: Option<u32>,
}

/// One member of an enum.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct EnumMember {
    pub name: String,
    pub value: u64,
}

/// The shape of a type. Child types are [`TypeId`] handles, so recursion and sharing
/// need no nesting.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum TypeKind {
    /// `void`
    Void,
    /// `bool`
    Bool,
    /// an integer of `bytes` width
    Int { bytes: u8, signed: bool },
    /// a floating-point type of `bytes` width
    Float { bytes: u8 },
    /// `T *`
    Ptr(TypeId),
    /// `T[len]`
    Array { elem: TypeId, len: u64 },
    /// a struct, with members in declaration order
    Struct {
        name: Option<String>,
        members: Vec<TypeMember>,
    },
    /// a union
    Union {
        name: Option<String>,
        members: Vec<TypeMember>,
    },
    /// an enum and its underlying integer type
    Enum {
        name: Option<String>,
        underlying: TypeId,
        members: Vec<EnumMember>,
    },
    /// a function prototype
    Func {
        ret: TypeId,
        params: Vec<TypeId>,
        varargs: bool,
    },
    /// a typedef to another type
    Typedef { name: String, underlying: TypeId },
    /// a type IDA could not describe, and the transient state of an aggregate placeholder
    /// before its body is filled (see [`TypeTable::alloc_placeholder`]).
    Unknown,
}

impl TypeKind {
    /// The type a pointer addresses, or `None` for a non-pointer. A structural accessor --
    /// the pointer analogue of reading a struct's members -- so callers needn't re-match
    /// the [`Ptr`](TypeKind::Ptr) variant by hand.
    #[inline]
    #[must_use]
    pub fn pointee(&self) -> Option<TypeId> {
        match self {
            TypeKind::Ptr(elem) => Some(*elem),
            _ => None,
        }
    }
}

/// An interned arena of [`TypeData`]: structurally identical types collapse to one
/// [`TypeId`].
#[derive(Debug)]
pub struct TypeTable {
    arena: Arena<TypeData>,
    dedup: HashMap<TypeData, TypeId>,
}

impl TypeTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            arena: Arena::new(),
            dedup: HashMap::new(),
        }
    }

    /// Intern a type, returning a shared handle. Types with identical kind, size, and
    /// child handles collapse to a single entry.
    pub fn intern(&mut self, data: TypeData) -> TypeId {
        if let Some(&id) = self.dedup.get(&data) {
            return id;
        }
        let id = self.arena.alloc(data.clone());
        self.dedup.insert(data, id);
        id
    }

    /// Reserve a handle for a not-yet-known type, returning a placeholder ([`Unknown`]).
    /// This breaks recursion: a recursive member can reference the aggregate's handle
    /// before [`fill`](Self::fill) supplies its body. Not deduplicated.
    ///
    /// [`Unknown`]: TypeKind::Unknown
    pub fn alloc_placeholder(&mut self) -> TypeId {
        self.arena.alloc(TypeData {
            kind: TypeKind::Unknown,
            size: None,
        })
    }

    /// Supply the body of a handle from [`alloc_placeholder`](Self::alloc_placeholder).
    pub fn fill(&mut self, id: TypeId, data: TypeData) {
        self.arena[id] = data;
    }

    /// The type behind a handle.
    #[inline]
    #[must_use]
    pub fn get(&self, id: TypeId) -> &TypeData {
        &self.arena[id]
    }

    /// Iterate every `(handle, type)` in interning order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (TypeId, &TypeData)> {
        self.arena.iter()
    }

    /// Number of distinct interned types.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.arena.len()
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.arena.is_empty()
    }
}

impl Default for TypeTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    fn int(bytes: u8, signed: bool) -> TypeData {
        TypeData {
            kind: TypeKind::Int { bytes, signed },
            size: Some(u64::from(bytes)),
        }
    }

    #[test]
    fn intern_dedups_identical_types() {
        let mut table = TypeTable::new();
        let a = table.intern(int(4, true));
        let b = table.intern(int(4, true));
        assert!(a == b);
        assert!(table.len() == 1);
    }

    #[test]
    fn intern_distinguishes_different_types() {
        let mut table = TypeTable::new();
        let i = table.intern(int(4, true));
        let u = table.intern(int(4, false));
        assert!(i != u);
        assert!(table.len() == 2);
    }

    #[test]
    fn recursive_struct_uses_a_placeholder_back_reference() {
        // struct node { struct node *next; } -- reserve the struct's handle first, so the
        // member pointer can target it before the body is filled. The table stays finite.
        let mut table = TypeTable::new();
        let node = table.alloc_placeholder();
        let ptr = table.intern(TypeData {
            kind: TypeKind::Ptr(node),
            size: Some(8),
        });
        table.fill(
            node,
            TypeData {
                kind: TypeKind::Struct {
                    name: Some("node".into()),
                    members: vec![TypeMember {
                        name: "next".into(),
                        bit_offset: 0,
                        ty: ptr,
                        bitfield_width: None,
                    }],
                },
                size: Some(8),
            },
        );

        assert!(let TypeKind::Struct { members, .. } = &table.get(node).kind);
        // the member pointer resolves back to the struct itself
        assert!(table.get(members[0].ty).kind == TypeKind::Ptr(node));
    }

    /// `pointee` unwraps a pointer's element type and is `None` for everything else.
    #[test]
    fn pointee_unwraps_only_pointers() {
        let mut table = TypeTable::new();
        let elem = table.intern(int(4, true));
        let ptr = table.intern(TypeData {
            kind: TypeKind::Ptr(elem),
            size: Some(8),
        });
        assert!(table.get(ptr).kind.pointee() == Some(elem));
        assert!(let None = table.get(elem).kind.pointee());
        assert!(let None = TypeKind::Void.pointee());
    }

    #[test]
    fn type_table_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TypeTable>();
    }
}
