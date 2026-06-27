//! Structured types: a third interned arena alongside the node arenas.
//!
//! Every expression carries a [`TypeId`] into a [`TypeTable`]. Types are interned, so
//! identical types share one handle, and recursion (a struct pointing at itself) is
//! represented by a [`TypeId`] back-reference — through a [`TypeKind::Named`] cycle
//! breaker — rather than by nesting. The table stays flat, finite, and `Send`, so a
//! materialized ctree carries its full type information off the kernel thread.

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
    /// Byte offset from the start of the aggregate.
    pub offset: u64,
    pub ty: TypeId,
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
    /// a named type not (yet) resolved — forward declarations and the cycle breaker
    /// for recursive types.
    Named(String),
    /// a type IDA could not describe
    Unknown,
}

/// An interned arena of [`TypeData`]: structurally identical types collapse to one
/// [`TypeId`].
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
    use super::*;

    fn int(bytes: u8, signed: bool) -> TypeData {
        TypeData {
            kind: TypeKind::Int { bytes, signed },
            size: Some(bytes as u64),
        }
    }

    #[test]
    fn intern_dedups_identical_types() {
        let mut table = TypeTable::new();
        let a = table.intern(int(4, true));
        let b = table.intern(int(4, true));
        assert_eq!(a, b);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn intern_distinguishes_different_types() {
        let mut table = TypeTable::new();
        let i = table.intern(int(4, true));
        let u = table.intern(int(4, false));
        assert_ne!(i, u);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn recursive_struct_uses_a_named_back_reference() {
        // struct node { struct node *next; } — the pointer targets a Named cycle
        // breaker, so the table stays finite.
        let mut table = TypeTable::new();
        let named = table.intern(TypeData {
            kind: TypeKind::Named("node".into()),
            size: None,
        });
        let ptr = table.intern(TypeData {
            kind: TypeKind::Ptr(named),
            size: Some(8),
        });
        let node = table.intern(TypeData {
            kind: TypeKind::Struct {
                name: Some("node".into()),
                members: vec![TypeMember {
                    name: "next".into(),
                    offset: 0,
                    ty: ptr,
                }],
            },
            size: Some(8),
        });

        let TypeKind::Struct { members, .. } = &table.get(node).kind else {
            panic!("expected a struct");
        };
        assert_eq!(table.get(members[0].ty).kind, TypeKind::Ptr(named));
    }

    #[test]
    fn type_table_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TypeTable>();
    }
}
