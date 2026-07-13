//! Reads a database's types into [`TypeTable`], the interned arena every resolved [`Type`] shares,
//! and writes them through [`TypesMut`] and the [`TypeExpr`] builder.
//!
//! A resolved type is an owned, `Send` [`Type`] snapshot off the kernel thread, carried by the
//! decompiler [`Ctree`](crate::decompiler::ctree::Ctree), a function's
//! [`StackFrame`](crate::stack::StackFrame), or standalone. Every type it references lives in one
//! [`TypeTable`].
//!
//! A type is referenced by a [`TypeId`] into the table. Types are interned, so identical
//! types share one handle, and recursion (a struct pointing at itself) is a [`TypeId`]
//! back-reference. A named aggregate reserves its handle via
//! [`alloc_placeholder`](TypeTable::alloc_placeholder) before its body is filled, so a
//! member can point back at it, rather than by nesting. The table stays flat, finite, and
//! `Send`.

use std::collections::HashMap;

use crate::arena::{Arena, Idx};

mod builder;
pub mod diff;
mod edit;
pub mod expr;
mod named;
mod repr;
mod resolved;
mod sink;
mod tinfo;

pub(crate) use builder::TypeBuilder;
pub use edit::{
    ConstantEdit, MemberEdit, MemberRef, TypeEdit, TypeEditCode, TypeWriteError, TypesMut,
};
pub use expr::TypeExpr;
pub use named::{NamedType, NamedTypes};
pub use repr::{NumberFormat, ValueRepr};
pub use resolved::Type;
pub(crate) use resolved::walk_type;
pub(crate) use sink::{SinkAdapter, TypeSink, raw, tid};
pub use tinfo::TypeInfo;

/// A typed handle into a [`TypeTable`].
pub type TypeId = Idx<TypeValue>;

/// A resolved type, pairing its shape with a byte size when known.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TypeValue {
    /// The type's shape.
    pub shape: TypeShape,
    /// Size in bytes, or `None` for an incomplete/sizeless type.
    pub size: Option<u64>,
}

/// One field of a struct or union.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[doc(alias("udm_t"))]
pub struct TypeMember {
    /// The field's name; empty if IDA gave none.
    pub name: String,
    /// Offset from the start of the aggregate, in bits.
    pub bit_offset: u64,
    /// The field's type.
    pub ty: TypeId,
    /// Width in bits for a bitfield member; `None` for an ordinary field.
    pub bitfield_width: Option<u32>,
    /// The field's value representation (radix/char, sign, leading zeros); `None` when unset or
    /// outside the numeric subset [`ValueRepr`] models.
    pub repr: Option<ValueRepr>,
}

/// One member of an enum.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[doc(alias("edm_t"))]
pub struct EnumMember {
    /// The constant's name.
    pub name: String,
    /// The constant's integer value.
    pub value: u64,
}

/// The shape of a type. Child types are [`TypeId`] handles, so recursion and sharing
/// need no nesting.
///
/// A closed set. A named type with no structural body becomes [`Opaque`](TypeShape::Opaque)
/// rather than a catch-all, and [`Unknown`](TypeShape::Unknown) is only the transient
/// build-time placeholder. A new shape in a later IDA is a deliberate, breaking addition.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum TypeShape {
    /// `void`
    Void,
    /// `bool`
    Bool,
    /// an integer of `bytes` width
    Int {
        /// Width in bytes.
        bytes: u8,
        /// Whether it is signed.
        signed: bool,
    },
    /// a floating-point type of `bytes` width
    Float {
        /// Width in bytes.
        bytes: u8,
    },
    /// `T *`
    #[doc(alias("is_ptr", "get_pointed_object"))]
    Ptr(TypeId),
    /// `T[len]`
    #[doc(alias("is_array", "get_array_element"))]
    Array {
        /// The element type.
        elem: TypeId,
        /// Number of elements.
        len: u64,
    },
    /// a struct, with members in declaration order
    #[doc(alias("is_udt", "get_udt_details"))]
    Struct {
        /// The tag name, or `None` if anonymous.
        name: Option<String>,
        /// Fields in declaration order.
        members: Vec<TypeMember>,
    },
    /// a union
    #[doc(alias("is_udt"))]
    Union {
        /// The tag name, or `None` if anonymous.
        name: Option<String>,
        /// Fields in declaration order.
        members: Vec<TypeMember>,
    },
    /// an enum and its underlying integer type
    #[doc(alias("is_enum", "get_enum_details", "is_bitmask_enum", "get_enum_repr"))]
    Enum {
        /// The tag name, or `None` if anonymous.
        name: Option<String>,
        /// The underlying integer type.
        underlying: TypeId,
        /// The enumerated constants.
        members: Vec<EnumMember>,
        /// Whether this is a bitmask (flag) enum.
        is_bitmask: bool,
        /// The enum's value representation (radix/char, sign, leading zeros); `None` when unset
        /// or outside the numeric subset [`ValueRepr`] models.
        repr: Option<ValueRepr>,
    },
    /// a function prototype
    #[doc(alias("is_func", "get_func_details"))]
    Function {
        /// Return type.
        ret: TypeId,
        /// Parameter types, in order.
        params: Vec<TypeId>,
        /// Whether the prototype is variadic.
        varargs: bool,
    },
    /// a typedef to another type
    #[doc(alias("is_typedef"))]
    Typedef {
        /// The alias name.
        name: String,
        /// The aliased type.
        underlying: TypeId,
    },
    /// a named type IDA can name but not structurally describe here: a forward-declared or
    /// otherwise incomplete aggregate, or an unresolved reference. Carries the resolved
    /// name so the node still identifies what it points at, just without a body.
    Opaque(String),
    /// the transient state of an aggregate placeholder before its body is filled (see
    /// [`TypeTable::alloc_placeholder`]); a well-formed table never carries it, so a
    /// leftover `Unknown` means an unfilled placeholder the caller must reject.
    Unknown,
}

impl TypeShape {
    /// The type a pointer addresses, or `None` for a non-pointer.
    ///
    /// A structural accessor (the pointer analogue of reading a struct's members), so callers
    /// needn't re-match the [`Ptr`](TypeShape::Ptr) variant by hand.
    #[inline]
    #[must_use]
    pub fn pointee(&self) -> Option<TypeId> {
        match self {
            Self::Ptr(elem) => Some(*elem),
            _ => None,
        }
    }

    /// The tag of a named aggregate ([`Struct`](TypeShape::Struct)/[`Union`](TypeShape::Union)/
    /// [`Enum`](TypeShape::Enum), unless anonymous) or the alias of a
    /// [`Typedef`](TypeShape::Typedef); `None` for an anonymous or structural type.
    ///
    /// Borrows from `self`, so the caller clones only when it needs an owned name; e.g. feeding it
    /// back to [`Database::type_named`](crate::Database::type_named) takes the borrow directly.
    #[inline]
    #[must_use]
    pub fn tag_name(&self) -> Option<&str> {
        match self {
            Self::Struct { name, .. } | Self::Union { name, .. } | Self::Enum { name, .. } => {
                name.as_deref()
            }
            Self::Typedef { name, .. } => Some(name.as_str()),
            _ => None,
        }
    }
}

/// An interned arena of [`TypeValue`] that collapses structurally identical types to one
/// [`TypeId`].
#[derive(Debug)]
#[doc(alias("tinfo_t"))]
pub struct TypeTable {
    arena: Arena<TypeValue>,
    dedup: HashMap<TypeValue, TypeId>,
}

impl TypeTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            arena: Arena::new(),
            dedup: HashMap::new(),
        }
    }

    /// Intern a type, returning a shared handle. Types with identical shape, size, and
    /// child handles collapse to a single entry.
    pub fn intern(&mut self, data: TypeValue) -> TypeId {
        if let Some(&id) = self.dedup.get(&data) {
            return id;
        }
        let id = self.arena.alloc(data.clone());
        self.dedup.insert(data, id);
        id
    }

    /// Reserve a handle for a not-yet-known type, returning a placeholder ([`Unknown`]).
    /// This breaks recursion, letting a recursive member reference the aggregate's handle
    /// before [`fill`](Self::fill) supplies its body. Not deduplicated.
    ///
    /// [`Unknown`]: TypeShape::Unknown
    pub fn alloc_placeholder(&mut self) -> TypeId {
        self.arena.alloc(TypeValue {
            shape: TypeShape::Unknown,
            size: None,
        })
    }

    /// Supply the body of a handle from [`alloc_placeholder`](Self::alloc_placeholder).
    pub fn fill(&mut self, id: TypeId, data: TypeValue) {
        self.arena[id] = data;
    }

    /// The type behind a handle.
    #[inline]
    #[must_use]
    pub fn get(&self, id: TypeId) -> &TypeValue {
        &self.arena[id]
    }

    /// Iterate every `(handle, type)` in interning order.
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (TypeId, &TypeValue)> {
        self.arena.iter()
    }

    /// Number of distinct interned types.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.arena.len()
    }

    /// Whether the table has no types.
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

    fn int(bytes: u8, signed: bool) -> TypeValue {
        TypeValue {
            shape: TypeShape::Int { bytes, signed },
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
        // struct node { struct node *next; }: reserve the struct's handle first, so the
        // member pointer can target it before the body is filled. The table stays finite.
        let mut table = TypeTable::new();
        let node = table.alloc_placeholder();
        let ptr = table.intern(TypeValue {
            shape: TypeShape::Ptr(node),
            size: Some(8),
        });
        table.fill(
            node,
            TypeValue {
                shape: TypeShape::Struct {
                    name: Some("node".into()),
                    members: vec![TypeMember {
                        name: "next".into(),
                        bit_offset: 0,
                        ty: ptr,
                        bitfield_width: None,
                        repr: None,
                    }],
                },
                size: Some(8),
            },
        );

        assert!(let TypeShape::Struct { members, .. } = &table.get(node).shape);
        // the member pointer resolves back to the struct itself
        assert!(table.get(members[0].ty).shape == TypeShape::Ptr(node));
    }

    /// `pointee` unwraps a pointer's element type and is `None` for everything else.
    #[test]
    fn pointee_unwraps_only_pointers() {
        let mut table = TypeTable::new();
        let elem = table.intern(int(4, true));
        let ptr = table.intern(TypeValue {
            shape: TypeShape::Ptr(elem),
            size: Some(8),
        });
        assert!(table.get(ptr).shape.pointee() == Some(elem));
        assert!(let None = table.get(elem).shape.pointee());
        assert!(let None = TypeShape::Void.pointee());
    }

    /// `tag_name` yields a named aggregate's tag and a typedef's alias, and `None` for an
    /// anonymous or structural type.
    #[test]
    fn tag_name_reads_named_types_only() {
        let named = TypeShape::Struct {
            name: Some("pt".into()),
            members: vec![],
        };
        assert!(named.tag_name() == Some("pt"));
        let anon = TypeShape::Struct {
            name: None,
            members: vec![],
        };
        assert!(anon.tag_name().is_none());

        let underlying = TypeTable::new().alloc_placeholder();
        let alias = TypeShape::Typedef {
            name: "u32".into(),
            underlying,
        };
        assert!(alias.tag_name() == Some("u32"));

        let scalar = TypeShape::Int {
            bytes: 4,
            signed: true,
        };
        assert!(scalar.tag_name().is_none());
    }

    #[test]
    fn type_table_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TypeTable>();
    }
}
