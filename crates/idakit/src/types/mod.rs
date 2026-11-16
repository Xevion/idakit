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

use serde::{Deserialize, Serialize};

use crate::arena::{Arena, Idx};
use crate::function::CallingConvention;

pub(crate) mod attributes;
mod builder;
pub mod diff;
mod edit;
mod encoding;
pub mod expr;
mod location;
mod named;
mod prototype;
mod repr;
mod resolved;
mod sink;
mod tinfo;

pub use attributes::{
    Comment, CommentKind, EnumAttributes, EnumGroup, MemberAttributes, PointerAttributes,
    PointerModifier, Qualifiers, ShiftedPointer, Signedness, StructAttributes, StructLayout,
};
pub(crate) use builder::TypeBuilder;
pub use edit::{
    ConstantEdit, MemberEdit, MemberRef, TypeEdit, TypeEditCode, TypeWriteError, TypesMut,
};
pub use expr::TypeExpr;
pub use location::{StorageLocation, StoragePiece};
pub use named::{NamedType, NamedTypes};
pub use prototype::{CallType, FunctionTypeFlags, Parameter, ParameterFlags, SpoiledRegister};
pub use repr::{NumberFormat, ValueRepr};
pub use resolved::Type;
pub(crate) use resolved::walk_type;
pub(crate) use sink::{SinkAdapter, TypeSink, raw, tid};
pub use tinfo::TypeInfo;

/// A typed handle into a [`TypeTable`].
pub type TypeId = Idx<TypeValue>;

/// A resolved type, pairing its shape with a byte size when known.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct TypeValue {
    /// The type's shape.
    pub shape: TypeShape,
    /// Size in bytes, or `None` for an incomplete/sizeless type.
    pub size: Option<u64>,
}

/// One field of a struct or union.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
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
    /// The field's comment and its kind; `None` when it has none.
    pub comment: Option<Comment>,
    /// The field's raw attributes: base class, vtable pointer, synthesized gap, and the rest.
    #[serde(with = "attributes::member_bits")]
    #[doc(alias("tafld_bits"))]
    pub attributes: MemberAttributes,
}

/// One member of an enum.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[doc(alias("edm_t"))]
pub struct EnumMember {
    /// The constant's name.
    pub name: String,
    /// The constant's integer value.
    pub value: u64,
    /// The constant's comment, or `None` when it has none. Enum constants only carry repeatable
    /// comments, so there is no kind to report.
    #[doc(alias("edm_t::cmt"))]
    pub comment: Option<String>,
}

/// The shape of a type. Child types are [`TypeId`] handles, so recursion and sharing
/// need no nesting.
///
/// A closed set. A named type with no structural body becomes [`Opaque`](TypeShape::Opaque)
/// rather than a catch-all, and [`Unknown`](TypeShape::Unknown) is only the transient
/// build-time placeholder. A new shape in a later IDA is a deliberate, breaking addition.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
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
    #[doc(alias("is_ptr", "get_pointed_object", "get_ptr_details"))]
    Ptr {
        /// The pointed-to type.
        target: TypeId,
        /// The `__ptr32`/`__ptr64`/`__restrict` modifier, or `None` for a plain pointer.
        modifier: Option<PointerModifier>,
        /// The parent struct and delta of a `__shifted` pointer, or `None` for an ordinary one.
        shifted: Option<ShiftedPointer>,
        /// The raw attribute word `modifier` and `shifted` are read from.
        #[serde(with = "attributes::pointer_bits")]
        attributes: PointerAttributes,
    },
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
        /// The struct's raw attributes: C++ object, vtable, `ms_struct`, and the rest.
        #[serde(with = "attributes::struct_bits")]
        attributes: StructAttributes,
        /// Padding, alignment, and packing.
        layout: StructLayout,
    },
    /// a union
    #[doc(alias("is_udt"))]
    Union {
        /// The tag name, or `None` if anonymous.
        name: Option<String>,
        /// Fields in declaration order.
        members: Vec<TypeMember>,
        /// The union's raw attributes.
        #[serde(with = "attributes::struct_bits")]
        attributes: StructAttributes,
        /// Padding, alignment, and packing.
        layout: StructLayout,
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
        /// The enum's declared storage signedness, or `None` when it declares neither.
        signedness: Option<Signedness>,
        /// A bitmask enum's groups over [`members`](Self::Enum::members), or `None` for a plain
        /// enum (or a bitmask the SDK reports no groups for).
        groups: Option<Vec<EnumGroup>>,
        /// The raw attribute word `signedness` and the display bits behind `repr` are read from.
        #[serde(with = "attributes::enum_bits")]
        #[doc(alias("taenum_bits"))]
        attributes: EnumAttributes,
    },
    /// a function prototype
    #[doc(alias("is_func", "get_func_details", "func_type_data_t"))]
    Function {
        /// Return type.
        #[doc(alias("rettype"))]
        ret: TypeId,
        /// The parameters, in order, hidden ones included (see [`Parameter::is_hidden`]).
        params: Vec<Parameter>,
        /// The calling convention, or `None` when the SDK reports none (`CM_CC_INVALID`).
        #[doc(alias("get_cc"))]
        calling_convention: Option<CallingConvention>,
        /// The prototype's flags, without the call-type field (read into `call_type`).
        #[serde(with = "attributes::function_bits")]
        flags: FunctionTypeFlags,
        /// How the function is called.
        call_type: CallType,
        /// Where the return value lives, or [`Unallocated`](StorageLocation::Unallocated) when
        /// locations were not computed.
        #[doc(alias("retloc"))]
        return_location: StorageLocation,
        /// Size in bytes of the stack arguments, 0 when locations were not computed.
        #[doc(alias("stkargs"))]
        stack_argument_size: u64,
        /// The registers the function spoils, when it declares them (see
        /// [`FunctionTypeFlags::SPOILED`]).
        spoiled: Vec<SpoiledRegister>,
    },
    /// a `const` and/or `volatile` qualification of another type
    #[doc(alias("get_modifiers", "is_decl_const", "is_decl_volatile"))]
    Qualified {
        /// The unqualified type.
        inner: TypeId,
        /// The qualifiers, never empty.
        #[serde(with = "attributes::qualifier_bits")]
        qualifiers: Qualifiers,
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
    /// A plain pointer to `target`, with no modifier, shift, or attribute bits.
    #[inline]
    #[must_use]
    pub const fn pointer(target: TypeId) -> Self {
        Self::Ptr {
            target,
            modifier: None,
            shifted: None,
            attributes: PointerAttributes::empty(),
        }
    }

    /// A bare prototype for tests: unnamed parameters, `__cdecl` (`__ellipsis` when variadic), and
    /// no computed locations.
    #[cfg(test)]
    pub(crate) fn test_function(ret: TypeId, params: Vec<TypeId>, variadic: bool) -> Self {
        Self::Function {
            ret,
            params: params
                .into_iter()
                .map(|ty| Parameter {
                    name: None,
                    ty,
                    comment: None,
                    location: StorageLocation::Unallocated,
                    flags: ParameterFlags::empty(),
                })
                .collect(),
            calling_convention: Some(if variadic {
                CallingConvention::Ellipsis { variation: 0 }
            } else {
                CallingConvention::Cdecl
            }),
            flags: FunctionTypeFlags::empty(),
            call_type: CallType::Default,
            return_location: StorageLocation::Unallocated,
            stack_argument_size: 0,
            spoiled: Vec::new(),
        }
    }

    /// Whether this is a variadic function prototype, which its calling convention decides.
    #[inline]
    #[must_use]
    #[doc(alias("is_vararg_cc"))]
    pub fn is_variadic(&self) -> bool {
        matches!(
            self,
            Self::Function { calling_convention: Some(cc), .. } if cc.is_vararg()
        )
    }

    /// The type a pointer addresses, or `None` for a non-pointer.
    ///
    /// A structural accessor (the pointer analogue of reading a struct's members), so callers
    /// needn't re-match the [`Ptr`](TypeShape::Ptr) variant by hand.
    #[inline]
    #[must_use]
    pub fn pointee(&self) -> Option<TypeId> {
        match self {
            Self::Ptr { target, .. } => Some(*target),
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
///
/// `PartialEq`/`Eq` are raw structural equality (arena order and intern-cache state included,
/// since [`alloc_placeholder`](Self::alloc_placeholder) bypasses `dedup`), not canonical "same
/// types" comparison; use [`Type::key`]/[`Type::canonical`] to compare across tables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[doc(alias("tinfo_t"))]
pub struct TypeTable {
    arena: Arena<TypeValue>,
    #[serde(with = "dedup_as_pairs")]
    dedup: HashMap<TypeValue, TypeId>,
}

/// (De)serializes [`TypeTable::dedup`] as a pair list rather than a native map: `TypeValue` is a
/// struct key, and formats such as JSON require string map keys.
mod dedup_as_pairs {
    use std::collections::HashMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{TypeId, TypeValue};

    pub(super) fn serialize<S: Serializer>(
        map: &HashMap<TypeValue, TypeId>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        map.iter().collect::<Vec<_>>().serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<HashMap<TypeValue, TypeId>, D::Error> {
        Ok(Vec::<(TypeValue, TypeId)>::deserialize(deserializer)?
            .into_iter()
            .collect())
    }
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
    fn is_empty_tracks_whether_a_type_is_interned() {
        let mut table = TypeTable::new();
        assert!(table.is_empty());
        table.intern(int(4, true));
        assert!(!table.is_empty());
    }

    #[test]
    fn recursive_struct_uses_a_placeholder_back_reference() {
        // struct node { struct node *next; }: reserve the struct's handle first, so the
        // member pointer can target it before the body is filled. The table stays finite.
        let mut table = TypeTable::new();
        let node = table.alloc_placeholder();
        let ptr = table.intern(TypeValue {
            shape: TypeShape::pointer(node),
            size: Some(8),
        });
        table.fill(
            node,
            TypeValue {
                shape: TypeShape::Struct {
                    attributes: StructAttributes::empty(),
                    layout: StructLayout::default(),
                    name: Some("node".into()),
                    members: vec![TypeMember {
                        comment: None,
                        attributes: MemberAttributes::empty(),
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
        assert!(table.get(members[0].ty).shape == TypeShape::pointer(node));
    }

    /// `pointee` unwraps a pointer's element type and is `None` for everything else.
    #[test]
    fn pointee_unwraps_only_pointers() {
        let mut table = TypeTable::new();
        let elem = table.intern(int(4, true));
        let ptr = table.intern(TypeValue {
            shape: TypeShape::pointer(elem),
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
            attributes: StructAttributes::empty(),
            layout: StructLayout::default(),
            name: Some("pt".into()),
            members: vec![],
        };
        assert!(named.tag_name() == Some("pt"));
        let anon = TypeShape::Struct {
            attributes: StructAttributes::empty(),
            layout: StructLayout::default(),
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

    /// A populated table (struct with a member, matching the recursive-struct fixture) clones
    /// to an equal, independent copy.
    #[test]
    fn type_table_clone_is_equal() {
        let mut table = TypeTable::new();
        let field = table.intern(int(4, true));
        table.intern(TypeValue {
            shape: TypeShape::Struct {
                attributes: StructAttributes::empty(),
                layout: StructLayout::default(),
                name: Some("pt".into()),
                members: vec![TypeMember {
                    comment: None,
                    attributes: MemberAttributes::empty(),
                    name: "x".into(),
                    bit_offset: 0,
                    ty: field,
                    bitfield_width: None,
                    repr: None,
                }],
            },
            size: Some(4),
        });

        let cloned = table.clone();
        assert!(cloned == table);
        assert!(cloned.len() == table.len());
    }

    /// A `TypeTable` with a struct-and-member survives a JSON round trip intact, exercising the
    /// [`Serialize`]/[`Deserialize`] chain through [`TypeValue`], [`TypeShape`], and
    /// [`TypeMember`].
    #[test]
    fn type_table_serde_round_trip() {
        let mut table = TypeTable::new();
        let field = table.intern(int(4, true));
        table.intern(TypeValue {
            shape: TypeShape::Struct {
                attributes: StructAttributes::empty(),
                layout: StructLayout::default(),
                name: Some("pt".into()),
                members: vec![TypeMember {
                    comment: None,
                    attributes: MemberAttributes::empty(),
                    name: "x".into(),
                    bit_offset: 0,
                    ty: field,
                    bitfield_width: None,
                    repr: Some(ValueRepr {
                        format: NumberFormat::Hexadecimal,
                        signed: false,
                        leading_zeros: false,
                    }),
                }],
            },
            size: Some(4),
        });

        let json = serde_json::to_string(&table).unwrap();
        let round_tripped: TypeTable = serde_json::from_str(&json).unwrap();
        assert!(round_tripped == table);
    }

    /// An empty table (`dedup` included) also round trips, so the pair-list adapter handles the
    /// zero-entry edge case, not just a populated map.
    #[test]
    fn empty_type_table_serde_round_trip() {
        let table = TypeTable::new();

        let json = serde_json::to_string(&table).unwrap();
        let round_tripped: TypeTable = serde_json::from_str(&json).unwrap();
        assert!(round_tripped == table);
    }
}
