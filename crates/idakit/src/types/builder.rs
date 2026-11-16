//! Streams the facade's type callbacks into [`TypeBuilder`], accumulating an interned
//! [`TypeTable`].
//!
//! Receives the facade's type callbacks (scalar/ptr/array/func/named-ref/anon/fill-*) and
//! builds an interned [`TypeTable`], resolving recursion through a by-name placeholder: a
//! named aggregate reserves its handle ([`named_ref`](Self::named_ref)) before its body
//! arrives ([`fill_struct`](Self::fill_struct)), so a member can point back at it. It is
//! error-type-agnostic: it records raw failure signals ([`too_wide`](Self::too_wide),
//! [`unfilled`](Self::unfilled)) for the caller to map to its own error, so both the ctree
//! walk and (later) a bare standalone type walk can drive the same builder.

use std::collections::HashMap;

use super::{
    CallType, EnumAttributes, EnumGroup, EnumMember, FunctionTypeFlags, NumberFormat, Parameter,
    PointerAttributes, PointerModifier, Qualifiers, ShiftedPointer, Signedness, SpoiledRegister,
    StorageLocation, StructAttributes, StructLayout, TypeId, TypeMember, TypeShape, TypeTable,
    TypeValue, ValueRepr,
};
use crate::decompiler::ctree::ExtractError;
use crate::function::CallingConvention;

/// Scalar-kind tags the facade's `t_scalar` callback uses to pick a [`TypeShape`]. The walker
/// emits only these four (a non-structural type is routed to [`opaque`](TypeBuilder::opaque)
/// instead), so the catch-all is a defensive fallback it never triggers.
mod scalar_kind {
    pub const VOID: u32 = 1;
    pub const BOOL: u32 = 2;
    pub const INT: u32 = 3;
    pub const FLOAT: u32 = 4;
}

fn opt_size(size: u64, has_size: u32) -> Option<u64> {
    (has_size != 0).then_some(size)
}

/// Builds a [`TypeTable`] from the facade's type callbacks. Owns the interning table plus
/// the recursion bookkeeping (`name2type` for dedup, `pending` for unfilled placeholders).
#[derive(Debug)]
pub(crate) struct TypeBuilder {
    table: TypeTable,
    /// Named aggregate/typedef -> its interned handle (recursion + dedup).
    name2type: HashMap<Box<str>, TypeId>,
    /// Placeholder handle -> its name (`None` = anonymous), pending its body.
    pending: HashMap<TypeId, Option<Box<str>>>,
    /// First scalar whose byte width overflowed `u8`, if any.
    too_wide: Option<u32>,
    /// First raw calling convention that decoded to no [`CallingConvention`], if any.
    invalid_calling_convention: Option<u32>,
}

impl TypeBuilder {
    pub(crate) fn new() -> Self {
        Self {
            table: TypeTable::new(),
            name2type: HashMap::new(),
            pending: HashMap::new(),
            too_wide: None,
            invalid_calling_convention: None,
        }
    }

    pub(crate) fn intern(&mut self, data: TypeValue) -> TypeId {
        self.table.intern(data)
    }

    pub(crate) fn alloc_placeholder(&mut self) -> TypeId {
        self.table.alloc_placeholder()
    }

    pub(crate) fn fill(&mut self, id: TypeId, data: TypeValue) {
        self.table.fill(id, data);
    }

    pub(crate) fn type_size(&self, id: TypeId) -> Option<u64> {
        self.table.get(id).size
    }

    pub(crate) fn scalar(
        &mut self,
        kind: u32,
        bytes: u32,
        signed: u32,
        size: u64,
        has_size: u32,
    ) -> TypeId {
        let width = if let Ok(w) = u8::try_from(bytes) {
            w
        } else {
            self.too_wide.get_or_insert(bytes);
            0
        };
        let shape = match kind {
            scalar_kind::VOID => TypeShape::Void,
            scalar_kind::BOOL => TypeShape::Bool,
            scalar_kind::INT => TypeShape::Int {
                bytes: width,
                signed: signed != 0,
            },
            scalar_kind::FLOAT => TypeShape::Float { bytes: width },
            _ => TypeShape::Unknown,
        };
        self.intern(TypeValue {
            shape,
            size: opt_size(size, has_size),
        })
    }

    pub(crate) fn ptr(
        &mut self,
        target: TypeId,
        size: u64,
        has_size: u32,
        attributes: PointerAttributes,
        shifted: Option<ShiftedPointer>,
    ) -> TypeId {
        self.intern(TypeValue {
            shape: TypeShape::Ptr {
                target,
                modifier: PointerModifier::from_attributes(attributes),
                shifted,
                attributes,
            },
            size: opt_size(size, has_size),
        })
    }

    pub(crate) fn array(&mut self, elem: TypeId, nelems: u64, size: u64, has_size: u32) -> TypeId {
        self.intern(TypeValue {
            shape: TypeShape::Array { elem, len: nelems },
            size: opt_size(size, has_size),
        })
    }

    /// A function prototype. `cc` is the raw `callcnv_t`, where 0 (`CM_CC_INVALID`) means none
    /// and any other undecodable value is recorded as a failure; `flags` is the raw `FTI_*` word.
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the facade's flat func callback"
    )]
    pub(crate) fn function(
        &mut self,
        ret: TypeId,
        params: Vec<Parameter>,
        cc: u32,
        flags: u32,
        return_location: StorageLocation,
        stack_argument_size: u64,
        spoiled: Vec<SpoiledRegister>,
    ) -> TypeId {
        let calling_convention = match cc {
            0 => None,
            raw => CallingConvention::try_from(raw)
                .inspect_err(|_| {
                    self.invalid_calling_convention.get_or_insert(raw);
                })
                .ok(),
        };
        self.intern(TypeValue {
            shape: TypeShape::Function {
                ret,
                params,
                calling_convention,
                flags: FunctionTypeFlags::from_bits_retain(flags & !idakit_sys::CALL_TYPE_MASK),
                call_type: CallType::from_flags(flags),
                return_location,
                stack_argument_size,
                spoiled,
            },
            size: None,
        })
    }

    /// A `const`/`volatile` qualification of `inner`, carrying the raw `type_t` modifier bits.
    pub(crate) fn qualified(
        &mut self,
        inner: TypeId,
        modifiers: u8,
        size: u64,
        has_size: u32,
    ) -> TypeId {
        self.intern(TypeValue {
            shape: TypeShape::Qualified {
                inner,
                qualifiers: Qualifiers::from_bits_retain(modifiers),
            },
            size: opt_size(size, has_size),
        })
    }

    /// A named type IDA can name but not describe here (a forward-decl/incomplete aggregate
    /// or unresolved reference): a bodyless, sizeless leaf carrying just the resolved name.
    pub(crate) fn opaque(&mut self, name: String) -> TypeId {
        self.intern(TypeValue {
            shape: TypeShape::Opaque(name),
            size: None,
        })
    }

    /// Reserve a named aggregate/typedef's handle, deduped by name so a second reference
    /// (and a recursive member) resolves to the same placeholder before its body is filled.
    pub(crate) fn named_ref(&mut self, name: String) -> TypeId {
        if let Some(&id) = self.name2type.get(name.as_str()) {
            return id;
        }
        let id = self.alloc_placeholder();
        let key: Box<str> = name.into_boxed_str();
        self.name2type.insert(key.clone(), id);
        self.pending.insert(id, Some(key));
        id
    }

    pub(crate) fn anon(&mut self) -> TypeId {
        let id = self.alloc_placeholder();
        self.pending.insert(id, None);
        id
    }

    fn take_name(&mut self, id: TypeId) -> Option<String> {
        self.pending.remove(&id).flatten().map(String::from)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the facade's flat fill_struct callback"
    )]
    pub(crate) fn fill_struct(
        &mut self,
        id: TypeId,
        is_union: bool,
        members: Vec<TypeMember>,
        size: u64,
        has_size: u32,
        attributes: StructAttributes,
        layout: StructLayout,
    ) {
        let name = self.take_name(id);
        let shape = if is_union {
            TypeShape::Union {
                name,
                members,
                attributes,
                layout,
            }
        } else {
            TypeShape::Struct {
                name,
                members,
                attributes,
                layout,
            }
        };
        self.fill(
            id,
            TypeValue {
                shape,
                size: opt_size(size, has_size),
            },
        );
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the facade's flat fill_enum callback"
    )]
    pub(crate) fn fill_enum(
        &mut self,
        id: TypeId,
        underlying: TypeId,
        members: Vec<EnumMember>,
        size: u64,
        has_size: u32,
        is_bitmask: bool,
        repr_vtype: u32,
        repr_signed: bool,
        repr_leading_zeros: bool,
        attributes: EnumAttributes,
        groups: Option<Vec<EnumGroup>>,
    ) {
        let name = self.take_name(id);
        let repr = NumberFormat::try_from(repr_vtype)
            .ok()
            .map(|format| ValueRepr {
                format,
                signed: repr_signed,
                leading_zeros: repr_leading_zeros,
            });
        self.fill(
            id,
            TypeValue {
                shape: TypeShape::Enum {
                    name,
                    underlying,
                    members,
                    is_bitmask,
                    repr,
                    signedness: Signedness::from_attributes(attributes),
                    groups,
                    attributes,
                },
                size: opt_size(size, has_size),
            },
        );
    }

    pub(crate) fn fill_typedef(&mut self, id: TypeId, underlying: TypeId) {
        let name = self.take_name(id).unwrap_or_default();
        // A typedef is a transparent alias, so it adopts its target's size.
        let size = self.type_size(underlying);
        self.fill(
            id,
            TypeValue {
                shape: TypeShape::Typedef { name, underlying },
                size,
            },
        );
    }

    /// The first value the walk could not represent, or `None` for a well-formed table: an
    /// over-wide scalar, an undecodable calling convention, or a placeholder never filled (it
    /// would stay [`TypeShape::Unknown`]).
    pub(crate) fn failure(&self) -> Option<ExtractError> {
        if let Some(bytes) = self.too_wide {
            return Some(ExtractError::ScalarTooWide { bytes });
        }
        if let Some(raw) = self.invalid_calling_convention {
            return Some(ExtractError::InvalidCallingConvention { raw });
        }
        let count = self.pending.len();
        (count != 0).then_some(ExtractError::UnfilledType { count })
    }

    /// Take the built table. Check [`failure`](Self::failure) first if a well-formed result
    /// matters.
    pub(crate) fn into_table(self) -> TypeTable {
        self.table
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    /// Each scalar-kind tag maps to its own [`TypeShape`], with an unknown tag falling to the
    /// defensive catch-all: deleting any arm would silently mislabel that kind as `Unknown`.
    #[test]
    fn scalar_kinds_map_to_their_shapes() {
        let mut b = TypeBuilder::new();
        let void = b.scalar(scalar_kind::VOID, 0, 0, 0, 0);
        let boolean = b.scalar(scalar_kind::BOOL, 1, 0, 0, 0);
        let int = b.scalar(scalar_kind::INT, 4, 1, 0, 0);
        let float = b.scalar(scalar_kind::FLOAT, 4, 0, 0, 0);
        let unknown = b.scalar(u32::MAX, 0, 0, 0, 0);
        let table = b.into_table();
        assert!(matches!(table.get(void).shape, TypeShape::Void));
        assert!(matches!(table.get(boolean).shape, TypeShape::Bool));
        assert!(matches!(
            table.get(int).shape,
            TypeShape::Int {
                bytes: 4,
                signed: true
            }
        ));
        assert!(matches!(
            table.get(float).shape,
            TypeShape::Float { bytes: 4 }
        ));
        assert!(matches!(table.get(unknown).shape, TypeShape::Unknown));
    }

    /// A scalar wider than a `u8` fails the walk with its byte count and stands a zero-width
    /// placeholder in its place.
    #[test]
    fn over_wide_scalar_is_recorded() {
        let mut b = TypeBuilder::new();
        let id = b.scalar(scalar_kind::INT, 300, 0, 0, 0);
        assert!(b.failure() == Some(ExtractError::ScalarTooWide { bytes: 300 }));
        assert!(matches!(
            b.into_table().get(id).shape,
            TypeShape::Int { bytes: 0, .. }
        ));
    }

    /// A reserved-but-unfilled placeholder fails the walk; an empty builder does not.
    #[test]
    fn a_reserved_placeholder_counts_as_unfilled() {
        let mut b = TypeBuilder::new();
        assert!(b.failure().is_none());
        b.anon();
        assert!(b.failure() == Some(ExtractError::UnfilledType { count: 1 }));
    }

    fn prototype(b: &mut TypeBuilder, cc: u32, flags: u32) -> TypeShape {
        let ret = b.scalar(scalar_kind::VOID, 0, 0, 0, 0);
        let id = b.function(
            ret,
            Vec::new(),
            cc,
            flags,
            StorageLocation::Unallocated,
            0,
            Vec::new(),
        );
        b.table.get(id).shape.clone()
    }

    /// `CM_CC_INVALID` reads as no convention, any other undecodable code fails the walk, and the
    /// call-type field is split out of the flags.
    #[test]
    fn function_decodes_its_calling_convention_and_flags() {
        let mut b = TypeBuilder::new();
        let shape = prototype(&mut b, 0, 0);
        assert!(let TypeShape::Function { calling_convention: None, .. } = shape);
        assert!(b.failure().is_none());

        let shape = prototype(&mut b, 0x40, 0x0142);
        assert!(shape.is_variadic());
        assert!(let TypeShape::Function { flags, call_type: CallType::Near, .. } = shape);
        assert!(flags == FunctionTypeFlags::NO_RETURN | FunctionTypeFlags::LOCATIONS);
        assert!(b.failure().is_none());

        prototype(&mut b, 0xA3, 0);
        assert!(b.failure() == Some(ExtractError::InvalidCallingConvention { raw: 0xA3 }));
    }
}
