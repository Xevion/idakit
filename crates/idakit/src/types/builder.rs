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

use super::{EnumMember, TypeId, TypeMember, TypeShape, TypeTable, TypeValue};

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
    /// First scalar whose byte width overflowed `u8`, if any; a caller-mapped failure.
    too_wide: Option<u32>,
}

impl TypeBuilder {
    pub(crate) fn new() -> Self {
        Self {
            table: TypeTable::new(),
            name2type: HashMap::new(),
            pending: HashMap::new(),
            too_wide: None,
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
        let width = match u8::try_from(bytes) {
            Ok(w) => w,
            Err(_) => {
                self.too_wide.get_or_insert(bytes);
                0
            }
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

    pub(crate) fn ptr(&mut self, target: TypeId, size: u64, has_size: u32) -> TypeId {
        self.intern(TypeValue {
            shape: TypeShape::Ptr(target),
            size: opt_size(size, has_size),
        })
    }

    pub(crate) fn array(&mut self, elem: TypeId, nelems: u64, size: u64, has_size: u32) -> TypeId {
        self.intern(TypeValue {
            shape: TypeShape::Array { elem, len: nelems },
            size: opt_size(size, has_size),
        })
    }

    pub(crate) fn function(&mut self, ret: TypeId, params: Vec<TypeId>, vararg: u32) -> TypeId {
        self.intern(TypeValue {
            shape: TypeShape::Function {
                ret,
                params,
                varargs: vararg != 0,
            },
            size: None,
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

    pub(crate) fn fill_struct(
        &mut self,
        id: TypeId,
        is_union: bool,
        members: Vec<TypeMember>,
        size: u64,
        has_size: u32,
    ) {
        let name = self.take_name(id);
        let shape = if is_union {
            TypeShape::Union { name, members }
        } else {
            TypeShape::Struct { name, members }
        };
        self.fill(
            id,
            TypeValue {
                shape,
                size: opt_size(size, has_size),
            },
        );
    }

    pub(crate) fn fill_enum(
        &mut self,
        id: TypeId,
        underlying: TypeId,
        members: Vec<EnumMember>,
        size: u64,
        has_size: u32,
    ) {
        let name = self.take_name(id);
        self.fill(
            id,
            TypeValue {
                shape: TypeShape::Enum {
                    name,
                    underlying,
                    members,
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

    /// The first over-wide scalar's byte count, if the walk emitted one: a placeholder stands in
    /// its place, and the caller turns this into its own error at finish.
    pub(crate) fn too_wide(&self) -> Option<u32> {
        self.too_wide
    }

    /// How many placeholders were referenced but never filled: a non-zero count means the
    /// table still carries a [`TypeShape::Unknown`] stand-in, which the caller rejects.
    pub(crate) fn unfilled(&self) -> usize {
        self.pending.len()
    }

    /// Take the built table. Check [`too_wide`](Self::too_wide)/[`unfilled`](Self::unfilled)
    /// first if a well-formed result matters.
    pub(crate) fn into_table(self) -> TypeTable {
        self.table
    }
}
