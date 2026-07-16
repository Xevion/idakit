//! Property tests over the diff engine and [`canonicalize`].
//!
//! Two generators feed them. [`canonical`] draws every declared [`CanonicalType`] shape, whether
//! or not a real walk could produce it, and suits the diff properties, which must hold over the
//! type as declared. [`table_and_root`] instead draws a [`TypeTable`] plus a root and runs the
//! real function, so its values are exact inhabitants of `canonicalize`'s image rather than
//! hand-guessed ones.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;

use assert2::assert;
use proptest::prelude::*;
use proptest::strategy::Union;
use proptest::test_runner::TestRunner;

use super::*;
use crate::types::{EnumMember, TypeId, TypeMember, TypeShape, TypeTable, TypeValue};

fn field_name() -> impl Strategy<Value = String> {
    prop_oneof![Just("a"), Just("b"), Just("c"), Just("d")].prop_map(str::to_owned)
}

fn const_name() -> impl Strategy<Value = String> {
    prop_oneof![Just("K0"), Just("K1"), Just("K2")].prop_map(str::to_owned)
}

fn tag_name() -> impl Strategy<Value = String> {
    prop_oneof![Just("T"), Just("U")].prop_map(str::to_owned)
}

fn opt_tag() -> impl Strategy<Value = Option<String>> {
    prop_oneof![Just(None), tag_name().prop_map(Some)]
}

fn opt_size() -> impl Strategy<Value = Option<u64>> {
    prop_oneof![Just(None), (0u64..64).prop_map(Some)]
}

fn opt_bitfield() -> impl Strategy<Value = Option<u32>> {
    prop_oneof![Just(None), (1u32..8).prop_map(Some)]
}

fn agg_kind() -> impl Strategy<Value = AggregateKind> {
    prop_oneof![
        Just(AggregateKind::Struct),
        Just(AggregateKind::Union),
        Just(AggregateKind::Enum),
    ]
}

fn record_kind() -> impl Strategy<Value = RecordKind> {
    prop_oneof![Just(RecordKind::Struct), Just(RecordKind::Union)]
}

/// Assemble members respecting the canonicalization invariants: distinct names, struct offsets
/// strictly increasing, union offsets all zero and name-sorted.
fn build_members(
    kind: RecordKind,
    raw: Vec<(String, Option<u32>, CanonicalType)>,
) -> Vec<CanonicalMember> {
    let mut seen = HashSet::new();
    let mut out: Vec<CanonicalMember> = Vec::new();
    for (name, bitfield_width, ty) in raw {
        if seen.insert(name.clone()) {
            let bit_offset = Some(if kind == RecordKind::Union {
                0
            } else {
                out.len() as u64 * 64
            });
            out.push(CanonicalMember {
                name,
                bit_offset,
                bitfield_width,
                ty,
            });
        }
    }
    if kind == RecordKind::Union {
        out.sort_by(|a, b| a.name.cmp(&b.name));
    }
    out
}

/// A member type for [`flat_member_raw`], never itself an aggregate, so a matched member's path
/// never grows a nested dot.
fn flat_member_ty() -> impl Strategy<Value = CanonicalType> {
    prop_oneof![
        Just(CanonicalType::Bool),
        (
            prop_oneof![Just(1u8), Just(2u8), Just(4u8), Just(8u8)],
            any::<bool>()
        )
            .prop_map(|(bytes, signed)| CanonicalType::Int {
                bytes: Some(bytes),
                signed
            }),
    ]
}

/// Raw members for [`build_members`], restricted to a single struct/union level so every matched
/// member's `Change::path` is its bare name.
fn flat_member_raw() -> impl Strategy<Value = Vec<(String, Option<u32>, CanonicalType)>> {
    prop::collection::vec((field_name(), opt_bitfield(), flat_member_ty()), 0..5)
}

fn constants() -> impl Strategy<Value = Vec<(String, u64)>> {
    prop::collection::vec((const_name(), any::<u64>()), 0..4).prop_map(|raw| {
        let mut seen = HashSet::new();
        let mut out: Vec<(String, u64)> = Vec::new();
        for (name, value) in raw {
            if seen.insert(name.clone()) {
                out.push((name, value));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    })
}

/// The recursive composition backing [`canonical`]: aggregates, pointers, arrays, enums,
/// typedefs, and functions built over a caller-supplied `leaf` strategy.
fn canonical_variant(
    leaf: impl Strategy<Value = CanonicalType> + 'static,
) -> impl Strategy<Value = CanonicalType> {
    leaf.prop_recursive(4, 40, 4, |inner| {
        let members = move |kind: RecordKind, inner: BoxedStrategy<CanonicalType>| {
            prop::collection::vec((field_name(), opt_bitfield(), inner), 0..4)
                .prop_map(move |raw| build_members(kind, raw))
        };
        let inner = inner.boxed();
        prop_oneof![
            (
                inner.clone(),
                prop_oneof![Just(None), Just(Some(4u8)), Just(Some(8u8))]
            )
                .prop_map(|(p, width)| CanonicalType::Ptr {
                    pointee: Box::new(p),
                    width
                }),
            (inner.clone(), 0u64..4).prop_map(|(e, len)| CanonicalType::Array {
                elem: Box::new(e),
                len
            }),
            (
                opt_tag(),
                members(RecordKind::Struct, inner.clone()),
                opt_size()
            )
                .prop_map(|(tag, members, size)| CanonicalType::Aggregate {
                    tag,
                    kind: RecordKind::Struct,
                    members,
                    size
                }),
            (
                opt_tag(),
                members(RecordKind::Union, inner.clone()),
                opt_size()
            )
                .prop_map(|(tag, members, size)| CanonicalType::Aggregate {
                    tag,
                    kind: RecordKind::Union,
                    members,
                    size
                }),
            (opt_tag(), inner.clone(), constants(), opt_size()).prop_map(
                |(tag, underlying, members, size)| CanonicalType::Enum {
                    tag,
                    underlying: Box::new(underlying),
                    members,
                    size
                }
            ),
            (tag_name(), inner.clone()).prop_map(|(name, u)| CanonicalType::Typedef {
                name,
                underlying: Box::new(u)
            }),
            (
                inner.clone(),
                prop::collection::vec(inner, 0..3),
                any::<bool>()
            )
                .prop_map(|(ret, params, varargs)| CanonicalType::Function {
                    ret: Box::new(ret),
                    params,
                    varargs
                }),
        ]
    })
}

/// A generator for invariant-respecting canonical types, bounded in depth.
fn canonical() -> impl Strategy<Value = CanonicalType> {
    let leaf = prop_oneof![
        Just(CanonicalType::Void),
        Just(CanonicalType::Bool),
        (
            prop_oneof![Just(1u8), Just(2u8), Just(4u8), Just(8u8)],
            any::<bool>()
        )
            .prop_map(|(bytes, signed)| CanonicalType::Int {
                bytes: Some(bytes),
                signed
            }),
        prop_oneof![Just(4u8), Just(8u8)].prop_map(|b| CanonicalType::Float { bytes: Some(b) }),
        (tag_name(), agg_kind()).prop_map(|(tag, kind)| CanonicalType::Named { tag, kind }),
        tag_name().prop_map(CanonicalType::Opaque),
        (1usize..4).prop_map(|n| CanonicalType::BackRef(NonZeroUsize::new(n).unwrap())),
    ];
    canonical_variant(leaf)
}

/// How a materialized struct, union, or enum is named.
///
/// [`canonicalize`] treats an empty or `$`-prefixed tag as synthetic, so
/// [`Synthetic`](Self::Synthetic) takes the same anonymous-cycle path as
/// [`Anonymous`](Self::Anonymous) while still carrying a name.
#[derive(Clone, Debug)]
enum TagPolicy {
    Anonymous,
    Synthetic(String),
    Real(String),
}

impl TagPolicy {
    fn name(&self) -> Option<String> {
        match self {
            Self::Anonymous => None,
            Self::Synthetic(tag) | Self::Real(tag) => Some(tag.clone()),
        }
    }
}

fn tag_policy() -> impl Strategy<Value = TagPolicy> {
    prop_oneof![
        Just(TagPolicy::Anonymous),
        tag_name().prop_map(|t| TagPolicy::Synthetic(format!("${t}"))),
        tag_name().prop_map(TagPolicy::Real),
    ]
}

/// An input-side type expression, the domain [`canonicalize`] is fuzzed over.
///
/// [`DeclRef`](Self::DeclRef) points into the sibling declaration pool ([`Declaration`]), so a
/// self- or mutually-recursive record arises the way a real one does, through a placeholder filled
/// after its members are built.
#[derive(Clone, Debug)]
enum TypeSpec {
    Void,
    Bool,
    Int {
        bytes: u8,
        signed: bool,
    },
    Float {
        bytes: u8,
    },
    Ptr {
        pointee: Box<Self>,
        width: u8,
    },
    Array {
        elem: Box<Self>,
        len: u64,
    },
    Enum {
        tag: TagPolicy,
        underlying_bytes: u8,
        underlying_signed: bool,
        members: Vec<(String, u64)>,
    },
    Function {
        ret: Box<Self>,
        params: Vec<Self>,
        varargs: bool,
    },
    Typedef {
        name: String,
        underlying: Box<Self>,
    },
    Opaque(String),
    /// A reference to declaration `n` in the enclosing pool, resolved to its already-allocated
    /// [`TypeId`] rather than expanded again, so generation terminates on a cyclic table.
    DeclRef(usize),
}

/// `(name, bit_offset, bitfield_width, type)`, one entry of a [`Declaration`]'s member list.
type RawMember = (String, u64, Option<u32>, TypeSpec);

/// A pre-allocated struct or union in the declaration pool.
///
/// Its placeholder is allocated before its members, so a [`TypeSpec::DeclRef`] anywhere in the
/// pool, including its own body, can close a cycle.
#[derive(Clone, Debug)]
struct Declaration {
    kind: RecordKind,
    tag: TagPolicy,
    /// Offsets already assigned by [`build_type_members`].
    members: Vec<RawMember>,
    size: Option<u64>,
}

/// Assigns bit offsets to a raw member list and drops duplicate names, the input-side analogue of
/// [`build_members`].
///
/// Struct offsets increase by 64 bits per field; union members all sit at 0.
fn build_type_members(
    kind: RecordKind,
    raw: Vec<(String, Option<u32>, TypeSpec)>,
) -> Vec<RawMember> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (name, bitfield_width, spec) in raw {
        if seen.insert(name.clone()) {
            let bit_offset = if kind == RecordKind::Union {
                0
            } else {
                out.len() as u64 * 64
            };
            out.push((name, bit_offset, bitfield_width, spec));
        }
    }
    out
}

/// A recursive [`TypeSpec`] generator, bounded in depth.
///
/// `decl_count` gates [`DeclRef`](TypeSpec::DeclRef) as a leaf, which is only valid when a
/// declaration pool of that size exists.
fn type_spec(decl_count: usize) -> BoxedStrategy<TypeSpec> {
    let mut leaves: Vec<BoxedStrategy<TypeSpec>> = vec![
        Just(TypeSpec::Void).boxed(),
        Just(TypeSpec::Bool).boxed(),
        (
            prop_oneof![Just(1u8), Just(2u8), Just(4u8), Just(8u8)],
            any::<bool>(),
        )
            .prop_map(|(bytes, signed)| TypeSpec::Int { bytes, signed })
            .boxed(),
        prop_oneof![Just(4u8), Just(8u8)]
            .prop_map(|bytes| TypeSpec::Float { bytes })
            .boxed(),
        tag_name().prop_map(TypeSpec::Opaque).boxed(),
        (
            tag_policy(),
            prop_oneof![Just(1u8), Just(4u8)],
            any::<bool>(),
            constants(),
        )
            .prop_map(
                |(tag, underlying_bytes, underlying_signed, members)| TypeSpec::Enum {
                    tag,
                    underlying_bytes,
                    underlying_signed,
                    members,
                },
            )
            .boxed(),
    ];
    if decl_count > 0 {
        leaves.push((0..decl_count).prop_map(TypeSpec::DeclRef).boxed());
    }
    Union::new(leaves)
        .prop_recursive(3, 20, 3, move |inner| {
            prop_oneof![
                (inner.clone(), prop_oneof![Just(4u8), Just(8u8)]).prop_map(|(p, width)| {
                    TypeSpec::Ptr {
                        pointee: Box::new(p),
                        width,
                    }
                }),
                (inner.clone(), 0u64..4).prop_map(|(elem, len)| TypeSpec::Array {
                    elem: Box::new(elem),
                    len
                }),
                (tag_name(), inner.clone()).prop_map(|(name, underlying)| TypeSpec::Typedef {
                    name,
                    underlying: Box::new(underlying)
                }),
                (
                    inner.clone(),
                    prop::collection::vec(inner, 0..3),
                    any::<bool>()
                )
                    .prop_map(|(ret, params, varargs)| TypeSpec::Function {
                        ret: Box::new(ret),
                        params,
                        varargs
                    }),
            ]
        })
        .boxed()
}

fn declaration(decl_count: usize) -> impl Strategy<Value = Declaration> {
    (
        record_kind(),
        tag_policy(),
        prop::collection::vec((field_name(), opt_bitfield(), type_spec(decl_count)), 0..4),
        opt_size(),
    )
        .prop_map(|(kind, tag, raw, size)| Declaration {
            kind,
            tag,
            members: build_type_members(kind, raw),
            size,
        })
}

/// A declaration pool plus a root expression over it, the shared input both [`table_and_root`]
/// and [`table_and_near_miss`] materialize into a [`TypeTable`].
fn declared_type() -> impl Strategy<Value = (Vec<Declaration>, TypeSpec)> {
    (0usize..=2).prop_flat_map(|decl_count| {
        (
            prop::collection::vec(declaration(decl_count), decl_count),
            type_spec(decl_count),
        )
    })
}

/// Allocates every declaration's placeholder up front, then fills each body, so a
/// [`TypeSpec::DeclRef`] anywhere in the pool resolves to a live handle.
fn materialize_declared(table: &mut TypeTable, decls: &[Declaration]) -> Vec<TypeId> {
    let ids: Vec<TypeId> = decls.iter().map(|_| table.alloc_placeholder()).collect();
    for (decl, &id) in decls.iter().zip(&ids) {
        let members = decl
            .members
            .iter()
            .map(|(name, bit_offset, bitfield_width, spec)| TypeMember {
                name: name.clone(),
                bit_offset: *bit_offset,
                ty: materialize_spec(spec, table, &ids),
                bitfield_width: *bitfield_width,
                repr: None,
            })
            .collect();
        let shape = match decl.kind {
            RecordKind::Struct => TypeShape::Struct {
                name: decl.tag.name(),
                members,
            },
            RecordKind::Union => TypeShape::Union {
                name: decl.tag.name(),
                members,
            },
        };
        table.fill(
            id,
            TypeValue {
                shape,
                size: decl.size,
            },
        );
    }
    ids
}

/// Materializes one [`TypeSpec`] into `table`, resolving [`DeclRef`](TypeSpec::DeclRef) against
/// `decl_ids` (already filled by [`materialize_declared`]).
fn materialize_spec(spec: &TypeSpec, table: &mut TypeTable, decl_ids: &[TypeId]) -> TypeId {
    match spec {
        TypeSpec::Void => table.intern(TypeValue {
            shape: TypeShape::Void,
            size: None,
        }),
        TypeSpec::Bool => table.intern(TypeValue {
            shape: TypeShape::Bool,
            size: Some(1),
        }),
        TypeSpec::Int { bytes, signed } => table.intern(TypeValue {
            shape: TypeShape::Int {
                bytes: *bytes,
                signed: *signed,
            },
            size: Some(u64::from(*bytes)),
        }),
        TypeSpec::Float { bytes } => table.intern(TypeValue {
            shape: TypeShape::Float { bytes: *bytes },
            size: Some(u64::from(*bytes)),
        }),
        TypeSpec::Ptr { pointee, width } => {
            let inner = materialize_spec(pointee, table, decl_ids);
            table.intern(TypeValue {
                shape: TypeShape::Ptr(inner),
                size: Some(u64::from(*width)),
            })
        }
        TypeSpec::Array { elem, len } => {
            let inner = materialize_spec(elem, table, decl_ids);
            table.intern(TypeValue {
                shape: TypeShape::Array {
                    elem: inner,
                    len: *len,
                },
                size: None,
            })
        }
        TypeSpec::Enum {
            tag,
            underlying_bytes,
            underlying_signed,
            members,
        } => {
            let underlying = table.intern(TypeValue {
                shape: TypeShape::Int {
                    bytes: *underlying_bytes,
                    signed: *underlying_signed,
                },
                size: Some(u64::from(*underlying_bytes)),
            });
            table.intern(TypeValue {
                shape: TypeShape::Enum {
                    name: tag.name(),
                    underlying,
                    members: members
                        .iter()
                        .map(|(name, value)| EnumMember {
                            name: name.clone(),
                            value: *value,
                        })
                        .collect(),
                    is_bitmask: false,
                    repr: None,
                },
                size: Some(u64::from(*underlying_bytes)),
            })
        }
        TypeSpec::Function {
            ret,
            params,
            varargs,
        } => {
            let ret = materialize_spec(ret, table, decl_ids);
            let params = params
                .iter()
                .map(|p| materialize_spec(p, table, decl_ids))
                .collect();
            table.intern(TypeValue {
                shape: TypeShape::Function {
                    ret,
                    params,
                    varargs: *varargs,
                },
                size: None,
            })
        }
        TypeSpec::Typedef { name, underlying } => {
            let underlying = materialize_spec(underlying, table, decl_ids);
            table.intern(TypeValue {
                shape: TypeShape::Typedef {
                    name: name.clone(),
                    underlying,
                },
                size: None,
            })
        }
        TypeSpec::Opaque(name) => table.intern(TypeValue {
            shape: TypeShape::Opaque(name.clone()),
            size: None,
        }),
        TypeSpec::DeclRef(index) => decl_ids[*index],
    }
}

/// Materializes a declaration pool and a root expression over it into a fresh table, returning the
/// root's handle.
fn build(table: &mut TypeTable, decls: &[Declaration], root: &TypeSpec) -> TypeId {
    let decl_ids = materialize_declared(table, decls);
    materialize_spec(root, table, &decl_ids)
}

/// A materialized `(table, root)`, the input [`canonicalize`] is fuzzed over.
fn table_and_root() -> impl Strategy<Value = (TypeTable, TypeId)> {
    declared_type().prop_map(|(decls, root)| {
        let mut table = TypeTable::new();
        let root_id = build(&mut table, &decls, &root);
        (table, root_id)
    })
}

/// Rebuilds a fresh, un-deduped [`TypeTable`] entry for a [`Named`](CanonicalType::Named) cut: an
/// empty-bodied stub of the right tag and kind, since a nominal cut is purely syntactic and
/// `canon` never re-reads what it points at once cut.
fn embed_canonical_named_stub(tag: &str, kind: AggregateKind, table: &mut TypeTable) -> TypeId {
    let shape = match kind {
        AggregateKind::Struct => TypeShape::Struct {
            name: Some(tag.to_owned()),
            members: Vec::new(),
        },
        AggregateKind::Union => TypeShape::Union {
            name: Some(tag.to_owned()),
            members: Vec::new(),
        },
        AggregateKind::Enum => {
            let underlying = table.intern(TypeValue {
                shape: TypeShape::Int {
                    bytes: 4,
                    signed: false,
                },
                size: Some(4),
            });
            TypeShape::Enum {
                name: Some(tag.to_owned()),
                underlying,
                members: Vec::new(),
                is_bitmask: false,
                repr: None,
            }
        }
    };
    table.intern(TypeValue { shape, size: None })
}

/// Rebuilds a fresh [`TypeTable`] entry from `c`, the reverse of `canon`'s own walk. `stack`
/// mirrors `canon`'s aggregate-frame stack, so a [`BackRef`](CanonicalType::BackRef) resolves to
/// the same enclosing frame's freshly allocated id.
///
/// Only ever fed real `canonicalize(..., CanonicalOptions::strict())` output, never the
/// arbitrarily-shaped [`canonical`] generator, so every width/offset/size is `Some` and every
/// `BackRef` is in range by construction. That is what lets this skip the filtering a generic
/// `CanonicalType -> TypeTable` inverse would need.
fn embed_canonical(c: &CanonicalType, table: &mut TypeTable, stack: &mut Vec<TypeId>) -> TypeId {
    match c {
        CanonicalType::Void => table.intern(TypeValue {
            shape: TypeShape::Void,
            size: None,
        }),
        CanonicalType::Bool => table.intern(TypeValue {
            shape: TypeShape::Bool,
            size: Some(1),
        }),
        CanonicalType::Int { bytes, signed } => {
            let bytes = bytes.expect("strict canonicalize output always sets Int::bytes");
            table.intern(TypeValue {
                shape: TypeShape::Int {
                    bytes,
                    signed: *signed,
                },
                size: Some(u64::from(bytes)),
            })
        }
        CanonicalType::Float { bytes } => {
            let bytes = bytes.expect("strict canonicalize output always sets Float::bytes");
            table.intern(TypeValue {
                shape: TypeShape::Float { bytes },
                size: Some(u64::from(bytes)),
            })
        }
        CanonicalType::Ptr { pointee, width } => {
            let inner = embed_canonical(pointee, table, stack);
            let width = width.expect("strict canonicalize output always sets Ptr::width");
            table.intern(TypeValue {
                shape: TypeShape::Ptr(inner),
                size: Some(u64::from(width)),
            })
        }
        CanonicalType::Array { elem, len } => {
            let inner = embed_canonical(elem, table, stack);
            table.intern(TypeValue {
                shape: TypeShape::Array {
                    elem: inner,
                    len: *len,
                },
                size: None,
            })
        }
        CanonicalType::Named { tag, kind } => embed_canonical_named_stub(tag, *kind, table),
        CanonicalType::Aggregate {
            tag,
            kind,
            members,
            size,
        } => {
            let id = table.alloc_placeholder();
            stack.push(id);
            let members = members
                .iter()
                .map(|m| TypeMember {
                    name: m.name.clone(),
                    bit_offset: m
                        .bit_offset
                        .expect("strict canonicalize output always sets member bit_offset"),
                    ty: embed_canonical(&m.ty, table, stack),
                    bitfield_width: m.bitfield_width,
                    repr: None,
                })
                .collect();
            stack.pop();
            let shape = match kind {
                RecordKind::Struct => TypeShape::Struct {
                    name: tag.clone(),
                    members,
                },
                RecordKind::Union => TypeShape::Union {
                    name: tag.clone(),
                    members,
                },
            };
            table.fill(id, TypeValue { shape, size: *size });
            id
        }
        CanonicalType::Enum {
            tag,
            underlying,
            members,
            size,
        } => {
            let underlying = embed_canonical(underlying, table, stack);
            table.intern(TypeValue {
                shape: TypeShape::Enum {
                    name: tag.clone(),
                    underlying,
                    members: members
                        .iter()
                        .map(|(name, value)| EnumMember {
                            name: name.clone(),
                            value: *value,
                        })
                        .collect(),
                    is_bitmask: false,
                    repr: None,
                },
                size: *size,
            })
        }
        CanonicalType::Function {
            ret,
            params,
            varargs,
        } => {
            let ret = embed_canonical(ret, table, stack);
            let params = params
                .iter()
                .map(|p| embed_canonical(p, table, stack))
                .collect();
            table.intern(TypeValue {
                shape: TypeShape::Function {
                    ret,
                    params,
                    varargs: *varargs,
                },
                size: None,
            })
        }
        CanonicalType::Typedef { name, underlying } => {
            let underlying = embed_canonical(underlying, table, stack);
            table.intern(TypeValue {
                shape: TypeShape::Typedef {
                    name: name.clone(),
                    underlying,
                },
                size: None,
            })
        }
        CanonicalType::Opaque(name) => table.intern(TypeValue {
            shape: TypeShape::Opaque(name.clone()),
            size: None,
        }),
        CanonicalType::BackRef(n) => stack[stack.len() - n.get()],
    }
}

/// Either keeps `original` or redraws it from `redraw`, weighted so most calls keep it.
///
/// Redrawing at every position would leave two mutated trees as unrelated as two independent
/// draws, which is what the near-miss generators exist to avoid.
fn maybe_redraw<T: Clone + std::fmt::Debug + 'static>(
    original: T,
    redraw_percent: u32,
    redraw: impl Strategy<Value = T> + 'static,
) -> BoxedStrategy<T> {
    prop_oneof![
        100 - redraw_percent => Just(original),
        redraw_percent => redraw,
    ]
    .boxed()
}

/// Combines a fixed collection of independent strategies into one strategy of the collected
/// values; proptest has no built-in combinator for a runtime-length `Vec` of strategies.
fn sequence<T: Clone + std::fmt::Debug + 'static>(
    strategies: Vec<BoxedStrategy<T>>,
) -> BoxedStrategy<Vec<T>> {
    strategies
        .into_iter()
        .fold(Just(Vec::new()).boxed(), |acc, s| {
            (acc, s)
                .prop_map(|(mut v, x)| {
                    v.push(x);
                    v
                })
                .boxed()
        })
}

/// A structurally-close variant of `spec`.
///
/// A `Ptr` mutates its pointee, so a mutation still reaches a [`DeclRef`](TypeSpec::DeclRef)
/// through indirection; a `DeclRef` itself never changes, since [`mutate_decls`] mutates its
/// declaration instead. Everything else is kept or redrawn wholesale with low probability.
fn mutate_type_spec(spec: TypeSpec, decl_count: usize) -> BoxedStrategy<TypeSpec> {
    match spec {
        TypeSpec::Ptr { pointee, width } => (
            mutate_type_spec(*pointee, decl_count),
            maybe_redraw(width, 20, prop_oneof![Just(4u8), Just(8u8)]),
        )
            .prop_map(|(pointee, width)| TypeSpec::Ptr {
                pointee: Box::new(pointee),
                width,
            })
            .boxed(),
        TypeSpec::DeclRef(index) => Just(TypeSpec::DeclRef(index)).boxed(),
        other => maybe_redraw(other, 25, type_spec(decl_count)),
    }
}

/// A structurally-close variant of one member: name, bitfield width, and type each independently
/// kept or redrawn. The offset stays fixed, since offset drift is [`mutate_members`]'s job.
fn mutate_member(member: RawMember, decl_count: usize) -> BoxedStrategy<RawMember> {
    let (name, bit_offset, bitfield_width, spec) = member;
    (
        maybe_redraw(name, 20, field_name()),
        Just(bit_offset),
        maybe_redraw(bitfield_width, 20, opt_bitfield()),
        mutate_type_spec(spec, decl_count),
    )
        .boxed()
}

/// A member list close to `members`: usually tweaked in place, so near-misses stay common,
/// occasionally relisted wholesale so an add or remove still gets exercised.
fn mutate_members(
    members: &[RawMember],
    kind: RecordKind,
    decl_count: usize,
) -> BoxedStrategy<Vec<RawMember>> {
    prop_oneof![
        7 => sequence(
            members
                .iter()
                .cloned()
                .map(|m| mutate_member(m, decl_count))
                .collect(),
        ),
        3 => prop::collection::vec((field_name(), opt_bitfield(), type_spec(decl_count)), 0..4)
            .prop_map(move |raw| build_type_members(kind, raw)),
    ]
    .boxed()
}

/// A structurally-close variant of one declaration: tag, size, and members each independently kept
/// or redrawn.
fn mutate_declaration(decl: Declaration, decl_count: usize) -> BoxedStrategy<Declaration> {
    let Declaration {
        kind,
        tag,
        members,
        size,
    } = decl;
    (
        maybe_redraw(tag, 15, tag_policy()),
        maybe_redraw(size, 15, opt_size()),
        mutate_members(&members, kind, decl_count),
    )
        .prop_map(move |(tag, size, members)| Declaration {
            kind,
            tag,
            members,
            size,
        })
        .boxed()
}

/// Mutates every declaration, keeping the pool's length fixed so every [`TypeSpec::DeclRef`] drawn
/// against it stays a valid index into the mutated pool.
fn mutate_decls(decls: Vec<Declaration>, decl_count: usize) -> BoxedStrategy<Vec<Declaration>> {
    sequence(
        decls
            .into_iter()
            .map(|d| mutate_declaration(d, decl_count))
            .collect(),
    )
}

/// A materialized `(table, root)` alongside a structurally-close variant, built by perturbing one
/// declaration pool and root expression.
///
/// Two independently drawn trees are almost always unrelated, which exercises only the diff
/// engine's add/remove fallback and barely its pairing logic (renames, moves, retypes).
fn table_and_near_miss() -> impl Strategy<Value = ((TypeTable, TypeId), (TypeTable, TypeId))> {
    declared_type().prop_flat_map(|(decls, root)| {
        let decl_count = decls.len();
        let decls_a = decls.clone();
        let root_a = root.clone();
        (
            mutate_decls(decls, decl_count),
            mutate_type_spec(root, decl_count),
        )
            .prop_map(move |(decls_b, root_b)| {
                let mut a = TypeTable::new();
                let root_id_a = build(&mut a, &decls_a, &root_a);
                let mut b = TypeTable::new();
                let root_id_b = build(&mut b, &decls_b, &root_b);
                ((a, root_id_a), (b, root_id_b))
            })
    })
}

/// Asserts every [`BackRef`](CanonicalType::BackRef) in `c` is within `open`, the number of
/// spelled-aggregate frames enclosing it, the de Bruijn well-scopedness a recursive aggregate
/// needs to close its own cycle.
///
/// `hits` tallies every `BackRef` visited, so a caller can tell a run that reached one from a run
/// that vacuously found none.
fn assert_backrefs_well_scoped(c: &CanonicalType, open: usize, hits: &Cell<usize>) {
    match c {
        CanonicalType::BackRef(n) => {
            assert!(n.get() >= 1 && n.get() <= open);
            hits.set(hits.get() + 1);
        }
        CanonicalType::Ptr { pointee, .. } => assert_backrefs_well_scoped(pointee, open, hits),
        CanonicalType::Array { elem, .. } => assert_backrefs_well_scoped(elem, open, hits),
        CanonicalType::Aggregate { members, .. } => {
            for m in members {
                assert_backrefs_well_scoped(&m.ty, open + 1, hits);
            }
        }
        CanonicalType::Enum { underlying, .. } | CanonicalType::Typedef { underlying, .. } => {
            assert_backrefs_well_scoped(underlying, open, hits);
        }
        CanonicalType::Function { ret, params, .. } => {
            assert_backrefs_well_scoped(ret, open, hits);
            for p in params {
                assert_backrefs_well_scoped(p, open, hits);
            }
        }
        CanonicalType::Void
        | CanonicalType::Bool
        | CanonicalType::Int { .. }
        | CanonicalType::Float { .. }
        | CanonicalType::Named { .. }
        | CanonicalType::Opaque(_) => {}
    }
}

/// Every renamed pair's current path mapped to its prior name, read off `forward`'s
/// [`Renamed`](ChangeKind::Renamed) entries.
///
/// A matched pair's retype, bitfield, or move change shares that current path, so this map
/// relocates them all to `forward`'s mirror.
fn rename_map(forward: &[Change]) -> HashMap<String, String> {
    forward
        .iter()
        .filter_map(|c| match &c.kind {
            ChangeKind::Renamed(from) => Some((c.path.clone(), from.clone())),
            _ => None,
        })
        .collect()
}

/// The `Change` [`assert_are_structural_mirrors`] expects in the backward diff for one forward
/// entry.
///
/// An add/remove swaps kind at the same path; a retype/bitfield/move on a matched pair swaps its
/// before/after and relocates to the pair's prior path via `rename_from`; a rename swaps
/// `(path, from)`.
fn mirror_change(change: &Change, rename_from: &HashMap<String, String>) -> Change {
    let mirrored_path = |p: &str| rename_from.get(p).cloned().unwrap_or_else(|| p.to_owned());
    let (path, kind) = match &change.kind {
        ChangeKind::Added(t) => (change.path.clone(), ChangeKind::Removed(t.clone())),
        ChangeKind::Removed(t) => (change.path.clone(), ChangeKind::Added(t.clone())),
        ChangeKind::Retyped { left, right } => (
            mirrored_path(&change.path),
            ChangeKind::Retyped {
                left: right.clone(),
                right: left.clone(),
            },
        ),
        ChangeKind::Renamed(from) => (from.clone(), ChangeKind::Renamed(change.path.clone())),
        ChangeKind::Moved { from, to } => (
            mirrored_path(&change.path),
            ChangeKind::Moved {
                from: *to,
                to: *from,
            },
        ),
        ChangeKind::BitfieldChanged { from, to } => (
            mirrored_path(&change.path),
            ChangeKind::BitfieldChanged {
                from: *to,
                to: *from,
            },
        ),
        ChangeKind::SizeChanged { left, right } => (
            change.path.clone(),
            ChangeKind::SizeChanged {
                left: *right,
                right: *left,
            },
        ),
        ChangeKind::ConstantAdded(v) => (change.path.clone(), ChangeKind::ConstantRemoved(*v)),
        ChangeKind::ConstantRemoved(v) => (change.path.clone(), ChangeKind::ConstantAdded(*v)),
        ChangeKind::ConstantChanged { left, right } => (
            change.path.clone(),
            ChangeKind::ConstantChanged {
                left: *right,
                right: *left,
            },
        ),
    };
    Change { path, kind }
}

/// Asserts `forward` and `backward` are true structural mirrors, not just matching counts: every
/// change in `forward`, run through [`mirror_change`], matches exactly one change in `backward`
/// with nothing left over.
///
/// Compared as a multiset via pool removal, since `Change` has no total order to sort by.
fn assert_are_structural_mirrors(forward: &[Change], backward: &[Change]) {
    let rename_from = rename_map(forward);
    let mut pool: Vec<Change> = backward.to_vec();
    for change in forward {
        let expected = mirror_change(change, &rename_from);
        let Some(pos) = pool.iter().position(|c| *c == expected) else {
            panic!("no mirror for {change:?} (expected {expected:?}) among {backward:?}");
        };
        pool.remove(pos);
    }
    assert!(
        pool.is_empty(),
        "backward has unmirrored changes left over: {pool:?}"
    );
}

proptest! {
    /// The core guarantee: diff is empty *iff* the values are equal, so a missed difference (a
    /// false "identical") fails here with a counterexample.
    #[test]
    fn diff_is_empty_iff_equal(a in canonical(), b in canonical()) {
        prop_assert_eq!(a.diff(&b).is_empty(), a == b);
    }

    /// A value never differs from itself, at any shape.
    #[test]
    fn self_diff_is_empty(a in canonical()) {
        prop_assert!(a.diff(&a).is_empty());
    }

    /// The diff relation is antisymmetric in its counts: the total length matches, the
    /// added/removed tallies swap, and the changed tally holds, since reversing a change only
    /// swaps its left/right values.
    #[test]
    fn diff_is_antisymmetric_in_its_metrics(a in canonical(), b in canonical()) {
        let forward = a.diff(&b);
        let backward = b.diff(&a);
        prop_assert_eq!(forward.len(), backward.len());
        prop_assert_eq!(forward.added(), backward.removed());
        prop_assert_eq!(forward.removed(), backward.added());
        prop_assert_eq!(forward.changed(), backward.changed());
    }

    /// The invariant behind [`diff_is_antisymmetric_in_its_metrics`], strengthened from matching
    /// counts to a literal structural mirror.
    ///
    /// Scoped to one flat struct/union level, so a matched member's path is its bare name, this
    /// pins `diff_members`'s pairing symmetry directly. A union collides every member at bit
    /// offset 0, where an asymmetric criterion pairs by index order alone.
    #[test]
    fn diff_members_are_structural_mirrors(
        kind in record_kind(),
        ra in flat_member_raw(),
        rb in flat_member_raw(),
        sa in opt_size(),
        sb in opt_size(),
    ) {
        let a = CanonicalType::Aggregate {
            tag: Some("S".to_owned()),
            kind,
            members: build_members(kind, ra),
            size: sa,
        };
        let b = CanonicalType::Aggregate {
            tag: Some("S".to_owned()),
            kind,
            members: build_members(kind, rb),
            size: sb,
        };
        assert_are_structural_mirrors(a.diff(&b).changes(), b.diff(&a).changes());
    }

    /// One declaration pool and root expression, materialized into two independently-numbered
    /// tables (the second padded with unrelated leading entries), canonicalizes to the same value:
    /// the `TypeId` numbering is never part of a type's identity.
    #[test]
    fn differently_spelled_types_canonicalize_identically((decls, root) in declared_type()) {
        let mut a = TypeTable::new();
        let root_a = build(&mut a, &decls, &root);

        let mut b = TypeTable::new();
        b.intern(TypeValue {
            shape: TypeShape::Bool,
            size: Some(1),
        });
        b.intern(TypeValue {
            shape: TypeShape::Void,
            size: None,
        });
        let root_b = build(&mut b, &decls, &root);

        prop_assert_eq!(
            canonicalize(&a, root_a, CanonicalOptions::strict()),
            canonicalize(&b, root_b, CanonicalOptions::strict())
        );
    }

    /// Canonicalizing is idempotent: embedding a real `canonicalize` output back into a fresh
    /// table via [`embed_canonical`] and canonicalizing that reproduces the exact same value.
    #[test]
    fn canonicalize_after_reembed_is_idempotent((table, root) in table_and_root()) {
        let once = canonicalize(&table, root, CanonicalOptions::strict());
        let mut rebuilt = TypeTable::new();
        let rebuilt_root = embed_canonical(&once, &mut rebuilt, &mut Vec::new());
        let twice = canonicalize(&rebuilt, rebuilt_root, CanonicalOptions::strict());
        prop_assert_eq!(once, twice);
    }
}

/// Every `BackRef` a real walk emits is well-scoped, with a `Cell` counter proving the run
/// actually reached one.
///
/// Driven by hand rather than through `proptest!`, which gives the closure no way to carry state
/// out. An anonymous self-cycle needs several draws to line up (a non-real tag, a `DeclRef`
/// member, that ref pointing at its own declaration), so the default case count flakes; the
/// raised one is still sub-second.
#[test]
fn backrefs_are_well_scoped() {
    let hits = Cell::new(0usize);
    let mut runner = TestRunner::new(ProptestConfig {
        cases: 1024,
        ..ProptestConfig::default()
    });
    runner
        .run(&table_and_root(), |(table, root)| {
            let c = canonicalize(&table, root, CanonicalOptions::strict());
            assert_backrefs_well_scoped(&c, 0, &hits);
            Ok(())
        })
        .unwrap();
    assert!(
        hits.get() > 0,
        "no BackRef appeared across the whole run; the well-scoped check never fired"
    );
}

/// Diff-empty-iff-equal again, on real `canonicalize` output over near-miss pairs.
///
/// Counts both branches, so a run that only ever drew equal pairs (or only unequal ones) fails
/// loudly instead of passing on an unexercised half of the property.
#[test]
fn diff_is_empty_iff_equal_for_real_canonical_types() {
    let equal_pairs = Cell::new(0usize);
    let unequal_pairs = Cell::new(0usize);
    let mut runner = TestRunner::default();
    runner
        .run(&table_and_near_miss(), |((a, root_a), (b, root_b))| {
            let ca = canonicalize(&a, root_a, CanonicalOptions::strict());
            let cb = canonicalize(&b, root_b, CanonicalOptions::strict());
            let equal = ca == cb;
            equal_pairs.set(equal_pairs.get() + usize::from(equal));
            unequal_pairs.set(unequal_pairs.get() + usize::from(!equal));
            assert!(ca.diff(&cb).is_empty() == equal);
            Ok(())
        })
        .unwrap();
    assert!(
        equal_pairs.get() > 0,
        "no near-miss pair ever came out equal across the whole run"
    );
    assert!(
        unequal_pairs.get() > 0,
        "no near-miss pair ever came out unequal across the whole run"
    );
}
