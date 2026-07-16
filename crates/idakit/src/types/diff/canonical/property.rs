//! Property tests: the diff must be *complete*, empty exactly when the two canonical values are
//! equal. A missed difference (a false "identical") fails here with a counterexample.

use std::collections::HashSet;

use proptest::prelude::*;

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

/// Assemble members respecting the canonicalization invariants: distinct names, struct offsets
/// strictly increasing, union offsets all zero and name-sorted.
fn build_members(
    kind: AggregateKind,
    raw: Vec<(String, Option<u32>, CanonicalType)>,
) -> Vec<CanonicalMember> {
    let mut seen = HashSet::new();
    let mut out: Vec<CanonicalMember> = Vec::new();
    for (name, bitfield_width, ty) in raw {
        if seen.insert(name.clone()) {
            let bit_offset = Some(if kind == AggregateKind::Union {
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
    if kind == AggregateKind::Union {
        out.sort_by(|a, b| a.name.cmp(&b.name));
    }
    out
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

/// The recursive composition shared by [`canonical`] and [`canonical_no_backref`]: everything
/// above the leaf strategy is identical, so only the leaf set differs between them.
fn canonical_variant(
    leaf: impl Strategy<Value = CanonicalType> + 'static,
) -> impl Strategy<Value = CanonicalType> {
    leaf.prop_recursive(4, 40, 4, |inner| {
        let members = move |kind: AggregateKind, inner: BoxedStrategy<CanonicalType>| {
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
                members(AggregateKind::Struct, inner.clone()),
                opt_size()
            )
                .prop_map(|(tag, members, size)| CanonicalType::Aggregate {
                    tag,
                    kind: AggregateKind::Struct,
                    members,
                    size
                }),
            (
                opt_tag(),
                members(AggregateKind::Union, inner.clone()),
                opt_size()
            )
                .prop_map(|(tag, members, size)| CanonicalType::Aggregate {
                    tag,
                    kind: AggregateKind::Union,
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
        (0usize..3).prop_map(CanonicalType::BackRef),
    ];
    canonical_variant(leaf)
}

/// A [`canonical`]-like generator, restricted to what a real [`canonicalize`] call can actually
/// produce, so [`materialize`] can round-trip it: no [`BackRef`](CanonicalType::BackRef) (its
/// validity depends on the exact aggregate-nesting depth at generation time, which an unguided
/// leaf can't respect), and every [`Aggregate`](CanonicalType::Aggregate)/
/// [`Enum`](CanonicalType::Enum) is anonymous. The latter matters at *every* depth, not just
/// nested ones: `canonicalize` only ever spells a *tagged* aggregate/enum at the walk's root
/// (anywhere else nominal-cuts to [`Named`](CanonicalType::Named)), and this generator draws
/// uniformly at every depth including the outermost, so a tagged aggregate/enum could land nested
/// just as easily as at the top, producing a value no real walk could emit there.
/// [`Named`](CanonicalType::Named) references still appear freely (a real walk cuts to one at any
/// non-root aggregate/enum position), just never as the bare root value (see
/// [`canonical_root_safe`]).
fn canonical_no_backref() -> impl Strategy<Value = CanonicalType> {
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
    ];
    leaf.prop_recursive(4, 40, 4, |inner| {
        let members = move |kind: AggregateKind, inner: BoxedStrategy<CanonicalType>| {
            prop::collection::vec((field_name(), opt_bitfield(), inner), 0..4)
                .prop_map(move |raw| build_members(kind, raw))
        };
        let inner = inner.boxed();
        prop_oneof![
            (inner.clone(), prop_oneof![Just(Some(4u8)), Just(Some(8u8))]).prop_map(
                |(p, width)| CanonicalType::Ptr {
                    pointee: Box::new(p),
                    width
                }
            ),
            (inner.clone(), 0u64..4).prop_map(|(e, len)| CanonicalType::Array {
                elem: Box::new(e),
                len
            }),
            (members(AggregateKind::Struct, inner.clone()), opt_size()).prop_map(
                |(members, size)| CanonicalType::Aggregate {
                    tag: None,
                    kind: AggregateKind::Struct,
                    members,
                    size
                }
            ),
            (members(AggregateKind::Union, inner.clone()), opt_size()).prop_map(
                |(members, size)| CanonicalType::Aggregate {
                    tag: None,
                    kind: AggregateKind::Union,
                    members,
                    size
                }
            ),
            (inner.clone(), constants(), opt_size()).prop_map(|(underlying, members, size)| {
                CanonicalType::Enum {
                    tag: None,
                    underlying: Box::new(underlying),
                    members,
                    size,
                }
            }),
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

/// [`canonical_no_backref`], filtered so the root itself is never a bare
/// [`Named`](CanonicalType::Named) cut: [`canonicalize`] always spells the root (only a
/// non-root reference nominal-cuts), so no materialized table could ever round-trip back to a
/// bare `Named` there. `Named` still appears freely nested inside members, pointees, and so on.
fn canonical_root_safe() -> impl Strategy<Value = CanonicalType> {
    canonical_no_backref().prop_filter("root is not a bare Named cut", |c| {
        !matches!(c, CanonicalType::Named { .. })
    })
}

/// Allocates a fresh, never-deduped table entry: the inverse building block [`materialize`] uses
/// throughout, so two structurally-identical but distinct source nodes never collapse to one
/// [`TypeId`] and spuriously trip [`canonicalize`]'s cycle detector (which keys purely on
/// identity, not value).
fn fresh(table: &mut TypeTable, value: TypeValue) -> TypeId {
    let id = table.alloc_placeholder();
    table.fill(id, value);
    id
}

/// The [`Named`](CanonicalType::Named) arm of [`materialize`]: an empty-bodied stub of the right
/// tag and kind, since a nominal cut is purely syntactic and never re-reads what it points at.
fn materialize_named_stub(tag: &str, kind: AggregateKind, table: &mut TypeTable) -> TypeId {
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
            let underlying = fresh(
                table,
                TypeValue {
                    shape: TypeShape::Int {
                        bytes: 4,
                        signed: false,
                    },
                    size: Some(4),
                },
            );
            TypeShape::Enum {
                name: Some(tag.to_owned()),
                underlying,
                members: Vec::new(),
                is_bitmask: false,
                repr: None,
            }
        }
    };
    fresh(table, TypeValue { shape, size: None })
}

/// The [`Aggregate`](CanonicalType::Aggregate) arm of [`materialize`]: recursively materializes
/// every member's type before assembling the struct/union shape it belongs to.
fn materialize_members(members: &[CanonicalMember], table: &mut TypeTable) -> Vec<TypeMember> {
    members
        .iter()
        .map(|m| TypeMember {
            name: m.name.clone(),
            bit_offset: m
                .bit_offset
                .expect("canonical_no_backref always sets member bit_offset"),
            ty: materialize(&m.ty, table),
            bitfield_width: m.bitfield_width,
            repr: None,
        })
        .collect()
}

/// The [`Enum`](CanonicalType::Enum) arm of [`materialize`].
fn materialize_enum(
    tag: Option<&str>,
    underlying: &CanonicalType,
    members: &[(String, u64)],
    size: Option<u64>,
    table: &mut TypeTable,
) -> TypeId {
    let underlying = materialize(underlying, table);
    fresh(
        table,
        TypeValue {
            shape: TypeShape::Enum {
                name: tag.map(str::to_owned),
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
            size,
        },
    )
}

/// The [`Function`](CanonicalType::Function) arm of [`materialize`].
fn materialize_function(
    ret: &CanonicalType,
    params: &[CanonicalType],
    varargs: bool,
    table: &mut TypeTable,
) -> TypeId {
    let ret = materialize(ret, table);
    let params = params.iter().map(|p| materialize(p, table)).collect();
    fresh(
        table,
        TypeValue {
            shape: TypeShape::Function {
                ret,
                params,
                varargs,
            },
            size: None,
        },
    )
}

/// Rebuilds a fresh [`TypeTable`] entry from a [`CanonicalType`] produced by
/// [`canonical_no_backref`]: the inverse of [`canonicalize`] under [`CanonicalOptions::strict`].
fn materialize(c: &CanonicalType, table: &mut TypeTable) -> TypeId {
    match c {
        CanonicalType::Void => fresh(
            table,
            TypeValue {
                shape: TypeShape::Void,
                size: None,
            },
        ),
        CanonicalType::Bool => fresh(
            table,
            TypeValue {
                shape: TypeShape::Bool,
                size: Some(1),
            },
        ),
        CanonicalType::Int { bytes, signed } => {
            let bytes = bytes.expect("canonical_no_backref always sets Int::bytes");
            fresh(
                table,
                TypeValue {
                    shape: TypeShape::Int {
                        bytes,
                        signed: *signed,
                    },
                    size: Some(u64::from(bytes)),
                },
            )
        }
        CanonicalType::Float { bytes } => {
            let bytes = bytes.expect("canonical_no_backref always sets Float::bytes");
            fresh(
                table,
                TypeValue {
                    shape: TypeShape::Float { bytes },
                    size: Some(u64::from(bytes)),
                },
            )
        }
        CanonicalType::Ptr { pointee, width } => {
            let inner = materialize(pointee, table);
            let width = width.expect("canonical_no_backref always sets Ptr::width");
            fresh(
                table,
                TypeValue {
                    shape: TypeShape::Ptr(inner),
                    size: Some(u64::from(width)),
                },
            )
        }
        CanonicalType::Array { elem, len } => {
            let inner = materialize(elem, table);
            fresh(
                table,
                TypeValue {
                    shape: TypeShape::Array {
                        elem: inner,
                        len: *len,
                    },
                    size: None,
                },
            )
        }
        CanonicalType::Named { tag, kind } => materialize_named_stub(tag, *kind, table),
        CanonicalType::Aggregate {
            tag,
            kind,
            members,
            size,
        } => {
            let members = materialize_members(members, table);
            let shape = match kind {
                AggregateKind::Struct => TypeShape::Struct {
                    name: tag.clone(),
                    members,
                },
                AggregateKind::Union => TypeShape::Union {
                    name: tag.clone(),
                    members,
                },
                AggregateKind::Enum => {
                    unreachable!("the generator never builds an Aggregate with AggregateKind::Enum")
                }
            };
            fresh(table, TypeValue { shape, size: *size })
        }
        CanonicalType::Enum {
            tag,
            underlying,
            members,
            size,
        } => materialize_enum(tag.as_deref(), underlying, members, *size, table),
        CanonicalType::Function {
            ret,
            params,
            varargs,
        } => materialize_function(ret, params, *varargs, table),
        CanonicalType::Typedef { name, underlying } => {
            let underlying = materialize(underlying, table);
            fresh(
                table,
                TypeValue {
                    shape: TypeShape::Typedef {
                        name: name.clone(),
                        underlying,
                    },
                    size: None,
                },
            )
        }
        CanonicalType::Opaque(name) => fresh(
            table,
            TypeValue {
                shape: TypeShape::Opaque(name.clone()),
                size: None,
            },
        ),
        CanonicalType::BackRef(_) => {
            unreachable!("canonical_no_backref never generates a BackRef leaf")
        }
    }
}

proptest! {
    /// The core guarantee: diff is empty *iff* the values are equal. This catches any missed
    /// difference (a false "identical"), the class of bug the enum-reorder case exposed.
    #[test]
    fn diff_is_empty_iff_equal(a in canonical(), b in canonical()) {
        prop_assert_eq!(a.diff(&b).is_empty(), a == b);
    }

    /// A value never differs from itself, at any shape.
    #[test]
    fn self_diff_is_empty(a in canonical()) {
        prop_assert!(a.diff(&a).is_empty());
    }

    /// The diff relation is antisymmetric in its counts: `a.diff(&b)` and `b.diff(&a)` have the
    /// same total length, and the added/removed tallies swap (an addition going one way is a
    /// removal going the other), while the changed tally (retype, rename, move, bitfield, or
    /// constant-value change) stays the same either way, since it only swaps each change's
    /// left/right values, never its count.
    #[test]
    fn diff_is_antisymmetric_in_its_metrics(a in canonical(), b in canonical()) {
        let forward = a.diff(&b);
        let backward = b.diff(&a);
        prop_assert_eq!(forward.len(), backward.len());
        prop_assert_eq!(forward.added(), backward.removed());
        prop_assert_eq!(forward.removed(), backward.added());
        prop_assert_eq!(forward.changed(), backward.changed());
    }

    /// Canonicalizing is a left inverse of [`materialize`]: rebuilding a table from a canonical
    /// form and canonicalizing it again reproduces the exact same value. The "canonicalize twice"
    /// idempotence guarantee, since [`CanonicalType`] carries no table of its own to canonicalize
    /// directly.
    #[test]
    fn canonicalize_after_materialize_is_idempotent(c in canonical_root_safe()) {
        let mut table = TypeTable::new();
        let root = materialize(&c, &mut table);
        let round_tripped = canonicalize(&table, root, CanonicalOptions::strict());
        prop_assert_eq!(round_tripped, c);
    }

    /// The same canonical shape, materialized into two tables whose arenas are ordered
    /// differently (one padded with unrelated leading entries, so every handle in it is offset
    /// from the other's), canonicalizes to the identical value: a structurally-equal type
    /// "spelled" through a different `TypeId` numbering is still the same type.
    #[test]
    fn differently_spelled_types_canonicalize_identically(c in canonical_root_safe()) {
        let mut a = TypeTable::new();
        let root_a = materialize(&c, &mut a);

        let mut b = TypeTable::new();
        b.intern(TypeValue {
            shape: TypeShape::Bool,
            size: Some(1),
        });
        b.intern(TypeValue {
            shape: TypeShape::Void,
            size: None,
        });
        let root_b = materialize(&c, &mut b);

        prop_assert_eq!(
            canonicalize(&a, root_a, CanonicalOptions::strict()),
            canonicalize(&b, root_b, CanonicalOptions::strict())
        );
    }
}
