//! Property tests: the diff must be *complete*, empty exactly when the two canonical values are
//! equal. A missed difference (a false "identical") fails here with a counterexample.

use std::collections::HashSet;

use proptest::prelude::*;

use super::*;

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
}
