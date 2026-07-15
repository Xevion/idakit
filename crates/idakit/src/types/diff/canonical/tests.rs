use assert2::assert;

use super::*;
use crate::types::{EnumMember, TypeId, TypeMember, TypeShape, TypeTable, TypeValue};

fn scalar(table: &mut TypeTable, bytes: u8, signed: bool) -> TypeId {
    table.intern(TypeValue {
        shape: TypeShape::Int { bytes, signed },
        size: Some(u64::from(bytes)),
    })
}

fn ptr(table: &mut TypeTable, to: TypeId, width: u64) -> TypeId {
    table.intern(TypeValue {
        shape: TypeShape::Ptr(to),
        size: Some(width),
    })
}

fn member(name: &str, bit_offset: u64, ty: TypeId) -> TypeMember {
    TypeMember {
        name: name.to_owned(),
        bit_offset,
        ty,
        bitfield_width: None,
        repr: None,
    }
}

/// A named `struct point { int x; int y; }` built into `table`, returning its handle.
fn point(table: &mut TypeTable) -> TypeId {
    let int = scalar(table, 4, true);
    table.intern(TypeValue {
        shape: TypeShape::Struct {
            name: Some("point".to_owned()),
            members: vec![member("x", 0, int), member("y", 32, int)],
        },
        size: Some(8),
    })
}

#[test]
fn scalar_projects_to_all_forms() {
    let mut table = TypeTable::new();
    let id = scalar(&mut table, 4, true);
    let c = canonicalize(&table, id, CanonicalOptions::strict());
    assert!(
        c == CanonicalType::Int {
            bytes: Some(4),
            signed: true
        }
    );
    assert!(c.to_string() == "i32");
    assert!(c.identity().is_none());
    // the key is deterministic
    assert!(c.key() == c.key());
}

#[test]
fn identical_types_in_separate_tables_share_every_projection() {
    // The whole point: two independent tables (two databases) produce equal canonical forms,
    // keys, and strings for the same type, which the table-local `TypeId` equality cannot do.
    let mut a = TypeTable::new();
    let root_a = point(&mut a);
    let ca = canonicalize(&a, root_a, CanonicalOptions::strict());

    let mut b = TypeTable::new();
    let root_b = point(&mut b);
    let cb = canonicalize(&b, root_b, CanonicalOptions::strict());

    assert!(ca == cb);
    assert!(ca.key() == cb.key());
    assert!(ca.to_string() == cb.to_string());
    assert!(ca.identity() == cb.identity());
}

#[test]
fn a_changed_member_keeps_identity_but_changes_the_fingerprint() {
    let mut a = TypeTable::new();
    let root_a = point(&mut a);
    let ca = canonicalize(&a, root_a, CanonicalOptions::strict());

    // point with an extra field: same tag (same identity), different body (different key).
    let mut b = TypeTable::new();
    let int = scalar(&mut b, 4, true);
    let root_b = b.intern(TypeValue {
        shape: TypeShape::Struct {
            name: Some("point".to_owned()),
            members: vec![
                member("x", 0, int),
                member("y", 32, int),
                member("z", 64, int),
            ],
        },
        size: Some(12),
    });
    let cb = canonicalize(&b, root_b, CanonicalOptions::strict());

    assert!(ca.identity() == cb.identity());
    assert!(
        ca.identity()
            == Some(TypeIdentity::Tagged {
                tag: "point".to_owned(),
                kind: AggregateKind::Struct,
            })
    );
    assert!(ca != cb);
    assert!(ca.key() != cb.key());
}

#[test]
fn a_named_aggregate_is_spelled_at_root_and_cut_when_referenced() {
    // struct node { node *next; }: the recursive pointer cuts to a nominal reference, so the
    // walk terminates without a back-edge.
    let mut table = TypeTable::new();
    let node = table.alloc_placeholder();
    let node_ptr = ptr(&mut table, node, 8);
    table.fill(
        node,
        TypeValue {
            shape: TypeShape::Struct {
                name: Some("node".to_owned()),
                members: vec![member("next", 0, node_ptr)],
            },
            size: Some(8),
        },
    );

    let c = canonicalize(&table, node, CanonicalOptions::strict());
    let CanonicalType::Aggregate { members, .. } = &c else {
        panic!("root spells its body");
    };
    assert!(
        members[0].ty
            == CanonicalType::Ptr {
                pointee: Box::new(CanonicalType::Named {
                    tag: "node".to_owned(),
                    kind: AggregateKind::Struct,
                }),
                width: Some(8),
            }
    );
}

#[test]
fn a_synthetic_named_cycle_closes_with_a_backref() {
    // A `$`-named (synthetic) self-referential struct has no stable tag to cut on, so the De
    // Bruijn guard is what makes it terminate.
    let mut table = TypeTable::new();
    let anon = table.alloc_placeholder();
    let anon_ptr = ptr(&mut table, anon, 8);
    table.fill(
        anon,
        TypeValue {
            shape: TypeShape::Struct {
                name: Some("$A".to_owned()),
                members: vec![member("self", 0, anon_ptr)],
            },
            size: Some(8),
        },
    );

    let c = canonicalize(&table, anon, CanonicalOptions::strict());
    let CanonicalType::Aggregate { tag, members, .. } = &c else {
        panic!("a synthetic tag is spelled structurally");
    };
    assert!(tag.is_none()); // synthetic name -> treated as anonymous
    assert!(
        members[0].ty
            == CanonicalType::Ptr {
                pointee: Box::new(CanonicalType::BackRef(1)),
                width: Some(8),
            }
    );
}

#[test]
fn the_size_knob_separates_abi_from_logical() {
    // Two structs differing only in field width: an ABI key distinguishes them, a logical key
    // does not (the cross-architecture case).
    let mut a = TypeTable::new();
    let i32t = scalar(&mut a, 4, true);
    let root_a = a.intern(TypeValue {
        shape: TypeShape::Struct {
            name: None,
            members: vec![member("v", 0, i32t)],
        },
        size: Some(4),
    });

    let mut b = TypeTable::new();
    let i64t = scalar(&mut b, 8, true);
    let root_b = b.intern(TypeValue {
        shape: TypeShape::Struct {
            name: None,
            members: vec![member("v", 0, i64t)],
        },
        size: Some(8),
    });

    let strict_a = canonicalize(&a, root_a, CanonicalOptions::strict());
    let strict_b = canonicalize(&b, root_b, CanonicalOptions::strict());
    assert!(strict_a.key() != strict_b.key());

    let logical_a = canonicalize(&a, root_a, CanonicalOptions::logical());
    let logical_b = canonicalize(&b, root_b, CanonicalOptions::logical());
    assert!(logical_a == logical_b);
    assert!(logical_a.key() == logical_b.key());
    assert!(logical_a.to_string() == "struct{v=iint}");
}

#[test]
fn bitfields_ride_along_in_the_member() {
    let mut table = TypeTable::new();
    let u32t = scalar(&mut table, 4, false);
    let root = table.intern(TypeValue {
        shape: TypeShape::Struct {
            name: Some("flags".to_owned()),
            members: vec![TypeMember {
                name: "lo".to_owned(),
                bit_offset: 0,
                ty: u32t,
                bitfield_width: Some(3),
                repr: None,
            }],
        },
        size: Some(4),
    });
    let c = canonicalize(&table, root, CanonicalOptions::strict());
    let CanonicalType::Aggregate { members, .. } = &c else {
        panic!("struct");
    };
    assert!(members[0].bitfield_width == Some(3));
    assert!(c.to_string() == "struct:flags{lo@0:3=u32}=4");
}

#[test]
fn an_enum_spells_at_root_and_cuts_when_referenced() {
    let mut table = TypeTable::new();
    let int = scalar(&mut table, 4, false);
    let color = table.intern(TypeValue {
        shape: TypeShape::Enum {
            name: Some("color".to_owned()),
            underlying: int,
            members: vec![
                EnumMember {
                    name: "red".to_owned(),
                    value: 0,
                },
                EnumMember {
                    name: "green".to_owned(),
                    value: 1,
                },
            ],
            is_bitmask: false,
            repr: None,
        },
        size: Some(4),
    });

    // referenced through a pointer -> nominal cut
    let color_ptr = ptr(&mut table, color, 8);
    let referenced = canonicalize(&table, color_ptr, CanonicalOptions::strict());
    assert!(
        referenced
            == CanonicalType::Ptr {
                pointee: Box::new(CanonicalType::Named {
                    tag: "color".to_owned(),
                    kind: AggregateKind::Enum,
                }),
                width: Some(8),
            }
    );

    // at the root -> spelled
    let defined = canonicalize(&table, color, CanonicalOptions::strict());
    assert!(
        defined.identity()
            == Some(TypeIdentity::Tagged {
                tag: "color".to_owned(),
                kind: AggregateKind::Enum,
            })
    );
    // Constants render name-sorted (green before red), not in insertion order, so a reordered
    // enum is one canonical value.
    assert!(defined.to_string() == "enum:color(u32){green=1,red=0}=4");
}

#[test]
fn a_function_prototype_canonicalizes() {
    let mut table = TypeTable::new();
    let int = scalar(&mut table, 4, true);
    let cstr = {
        let ch = table.intern(TypeValue {
            shape: TypeShape::Int {
                bytes: 1,
                signed: true,
            },
            size: Some(1),
        });
        ptr(&mut table, ch, 8)
    };
    let proto = table.intern(TypeValue {
        shape: TypeShape::Function {
            ret: int,
            params: vec![cstr],
            varargs: true,
        },
        size: None,
    });
    let c = canonicalize(&table, proto, CanonicalOptions::strict());
    assert!(c.to_string() == "fn(ptr:8(i8),...)->i32");
    assert!(c.identity().is_none());
}

#[test]
fn a_typedef_keeps_its_alias_as_identity() {
    let mut table = TypeTable::new();
    let int = scalar(&mut table, 4, false);
    let alias = table.intern(TypeValue {
        shape: TypeShape::Typedef {
            name: "u32".to_owned(),
            underlying: int,
        },
        size: Some(4),
    });
    let c = canonicalize(&table, alias, CanonicalOptions::strict());
    assert!(
        c.identity()
            == Some(TypeIdentity::Alias {
                name: "u32".to_owned(),
            })
    );
    assert!(c.to_string() == "typedef u32=u32");
}

#[test]
fn identical_types_diff_to_nothing() {
    let mut t = TypeTable::new();
    let p = point(&mut t);
    let c = canonicalize(&t, p, CanonicalOptions::strict());
    let d = c.diff(&c);
    assert!(d.is_empty());
    assert!(d.to_string() == "(identical)");
}

#[test]
fn a_scalar_retype_is_a_root_change() {
    let a = CanonicalType::Int {
        bytes: Some(4),
        signed: true,
    };
    let b = CanonicalType::Int {
        bytes: Some(8),
        signed: true,
    };
    let d = a.diff(&b);
    assert!(d.changes().len() == 1);
    assert!(d.to_string() == "Change type  i32 → i64");
}

#[test]
#[expect(
    clippy::many_single_char_names,
    reason = "a/b name the two type tables being diffed, matching the diff's own a/b framing"
)]
fn drift_reports_retype_add_and_size() {
    // point {x:i32, y:i32}=8  ->  point {x:i32, y:i64, z:i32}=16.
    let mut a = TypeTable::new();
    let p = point(&mut a);
    let ca = canonicalize(&a, p, CanonicalOptions::strict());

    let mut b = TypeTable::new();
    let i32t = scalar(&mut b, 4, true);
    let i64t = scalar(&mut b, 8, true);
    let root = b.intern(TypeValue {
        shape: TypeShape::Struct {
            name: Some("point".to_owned()),
            members: vec![
                member("x", 0, i32t),
                member("y", 32, i64t),
                member("z", 96, i32t),
            ],
        },
        size: Some(16),
    });
    let cb = canonicalize(&b, root, CanonicalOptions::strict());

    let d = ca.diff(&cb);
    let s = d.to_string();
    assert!(!d.is_empty());
    assert!(s.contains("Resize"));
    assert!(s.contains("0x8 → 0x10"));
    assert!(s.contains("Change type"));
    assert!(s.contains("i32 → i64"));
    assert!(s.contains("Add"));
    // Metrics: y retyped, z added, root resized, and added+removed+changed plus the size
    // change partition len().
    assert!(d.len() == 3);
    assert!(d.added() == 1);
    assert!(d.removed() == 0);
    assert!(d.changed() == 1);
    assert!(d.size_change() == Some((Some(8), Some(16))));
}

#[test]
fn a_nested_member_change_uses_a_dotted_path() {
    // struct outer { struct { i32 v } in; } with `v` widened on the right.
    let build = |vbytes: u8| {
        let mut t = TypeTable::new();
        let v = scalar(&mut t, vbytes, true);
        let inner = t.intern(TypeValue {
            shape: TypeShape::Struct {
                name: None,
                members: vec![member("v", 0, v)],
            },
            size: Some(u64::from(vbytes)),
        });
        let outer = t.intern(TypeValue {
            shape: TypeShape::Struct {
                name: Some("outer".to_owned()),
                members: vec![member("in", 0, inner)],
            },
            size: Some(u64::from(vbytes)),
        });
        canonicalize(&t, outer, CanonicalOptions::strict())
    };
    let d = build(4).diff(&build(8));
    let s = d.to_string();
    assert!(s.contains("in.v"));
    assert!(s.contains("i32 → i64"));
}

fn cint(bytes: u8, signed: bool) -> CanonicalType {
    CanonicalType::Int {
        bytes: Some(bytes),
        signed,
    }
}

fn cfield(name: &str, off: u64, ty: CanonicalType) -> CanonicalMember {
    CanonicalMember {
        name: name.to_owned(),
        bit_offset: Some(off),
        bitfield_width: None,
        ty,
    }
}

fn cstruct(tag: &str, members: Vec<CanonicalMember>, size: u64) -> CanonicalType {
    CanonicalType::Aggregate {
        tag: Some(tag.to_owned()),
        kind: AggregateKind::Struct,
        members,
        size: Some(size),
    }
}

/// A named enum built into `table`, in the given constant order.
fn enum_of(table: &mut TypeTable, tag: &str, consts: &[(&str, u64)]) -> TypeId {
    let underlying = scalar(table, 4, false);
    table.intern(TypeValue {
        shape: TypeShape::Enum {
            name: Some(tag.to_owned()),
            underlying,
            members: consts
                .iter()
                .map(|(n, v)| EnumMember {
                    name: (*n).to_owned(),
                    value: *v,
                })
                .collect(),
            is_bitmask: false,
            repr: None,
        },
        size: Some(4),
    })
}

#[test]
fn an_enum_reordered_is_the_same_type() {
    // The LogMark regression: the same constants in a different order must be one canonical
    // value, one key, and an empty diff, not a "drifted" phantom.
    let mut a = TypeTable::new();
    let ea = enum_of(&mut a, "E", &[("A", 1), ("B", 2), ("C", 3)]);
    let ca = canonicalize(&a, ea, CanonicalOptions::strict());
    let mut b = TypeTable::new();
    let eb = enum_of(&mut b, "E", &[("C", 3), ("A", 1), ("B", 2)]);
    let cb = canonicalize(&b, eb, CanonicalOptions::strict());

    assert!(ca == cb);
    assert!(ca.key() == cb.key());
    assert!(ca.diff(&cb).is_empty());
}

#[test]
fn a_union_reordered_is_the_same_type() {
    let build = |order: &[&str]| {
        let mut t = TypeTable::new();
        let i = scalar(&mut t, 4, true);
        let f = scalar(&mut t, 8, false);
        let by_name = |n: &str| TypeMember {
            name: n.to_owned(),
            bit_offset: 0,
            ty: if n == "i" { i } else { f },
            bitfield_width: None,
            repr: None,
        };
        let root = t.intern(TypeValue {
            shape: TypeShape::Union {
                name: Some("U".to_owned()),
                members: order.iter().map(|n| by_name(n)).collect(),
            },
            size: Some(8),
        });
        canonicalize(&t, root, CanonicalOptions::strict())
    };
    let ca = build(&["i", "f"]);
    let cb = build(&["f", "i"]);
    assert!(ca == cb);
    assert!(ca.diff(&cb).is_empty());
}

#[test]
fn a_renamed_field_is_detected_not_add_remove() {
    let a = cstruct("S", vec![cfield("old", 0, cint(4, true))], 4);
    let b = cstruct("S", vec![cfield("new", 0, cint(4, true))], 4);
    let d = a.diff(&b);
    assert!(d.changes().len() == 1);
    assert!(d.to_string() == "Rename  old → new");
}

#[test]
fn a_repacked_field_moves() {
    // Same members and types, one field at a new offset, no insert/remove -> a Move.
    let a = cstruct(
        "S",
        vec![
            cfield("x", 0, cint(4, true)),
            cfield("y", 64, cint(4, true)),
        ],
        16,
    );
    let b = cstruct(
        "S",
        vec![
            cfield("x", 0, cint(4, true)),
            cfield("y", 96, cint(4, true)),
        ],
        16,
    );
    let d = a.diff(&b);
    assert!(d.to_string() == "Move  y  0x8 → 0xc");
}

#[test]
fn an_inserted_field_does_not_report_the_offset_cascade() {
    // Inserting `mid` shifts `y`; the diff shows the insertion and size, not y's forced move.
    let a = cstruct(
        "S",
        vec![
            cfield("x", 0, cint(4, true)),
            cfield("y", 32, cint(4, true)),
        ],
        8,
    );
    let b = cstruct(
        "S",
        vec![
            cfield("x", 0, cint(4, true)),
            cfield("mid", 32, cint(4, true)),
            cfield("y", 64, cint(4, true)),
        ],
        12,
    );
    let d = a.diff(&b);
    let s = d.to_string();
    assert!(s.contains("Add"));
    assert!(s.contains("mid"));
    assert!(s.contains("Resize"));
    assert!(s.contains("0x8 → 0xc"));
    assert!(!s.contains("Move")); // y's shift is the derivable cascade, suppressed
}

#[test]
fn a_bitfield_width_change_is_flagged() {
    let bf = |w: u32| CanonicalType::Aggregate {
        tag: Some("F".to_owned()),
        kind: AggregateKind::Struct,
        members: vec![CanonicalMember {
            name: "b".to_owned(),
            bit_offset: Some(0),
            bitfield_width: Some(w),
            ty: cint(4, false),
        }],
        size: Some(4),
    };
    let d = bf(3).diff(&bf(5));
    assert!(d.to_string() == "Change width  b  3 → 5");
}

#[test]
fn a_different_tag_is_a_whole_retype() {
    let a = cstruct("A", vec![cfield("x", 0, cint(4, true))], 4);
    let b = cstruct("B", vec![cfield("x", 0, cint(4, true))], 4);
    let d = a.diff(&b);
    assert!(d.changes().len() == 1);
    assert!(let ChangeKind::Retyped { .. } = &d.changes()[0].kind);
}

#[test]
fn a_struct_and_union_of_one_body_still_differ() {
    let s = cstruct("X", vec![cfield("a", 0, cint(4, true))], 4);
    let u = CanonicalType::Aggregate {
        tag: Some("X".to_owned()),
        kind: AggregateKind::Union,
        members: vec![cfield("a", 0, cint(4, true))],
        size: Some(4),
    };
    let d = s.diff(&u);
    assert!(let ChangeKind::Retyped { .. } = &d.changes()[0].kind);
}

#[test]
fn enum_constants_add_remove_and_change() {
    let en = |consts: &[(&str, u64)]| CanonicalType::Enum {
        tag: Some("E".to_owned()),
        underlying: Box::new(cint(4, false)),
        members: consts.iter().map(|(n, v)| ((*n).to_owned(), *v)).collect(),
        size: Some(4),
    };
    let a = en(&[("A", 1), ("B", 2)]);
    let b = en(&[("A", 9), ("C", 3)]); // A changed, B removed, C added
    let d = a.diff(&b);
    let s = d.to_string();
    assert!(s.contains("Change value"));
    assert!(s.contains("0x1 → 0x9"));
    assert!(s.contains("Remove"));
    assert!(s.contains("0x2"));
    assert!(s.contains("Add"));
    assert!(s.contains("0x3"));
    // Constant add/remove/change fold into the same metrics as members; no size change here.
    assert!(d.added() == 1);
    assert!(d.removed() == 1);
    assert!(d.changed() == 1);
    assert!(d.size_change().is_none());
}
