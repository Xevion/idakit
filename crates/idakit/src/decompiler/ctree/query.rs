//! Structural primitives for querying a [`Ctree`], forming a composable layer above the
//! bare node arenas.
//!
//! Decompiled expressions wrap the interesting node in address/place nodes (`Cast`, `&`,
//! `*`, member access) whose exact shape varies with optimization level and whether IDA
//! has typed a pointer. [`strip_casts`], [`base_var`], and [`global_target`] look
//! **through** those wrappers so callers can match patterns *tolerantly* rather than
//! against one exact shape.
//!
//! These are deliberately general. The crate's constructor-analysis test (`tests/ctor.rs`)
//! composes them into higher-level matchers, recovering C++ vtable installs and base-ctor
//! calls from real decompiler output, as a worked example.

use serde::{Deserialize, Serialize};

use super::node::{ExpressionId, ExpressionKind, LocalId};
use super::ops::{BinaryOp, UnaryOp};
use super::tree::Ctree;
use crate::address::Address;

/// A reference to a global/static the decompiler named, as surfaced by [`global_target`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GlobalRef {
    /// The global's address.
    pub address: Address,
    /// Its symbol name, if the decompiler gave it one.
    pub name: Option<String>,
}

/// Peel cast `(T)x` and address-of `&x` wrappers, which rename nothing, down to the first
/// expression that is neither.
///
/// Does not look through a dereference `*x`, which names the pointee. Whether to follow that is
/// the matcher's call. Shared by [`base_var`] and [`global_target`], and public so custom
/// matchers peel the same way.
#[must_use]
pub fn strip_casts(tree: &Ctree, mut e: ExpressionId) -> ExpressionId {
    loop {
        match tree.kind(e) {
            ExpressionKind::Cast { x }
            | ExpressionKind::Unary {
                op: UnaryOp::Ref,
                x,
            } => e = *x,
            _ => return e,
        }
    }
}

/// Follow `e` through place/address wrappers (`MemberRef`/`MemberPtr`/`Deref`/`&`/`Cast`) and
/// pointer arithmetic down to the root [`ExpressionKind::Var`], accumulating the byte offset.
///
/// Returns the local and the total offset from its base, or `None` if the expression isn't
/// rooted at a variable.
///
/// The typed shape (`this->Other` as `MemberRef`/`MemberPtr`, once IDA has typed the struct
/// layout) and the untyped shape (`*((_QWORD *)this + 2)` or `(char *)this + 16`, as raw
/// pointer arithmetic) both resolve to the same `(this, 16)`. The untyped form is what shows
/// up in stripped binaries, so threading it is what makes these matchers useful there.
///
/// ```
/// use idakit::decompiler::ctree::query::base_var;
/// use idakit::decompiler::ctree::{CtreeBuilder, Local, LocalLocation};
/// use idakit::types::{TypeShape, TypeValue};
///
/// let mut b = CtreeBuilder::new();
/// let ty = b.intern_type(TypeValue {
///     shape: TypeShape::Unknown,
///     size: None,
/// });
/// let this = b.push_local(Local {
///     name: "this".into(),
///     ty,
///     is_arg: true,
///     is_result: false,
///     is_byref: false,
///     width: 8,
///     comment: None,
///     location: LocalLocation::Register(0),
/// });
///
/// // `(T)this->field`, at byte offset 16, the cast real decompiler output wraps around it.
/// let v = b.var(ty, this);
/// let member = b.member_ptr(ty, v, 16);
/// let cast = b.cast(ty, member);
/// let stmt = b.expression_statement(cast);
/// let block = b.block(vec![stmt]);
/// let tree = b.finish(block);
///
/// // The cast is peeled and the member offset threaded back to its base local.
/// assert_eq!(base_var(&tree, cast), Some((this, 16)));
/// ```
#[must_use]
pub fn base_var(tree: &Ctree, e: ExpressionId) -> Option<(LocalId, i64)> {
    // Casts and `&` rename nothing; peel them first so the match below sees the place node.
    let e = strip_casts(tree, e);
    match tree.kind(e) {
        ExpressionKind::Var(v) => Some((*v, 0)),
        ExpressionKind::MemberRef { obj, byte_offset }
        | ExpressionKind::MemberPtr { obj, byte_offset } => {
            base_var(tree, *obj).map(|(v, off)| (v, off + i64::from(*byte_offset)))
        }
        // `*p` keeps the same root and offset; the load itself is not navigation.
        ExpressionKind::Deref { x, .. } => base_var(tree, *x),
        // Pointer arithmetic `base + k`: the byte delta is the constant index scaled by the
        // pointee size of `base`, exactly as C scales it, so a `_QWORD*` index of 2 and a
        // `char*` index of 16 both advance 16 bytes. The `pointee_size` guard means plain
        // integer addition (no pointer type) is not mistaken for navigation.
        ExpressionKind::Binary {
            op: BinaryOp::Add,
            x,
            y,
        } => {
            let (base, k) = match (tree.kind(*x), tree.kind(*y)) {
                (_, ExpressionKind::Num(k)) => (*x, *k),
                (ExpressionKind::Num(k), _) => (*y, *k),
                _ => return None,
            };
            let elem = pointee_size(tree, base)?;
            base_var(tree, base).map(|(v, off)| (v, off + k as i64 * elem))
        }
        _ => None,
    }
}

/// The byte size of what `e`'s pointer type addresses, used to scale pointer arithmetic.
/// `None` unless `e` is a pointer whose element size is known.
fn pointee_size(tree: &Ctree, e: ExpressionId) -> Option<i64> {
    let elem = tree.type_of(tree.expression(e).ty).shape.pointee()?;
    tree.type_of(elem).size.map(|s| s as i64)
}

/// Follow `e` through `Cast`/`&` down to a [`ExpressionKind::Obj`], returning the global it names.
pub fn global_target(tree: &Ctree, e: ExpressionId) -> Option<GlobalRef> {
    let (address, name) = tree.kind(strip_casts(tree, e)).as_obj()?;
    Some(GlobalRef {
        address,
        name: name.map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ctree::AssignmentOp;
    use crate::decompiler::ctree::node::{Local, LocalLocation};
    use crate::decompiler::ctree::tree::CtreeBuilder;
    use crate::types::{TypeShape, TypeValue};
    use assert2::assert;
    use rstest::rstest;

    fn ty(b: &mut CtreeBuilder) -> crate::types::TypeId {
        b.intern_type(TypeValue {
            shape: TypeShape::Unknown,
            size: None,
        })
    }

    fn this_local_def(name: &str, t: crate::types::TypeId) -> Local {
        Local {
            name: name.into(),
            ty: t,
            is_arg: true,
            is_result: false,
            is_byref: false,
            width: 8,
            comment: None,
            location: LocalLocation::Register(0),
        }
    }

    /// Build a constructor-shaped tree mirroring real decompiler output:
    /// ```text
    /// this->_vptr            = (..)&vtbl_primary;   // install, off 0
    /// this->Other._vptr      = (..)&vtbl_sub;       // install, off 16
    /// BaseCtor(this);                                // this-call, off 0
    /// OtherCtor(&this->Other);                       // this-call, off 16
    /// this->d = 4;                                   // field init (NOT an install)
    /// ```
    fn ctor_tree() -> Ctree {
        let mut b = CtreeBuilder::new();
        let t = ty(&mut b);
        let this = b.push_local(this_local_def("this", t));

        // primary vtable install: this->_vptr = (..)&vtbl_primary  (offset 0)
        let v0 = b.var(t, this);
        let mp0 = b.member_ptr(t, v0, 0);
        let mr0 = b.member_ref(t, mp0, 0);
        let o1 = b.obj(t, Address::new_const(0x1000), Some("vtbl_primary"));
        let c1 = b.cast(t, o1);
        let a1 = b.assign(t, AssignmentOp::Assign, mr0, c1);

        // subobject install: this->Other._vptr = (..)&vtbl_sub  (offset 16)
        let v1 = b.var(t, this);
        let mp16 = b.member_ptr(t, v1, 16);
        let mr0b = b.member_ref(t, mp16, 0);
        let o2 = b.obj(t, Address::new_const(0x2000), Some("vtbl_sub"));
        let r2 = b.unary(t, UnaryOp::Ref, o2);
        let c2 = b.cast(t, r2);
        let a2 = b.assign(t, AssignmentOp::Assign, mr0b, c2);

        // base ctor call: BaseCtor(this)  (offset 0)
        let v2 = b.var(t, this);
        let oc1 = b.obj(t, Address::new_const(0x3000), Some("BaseCtor"));
        let call1 = b.call_expression(t, oc1, vec![v2]);

        // subobject ctor call: OtherCtor(&this->Other)  (offset 16)
        let v3 = b.var(t, this);
        let mp16b = b.member_ptr(t, v3, 16);
        let r4 = b.unary(t, UnaryOp::Ref, mp16b);
        let oc2 = b.obj(t, Address::new_const(0x4000), Some("OtherCtor"));
        let call2 = b.call_expression(t, oc2, vec![r4]);

        // field init: this->d = 4  (NOT a vtable install)
        let v4 = b.var(t, this);
        let mp28 = b.member_ptr(t, v4, 28);
        let num = b.num(t, 4);
        let a3 = b.assign(t, AssignmentOp::Assign, mp28, num);

        let statements: Vec<_> = [a1, a2, call1, call2, a3]
            .into_iter()
            .map(|e| b.expression_statement(e))
            .collect();
        let block = b.block(statements);
        b.finish(block)
    }

    #[test]
    fn this_local_is_the_first_arg() {
        let tree = ctor_tree();
        assert!(tree.this_local() == Some(LocalId(0)));
    }

    /// Peels `(T)x` and `&x`, but stops at a dereference (a load names a different object).
    #[test]
    fn strip_casts_peels_cast_and_ref_but_stops_at_deref() {
        let mut b = CtreeBuilder::new();
        let t = ty(&mut b);
        let obj = b.obj(t, Address::new_const(0x10), None);
        let deref = b.deref(t, obj, 8);
        let cast = b.cast(t, deref);
        let st = b.expression_statement(cast);
        let block = b.block(vec![st]);
        let tree = b.finish(block);
        // `(T)(*obj)`: the cast peels, the deref does not.
        assert!(strip_casts(&tree, cast) == deref);
        // A bare leaf has nothing to peel.
        assert!(strip_casts(&tree, obj) == obj);
    }

    #[test]
    fn base_var_threads_offset_through_member_and_address_ops() {
        let tree = ctor_tree();
        // Find the `&this->Other` argument of the OtherCtor call and resolve it.
        let (_, _, args) = tree
            .calls()
            .find(|(_, callee, _)| {
                matches!(tree.kind(*callee), ExpressionKind::Obj { name: Some(n), .. } if n == "OtherCtor")
            })
            .expect("OtherCtor call");
        assert!(base_var(&tree, args[0]) == Some((LocalId(0), 16)));
    }

    /// Untyped pointer arithmetic threads to the same offset a member access would, since
    /// the constant index is scaled by the pointee size, so `(_QWORD *)this + 2`,
    /// `(_DWORD *)this + 7`, and `(char *)this + 16` resolve to bytes 16, 28, and 16.
    #[rstest]
    #[case(8, 2, 16)]
    #[case(4, 7, 28)]
    #[case(1, 16, 16)]
    fn base_var_threads_scaled_pointer_arithmetic(
        #[case] elem_bytes: u8,
        #[case] index: u64,
        #[case] expect: i64,
    ) {
        let mut b = CtreeBuilder::new();
        let elem = b.intern_type(TypeValue {
            shape: TypeShape::Int {
                bytes: elem_bytes,
                signed: false,
            },
            size: Some(u64::from(elem_bytes)),
        });
        let ptr = b.intern_type(TypeValue {
            shape: TypeShape::Ptr(elem),
            size: Some(8),
        });
        let this = b.push_local(this_local_def("this", ptr));
        let v = b.var(ptr, this);
        let cast = b.cast(ptr, v);
        let num = b.num(elem, index);
        let add = b.binary(ptr, BinaryOp::Add, cast, num);
        // The install/arg shapes wrap the arithmetic in a `*(...)` or `(T)(...)`; resolving
        // through that wrapper is the whole point.
        let deref = b.deref(elem, add, u32::from(elem_bytes));
        let st = b.expression_statement(deref);
        let block = b.block(vec![st]);
        let tree = b.finish(block);
        assert!(base_var(&tree, deref) == Some((this, expect)));
    }

    /// The `pointee_size` guard: integer addition with no pointer type is not navigation.
    #[test]
    fn base_var_rejects_non_pointer_addition() {
        let mut b = CtreeBuilder::new();
        let int = b.intern_type(TypeValue {
            shape: TypeShape::Int {
                bytes: 4,
                signed: true,
            },
            size: Some(4),
        });
        let this = b.push_local(this_local_def("this", int));
        let v = b.var(int, this);
        let num = b.num(int, 4);
        let add = b.binary(int, BinaryOp::Add, v, num);
        let st = b.expression_statement(add);
        let block = b.block(vec![st]);
        let tree = b.finish(block);
        assert!(let None = base_var(&tree, add));
    }

    /// `GlobalRef` hashes by its fields, so it can key a `HashSet`.
    #[test]
    fn global_ref_hashes() {
        use std::collections::HashSet;

        let named = GlobalRef {
            address: Address::new_const(0x1000),
            name: Some("foo".into()),
        };
        let anon = GlobalRef {
            address: Address::new_const(0x2000),
            name: None,
        };
        let mut set = HashSet::new();
        set.insert(named.clone());
        set.insert(anon.clone());
        assert!(set.contains(&named));
        assert!(set.contains(&anon));
        assert!(!set.contains(&GlobalRef {
            address: Address::new_const(0x3000),
            name: None,
        }));
    }

    /// `Ord` sorts by `address` first, since it leads the field list.
    #[test]
    fn global_ref_ord_sorts_by_address() {
        let low = GlobalRef {
            address: Address::new_const(0x1000),
            name: Some("z".into()),
        };
        let high = GlobalRef {
            address: Address::new_const(0x2000),
            name: Some("a".into()),
        };
        let mut refs = vec![high.clone(), low.clone()];
        refs.sort();
        assert!(refs == vec![low, high]);
    }

    /// A `GlobalRef` round-trips through JSON.
    #[test]
    fn global_ref_serde_round_trips() {
        let global = GlobalRef {
            address: Address::new_const(0x1000),
            name: Some("foo".into()),
        };
        let json = serde_json::to_string(&global).unwrap();
        assert!(serde_json::from_str::<GlobalRef>(&json).unwrap() == global);
    }
}
