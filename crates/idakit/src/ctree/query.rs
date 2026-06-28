//! Structural queries over a [`Ctree`] — the analysis layer above the bare node arenas.
//!
//! These exist because the patterns that matter for C++ reverse engineering — a
//! constructor installing a vtable, a base/subobject constructor call — are awkward to
//! spell out by hand against raw nodes, and IDA's own decompiler already resolved the
//! register dataflow a disassembly-level pass would have to reconstruct. The matchers
//! here are deliberately *tolerant*: they look **through** the address/place wrapper
//! nodes the decompiler emits (`Cast`, `&`, `*`, member access) rather than matching one
//! exact shape, because the exact shape varies with optimization level and whether IDA
//! has typed the `this` pointer.
//!
//! The two primitives, [`base_var`] and [`global_target`], do that look-through and are
//! public so callers can compose their own matchers; [`vtable_installs`] and
//! [`this_arg_calls`] are the constructor-analysis matchers built from them.

use super::node::{Cexpr, ExprId, LvarId};
use super::ops::{AssignOp, BinOp, UnOp};
use super::tree::Ctree;
use crate::Ea;

/// A reference to a global/static the decompiler named, as surfaced by [`global_target`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalRef {
    pub ea: Ea,
    pub name: Option<String>,
}

/// A store of a global's address into a `this`-relative slot — a vtable install in a
/// constructor (`this->__vftable = &vtbl`). `this_offset` is the byte offset within the
/// object (0 = primary base, non-zero = a multiple-inheritance subobject).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VtableInstall {
    pub this_offset: i64,
    pub vtable: Ea,
    pub vtable_name: Option<String>,
}

/// A direct call whose first argument is `this`-relative — a base or subobject
/// constructor call (`Base::Base(this)`, `Other::Other(&this->Other)`). `this_offset` is
/// the byte offset of the subobject the call applies to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThisCall {
    pub callee: Ea,
    pub callee_name: Option<String>,
    pub this_offset: i64,
}

/// Peel cast `(T)x` and address-of `&x` wrappers, which rename nothing, down to the first
/// expression that is neither. Does not look through a dereference `*x`, which names the
/// pointee: whether to follow that is the matcher's call. Shared by [`base_var`] and
/// [`global_target`], and public so custom matchers peel the same way.
pub fn strip_casts(tree: &Ctree, mut e: ExprId) -> ExprId {
    loop {
        match tree.kind(e) {
            Cexpr::Cast { x } | Cexpr::Unary { op: UnOp::Ref, x } => e = *x,
            _ => return e,
        }
    }
}

/// Follow `e` through place/address wrappers (`MemberRef`/`MemberPtr`/`Deref`/`&`/`Cast`)
/// and pointer arithmetic down to the root [`Cexpr::Var`], accumulating the byte offset.
/// Returns the local and the total offset from its base, or `None` if the expression isn't
/// rooted at a variable.
///
/// Both the typed shape — `this->Other` as `MemberRef`/`MemberPtr` once IDA has the struct
/// layout — and the untyped shape — `*((_QWORD *)this + 2)` or `(char *)this + 16` as raw
/// pointer arithmetic — resolve to the same `(this, 16)`. The untyped form is what shows up
/// in stripped binaries, so threading it is what makes these matchers useful there.
pub fn base_var(tree: &Ctree, e: ExprId) -> Option<(LvarId, i64)> {
    // Casts and `&` rename nothing; peel them first so the match below sees the place node.
    let e = strip_casts(tree, e);
    match tree.kind(e) {
        Cexpr::Var(v) => Some((*v, 0)),
        Cexpr::MemberRef { obj, byte_offset } | Cexpr::MemberPtr { obj, byte_offset } => {
            base_var(tree, *obj).map(|(v, off)| (v, off + i64::from(*byte_offset)))
        }
        // `*p` keeps the same root and offset; the load itself is not navigation.
        Cexpr::Deref { x, .. } => base_var(tree, *x),
        // Pointer arithmetic `base + k`: the byte delta is the constant index scaled by the
        // pointee size of `base`, exactly as C scales it — so a `_QWORD*` index of 2 and a
        // `char*` index of 16 both advance 16 bytes. The `pointee_size` guard means plain
        // integer addition (no pointer type) is not mistaken for navigation.
        Cexpr::Binary {
            op: BinOp::Add,
            x,
            y,
        } => {
            let (base, k) = match (tree.kind(*x), tree.kind(*y)) {
                (_, Cexpr::Num(k)) => (*x, *k),
                (Cexpr::Num(k), _) => (*y, *k),
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
fn pointee_size(tree: &Ctree, e: ExprId) -> Option<i64> {
    let elem = tree.type_of(tree.expr(e).ty).kind.pointee()?;
    tree.type_of(elem).size.map(|s| s as i64)
}

/// Follow `e` through `Cast`/`&` down to a [`Cexpr::Obj`], returning the global it names.
pub fn global_target(tree: &Ctree, e: ExprId) -> Option<GlobalRef> {
    let (ea, name) = tree.kind(strip_casts(tree, e)).as_obj()?;
    Some(GlobalRef {
        ea,
        name: name.map(str::to_owned),
    })
}

/// Every vtable install in the tree: a plain assignment of a global's address into a
/// `this`-relative slot.
pub fn vtable_installs(tree: &Ctree) -> Vec<VtableInstall> {
    let Some(this) = tree.this_lvar() else {
        return Vec::new();
    };
    tree.assigns()
        .filter_map(|(_, op, x, y)| {
            if op != AssignOp::Assign {
                return None;
            }
            let (v, off) = base_var(tree, x)?;
            if v != this {
                return None;
            }
            let g = global_target(tree, y)?;
            Some(VtableInstall {
                this_offset: off,
                vtable: g.ea,
                vtable_name: g.name,
            })
        })
        .collect()
}

/// Every direct call whose first argument is `this`-relative — base/subobject constructor
/// calls and other `this`-threading calls.
pub fn this_arg_calls(tree: &Ctree) -> Vec<ThisCall> {
    let Some(this) = tree.this_lvar() else {
        return Vec::new();
    };
    tree.calls()
        .filter_map(|(_, callee, args)| {
            let g = global_target(tree, callee)?;
            let (v, off) = base_var(tree, *args.first()?)?;
            if v != this {
                return None;
            }
            Some(ThisCall {
                callee: g.ea,
                callee_name: g.name,
                this_offset: off,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctree::node::{Lvar, LvarLocation};
    use crate::ctree::tree::CtreeBuilder;
    use crate::ctree::types::{TypeData, TypeKind};
    use assert2::assert;
    use rstest::rstest;

    fn ty(b: &mut CtreeBuilder) -> crate::ctree::TypeId {
        b.intern_type(TypeData {
            kind: TypeKind::Unknown,
            size: None,
        })
    }

    fn this_lvar_def(name: &str, t: crate::ctree::TypeId) -> Lvar {
        Lvar {
            name: name.into(),
            ty: t,
            is_arg: true,
            is_result: false,
            is_byref: false,
            width: 8,
            comment: None,
            location: LvarLocation::Register(0),
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
        let this = b.push_lvar(this_lvar_def("this", t));

        // primary vtable install: this->_vptr = (..)&vtbl_primary  (offset 0)
        let v0 = b.var(t, this);
        let mp0 = b.member_ptr(t, v0, 0);
        let mr0 = b.member_ref(t, mp0, 0);
        let o1 = b.obj(t, Ea::new_const(0x1000), Some("vtbl_primary"));
        let c1 = b.cast(t, o1);
        let a1 = b.assign(t, AssignOp::Assign, mr0, c1);

        // subobject install: this->Other._vptr = (..)&vtbl_sub  (offset 16)
        let v1 = b.var(t, this);
        let mp16 = b.member_ptr(t, v1, 16);
        let mr0b = b.member_ref(t, mp16, 0);
        let o2 = b.obj(t, Ea::new_const(0x2000), Some("vtbl_sub"));
        let r2 = b.unary(t, UnOp::Ref, o2);
        let c2 = b.cast(t, r2);
        let a2 = b.assign(t, AssignOp::Assign, mr0b, c2);

        // base ctor call: BaseCtor(this)  (offset 0)
        let v2 = b.var(t, this);
        let oc1 = b.obj(t, Ea::new_const(0x3000), Some("BaseCtor"));
        let call1 = b.call_expr(t, oc1, vec![v2]);

        // subobject ctor call: OtherCtor(&this->Other)  (offset 16)
        let v3 = b.var(t, this);
        let mp16b = b.member_ptr(t, v3, 16);
        let r4 = b.unary(t, UnOp::Ref, mp16b);
        let oc2 = b.obj(t, Ea::new_const(0x4000), Some("OtherCtor"));
        let call2 = b.call_expr(t, oc2, vec![r4]);

        // field init: this->d = 4  (NOT a vtable install)
        let v4 = b.var(t, this);
        let mp28 = b.member_ptr(t, v4, 28);
        let num = b.num(t, 4);
        let a3 = b.assign(t, AssignOp::Assign, mp28, num);

        let stmts: Vec<_> = [a1, a2, call1, call2, a3]
            .into_iter()
            .map(|e| b.expr_stmt(e))
            .collect();
        let block = b.block(stmts);
        b.finish(block)
    }

    #[test]
    fn this_lvar_is_the_first_arg() {
        let tree = ctor_tree();
        assert!(tree.this_lvar() == Some(LvarId(0)));
    }

    /// Peels `(T)x` and `&x`, but stops at a dereference (a load names a different object).
    #[test]
    fn strip_casts_peels_cast_and_ref_but_stops_at_deref() {
        let mut b = CtreeBuilder::new();
        let t = ty(&mut b);
        let obj = b.obj(t, Ea::new_const(0x10), None);
        let deref = b.deref(t, obj, 8);
        let cast = b.cast(t, deref);
        let st = b.expr_stmt(cast);
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
                matches!(tree.kind(*callee), Cexpr::Obj { name: Some(n), .. } if n == "OtherCtor")
            })
            .expect("OtherCtor call");
        assert!(base_var(&tree, args[0]) == Some((LvarId(0), 16)));
    }

    /// Untyped pointer arithmetic threads to the same offset a member access would: the
    /// constant index is scaled by the pointee size, so `(_QWORD *)this + 2`,
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
        let elem = b.intern_type(TypeData {
            kind: TypeKind::Int {
                bytes: elem_bytes,
                signed: false,
            },
            size: Some(u64::from(elem_bytes)),
        });
        let ptr = b.intern_type(TypeData {
            kind: TypeKind::Ptr(elem),
            size: Some(8),
        });
        let this = b.push_lvar(this_lvar_def("this", ptr));
        let v = b.var(ptr, this);
        let cast = b.cast(ptr, v);
        let num = b.num(elem, index);
        let add = b.binary(ptr, BinOp::Add, cast, num);
        // The install/arg shapes wrap the arithmetic in a `*(...)` or `(T)(...)`; resolving
        // through that wrapper is the whole point.
        let deref = b.deref(elem, add, u32::from(elem_bytes));
        let st = b.expr_stmt(deref);
        let block = b.block(vec![st]);
        let tree = b.finish(block);
        assert!(base_var(&tree, deref) == Some((this, expect)));
    }

    /// The `pointee_size` guard: integer addition with no pointer type is not navigation.
    #[test]
    fn base_var_rejects_non_pointer_addition() {
        let mut b = CtreeBuilder::new();
        let int = b.intern_type(TypeData {
            kind: TypeKind::Int {
                bytes: 4,
                signed: true,
            },
            size: Some(4),
        });
        let this = b.push_lvar(this_lvar_def("this", int));
        let v = b.var(int, this);
        let num = b.num(int, 4);
        let add = b.binary(int, BinOp::Add, v, num);
        let st = b.expr_stmt(add);
        let block = b.block(vec![st]);
        let tree = b.finish(block);
        assert!(let None = base_var(&tree, add));
    }

    #[test]
    fn vtable_installs_finds_both_and_skips_field_init() {
        let tree = ctor_tree();
        let mut installs = vtable_installs(&tree);
        installs.sort_by_key(|i| i.this_offset);
        assert!(
            installs
                == vec![
                    VtableInstall {
                        this_offset: 0,
                        vtable: Ea::new_const(0x1000),
                        vtable_name: Some("vtbl_primary".into()),
                    },
                    VtableInstall {
                        this_offset: 16,
                        vtable: Ea::new_const(0x2000),
                        vtable_name: Some("vtbl_sub".into()),
                    },
                ]
        );
    }

    #[test]
    fn this_arg_calls_finds_base_and_subobject_ctors() {
        let tree = ctor_tree();
        let mut calls = this_arg_calls(&tree);
        calls.sort_by_key(|c| c.this_offset);
        assert!(
            calls
                == vec![
                    ThisCall {
                        callee: Ea::new_const(0x3000),
                        callee_name: Some("BaseCtor".into()),
                        this_offset: 0,
                    },
                    ThisCall {
                        callee: Ea::new_const(0x4000),
                        callee_name: Some("OtherCtor".into()),
                        this_offset: 16,
                    },
                ]
        );
    }
}
