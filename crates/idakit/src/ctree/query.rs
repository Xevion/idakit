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
use super::ops::{AssignOp, UnOp};
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

/// Follow `e` through place/address wrappers (`MemberRef`/`MemberPtr`/`Deref`/`&`/`Cast`)
/// down to the root [`Cexpr::Var`], accumulating member byte offsets. Returns the local
/// and the total offset from its base, or `None` if the expression isn't rooted at a
/// variable.
pub fn base_var(tree: &Ctree, e: ExprId) -> Option<(LvarId, i64)> {
    match &tree.expr(e).kind {
        Cexpr::Var(v) => Some((*v, 0)),
        Cexpr::MemberRef { obj, byte_offset } | Cexpr::MemberPtr { obj, byte_offset } => {
            base_var(tree, *obj).map(|(v, off)| (v, off + i64::from(*byte_offset)))
        }
        // `*p`, `&p`, and `(T)p` keep the same root and offset — they're not navigation.
        Cexpr::Deref { x, .. } | Cexpr::Cast { x } | Cexpr::Unary { op: UnOp::Ref, x } => {
            base_var(tree, *x)
        }
        _ => None,
    }
}

/// Follow `e` through `Cast`/`&` down to a [`Cexpr::Obj`], returning the global it names.
pub fn global_target(tree: &Ctree, e: ExprId) -> Option<GlobalRef> {
    match &tree.expr(e).kind {
        Cexpr::Obj { ea, name } => Some(GlobalRef {
            ea: *ea,
            name: name.clone(),
        }),
        Cexpr::Cast { x } | Cexpr::Unary { op: UnOp::Ref, x } => global_target(tree, *x),
        _ => None,
    }
}

/// Every vtable install in the tree: a plain assignment of a global's address into a
/// `this`-relative slot.
pub fn vtable_installs(tree: &Ctree) -> Vec<VtableInstall> {
    let Some(this) = tree.this_lvar() else {
        return Vec::new();
    };
    tree.exprs()
        .filter_map(|(_, node)| {
            let Cexpr::Assign {
                op: AssignOp::Assign,
                x,
                y,
            } = &node.kind
            else {
                return None;
            };
            let (v, off) = base_var(tree, *x)?;
            if v != this {
                return None;
            }
            let g = global_target(tree, *y)?;
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
    tree.exprs()
        .filter_map(|(_, node)| {
            let Cexpr::Call { callee, args } = &node.kind else {
                return None;
            };
            let g = global_target(tree, *callee)?;
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
    use crate::ctree::node::{Cinsn, Lvar, LvarLocation};
    use crate::ctree::tree::CtreeBuilder;
    use crate::ctree::types::{TypeData, TypeKind};
    use assert2::assert;

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
        let none = None;

        // primary vtable install: Assign( MemberRef{0}(MemberPtr{0}(this)), Cast(Obj) )
        let v0 = b.expr(none, t, Cexpr::Var(this));
        let mp0 = b.expr(
            none,
            t,
            Cexpr::MemberPtr {
                obj: v0,
                byte_offset: 0,
            },
        );
        let mr0 = b.expr(
            none,
            t,
            Cexpr::MemberRef {
                obj: mp0,
                byte_offset: 0,
            },
        );
        let o1 = b.expr(
            none,
            t,
            Cexpr::Obj {
                ea: Ea::new_const(0x1000),
                name: Some("vtbl_primary".into()),
            },
        );
        let c1 = b.expr(none, t, Cexpr::Cast { x: o1 });
        let a1 = b.expr(
            none,
            t,
            Cexpr::Assign {
                op: AssignOp::Assign,
                x: mr0,
                y: c1,
            },
        );

        // subobject install: Assign( MemberRef{0}(MemberPtr{16}(this)), Cast(&Obj) )
        let v1 = b.expr(none, t, Cexpr::Var(this));
        let mp16 = b.expr(
            none,
            t,
            Cexpr::MemberPtr {
                obj: v1,
                byte_offset: 16,
            },
        );
        let mr0b = b.expr(
            none,
            t,
            Cexpr::MemberRef {
                obj: mp16,
                byte_offset: 0,
            },
        );
        let o2 = b.expr(
            none,
            t,
            Cexpr::Obj {
                ea: Ea::new_const(0x2000),
                name: Some("vtbl_sub".into()),
            },
        );
        let r2 = b.expr(
            none,
            t,
            Cexpr::Unary {
                op: UnOp::Ref,
                x: o2,
            },
        );
        let c2 = b.expr(none, t, Cexpr::Cast { x: r2 });
        let a2 = b.expr(
            none,
            t,
            Cexpr::Assign {
                op: AssignOp::Assign,
                x: mr0b,
                y: c2,
            },
        );

        // base ctor call: Call(Obj(BaseCtor), [Var(this)])
        let v2 = b.expr(none, t, Cexpr::Var(this));
        let oc1 = b.expr(
            none,
            t,
            Cexpr::Obj {
                ea: Ea::new_const(0x3000),
                name: Some("BaseCtor".into()),
            },
        );
        let call1 = b.expr(
            none,
            t,
            Cexpr::Call {
                callee: oc1,
                args: vec![v2],
            },
        );

        // subobject ctor call: Call(Obj(OtherCtor), [&this->Other])
        let v3 = b.expr(none, t, Cexpr::Var(this));
        let mp16b = b.expr(
            none,
            t,
            Cexpr::MemberPtr {
                obj: v3,
                byte_offset: 16,
            },
        );
        let r4 = b.expr(
            none,
            t,
            Cexpr::Unary {
                op: UnOp::Ref,
                x: mp16b,
            },
        );
        let oc2 = b.expr(
            none,
            t,
            Cexpr::Obj {
                ea: Ea::new_const(0x4000),
                name: Some("OtherCtor".into()),
            },
        );
        let call2 = b.expr(
            none,
            t,
            Cexpr::Call {
                callee: oc2,
                args: vec![r4],
            },
        );

        // field init: Assign( MemberPtr{28}(this), Num(4) ) — not a vtable install
        let v4 = b.expr(none, t, Cexpr::Var(this));
        let mp28 = b.expr(
            none,
            t,
            Cexpr::MemberPtr {
                obj: v4,
                byte_offset: 28,
            },
        );
        let num = b.expr(none, t, Cexpr::Num(4));
        let a3 = b.expr(
            none,
            t,
            Cexpr::Assign {
                op: AssignOp::Assign,
                x: mp28,
                y: num,
            },
        );

        let stmts: Vec<_> = [a1, a2, call1, call2, a3]
            .into_iter()
            .map(|e| b.stmt(none, Cinsn::Expr(e)))
            .collect();
        let block = b.stmt(none, Cinsn::Block(stmts));
        b.finish(block)
    }

    #[test]
    fn this_lvar_is_the_first_arg() {
        let tree = ctor_tree();
        assert!(tree.this_lvar() == Some(LvarId(0)));
    }

    #[test]
    fn base_var_threads_offset_through_member_and_address_ops() {
        let tree = ctor_tree();
        // Find the `&this->Other` argument of the OtherCtor call and resolve it.
        let (_, call) = tree
            .exprs()
            .find(|(_, n)| {
                matches!(&n.kind, Cexpr::Call { callee, .. }
                    if matches!(&tree.expr(*callee).kind, Cexpr::Obj { name: Some(n), .. } if n == "OtherCtor"))
            })
            .expect("OtherCtor call");
        assert!(let Cexpr::Call { args, .. } = &call.kind);
        assert!(base_var(&tree, args[0]) == Some((LvarId(0), 16)));
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
