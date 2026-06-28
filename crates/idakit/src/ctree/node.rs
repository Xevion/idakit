//! ctree node kinds: expressions ([`Cexpr`]) and statements ([`Cinsn`]).
//!
//! Mirrors IDA's `cot_*` / `cit_*` split. Child links are arena handles
//! ([`ExprId`]/[`StmtId`]), not boxes, so the tree is flat, `Send`, and navigable in
//! both directions (each [`ExprNode`]/[`StmtNode`] also stores its `parent`).
//! Operators are grouped (see [`BinOp`]/[`UnOp`]/[`AssignOp`]); leaves carry their
//! resolved value.

use super::arena::Idx;
use super::ops::{AssignOp, BinOp, UnOp};
use super::types::TypeId;
use crate::Ea;

/// Handle to an [`ExprNode`].
pub type ExprId = Idx<ExprNode>;
/// Handle to a [`StmtNode`].
pub type StmtId = Idx<StmtNode>;

/// A reference to any node — expression or statement. Used for parent links and
/// uniform navigation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum NodeRef {
    Expr(ExprId),
    Stmt(StmtId),
}

impl NodeRef {
    /// The expression handle, or `None` if this refers to a statement.
    #[inline]
    #[must_use]
    pub fn as_expr(self) -> Option<ExprId> {
        match self {
            NodeRef::Expr(e) => Some(e),
            NodeRef::Stmt(_) => None,
        }
    }

    /// The statement handle, or `None` if this refers to an expression.
    #[inline]
    #[must_use]
    pub fn as_stmt(self) -> Option<StmtId> {
        match self {
            NodeRef::Stmt(s) => Some(s),
            NodeRef::Expr(_) => None,
        }
    }

    /// Whether this refers to an expression.
    #[inline]
    #[must_use]
    pub fn is_expr(self) -> bool {
        matches!(self, NodeRef::Expr(_))
    }

    /// Whether this refers to a statement.
    #[inline]
    #[must_use]
    pub fn is_stmt(self) -> bool {
        matches!(self, NodeRef::Stmt(_))
    }
}

/// Index of a local variable in the decompiled function's lvar table
/// ([`Ctree::lvar`](super::Ctree::lvar)).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct LvarId(pub u32);

/// Where a local variable lives, as the decompiler placed it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LvarLocation {
    /// In a register (the microcode register number).
    Register(u32),
    /// On the stack, at this frame offset.
    Stack(i64),
    /// Scattered or otherwise not a single register/stack slot.
    Other,
}

/// One local variable of a decompiled function: its name, resolved type, and role.
/// [`Cexpr::Var`] indexes the tree's lvar table to one of these.
#[derive(Clone, Debug, PartialEq)]
pub struct Lvar {
    pub name: String,
    /// The variable's type, into the tree's [`TypeTable`](super::TypeTable).
    pub ty: TypeId,
    /// A function parameter.
    pub is_arg: bool,
    /// The synthesized return-value variable.
    pub is_result: bool,
    /// Taken by-reference somewhere in the function.
    pub is_byref: bool,
    /// Size in bytes.
    pub width: u32,
    /// The user's comment on the variable, if any.
    pub comment: Option<String>,
    pub location: LvarLocation,
}

/// An expression node: its source address, type, parent, and kind.
///
/// `ea` is `None` for synthetic nodes the decompiler introduces with no backing
/// instruction (`Option<Ea>` is niche-optimized to a bare `u64`; see [`Ea`]).
#[derive(Clone, Debug, PartialEq)]
pub struct ExprNode {
    pub ea: Option<Ea>,
    /// The expression's resolved type, into the tree's [`TypeTable`](super::TypeTable).
    pub ty: TypeId,
    pub parent: Option<NodeRef>,
    pub kind: Cexpr,
}

/// A statement node: its source address, parent, and kind. `ea` is `None` for synthetic
/// nodes with no backing instruction.
#[derive(Clone, Debug, PartialEq)]
pub struct StmtNode {
    pub ea: Option<Ea>,
    pub parent: Option<NodeRef>,
    pub kind: Cinsn,
}

/// An expression kind. Child links are arena handles; leaves carry their value.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Cexpr {
    /// `x OP y`
    Binary { op: BinOp, x: ExprId, y: ExprId },
    /// `x OP= y`
    Assign { op: AssignOp, x: ExprId, y: ExprId },
    /// `OP x` (or `x OP` for post-inc/dec)
    Unary { op: UnOp, x: ExprId },
    /// `cond ? then_ : else_`
    Ternary {
        cond: ExprId,
        then_: ExprId,
        else_: ExprId,
    },
    /// `callee(args...)`
    Call { callee: ExprId, args: Vec<ExprId> },
    /// `array[index]`
    Index { array: ExprId, index: ExprId },
    /// `obj.field`, the member at `byte_offset`
    MemberRef {
        obj: ExprId,
        /// Offset of the member from the start of the aggregate, in **bytes** (from IDA's
        /// `cot_memref.m`). Contrast [`TypeMember::bit_offset`](super::TypeMember), in bits.
        byte_offset: u32,
    },
    /// `obj->field`, the member at `byte_offset`
    MemberPtr {
        obj: ExprId,
        /// Offset of the member from the start of the aggregate, in **bytes** (from IDA's
        /// `cot_memptr.m`). Contrast [`TypeMember::bit_offset`](super::TypeMember), in bits.
        byte_offset: u32,
    },
    /// `(T)x` — the target type is carried on the node (added with the type arena).
    Cast { x: ExprId },
    /// `*x`, dereferencing `size` bytes
    Deref { x: ExprId, size: u32 },
    /// `sizeof(x)`
    Sizeof(ExprId),
    /// integer literal (raw bits; signedness comes from the node's type)
    Num(u64),
    /// floating-point literal.
    ///
    /// `PartialEq` on `Cexpr` is structural, so `Fnum(NaN)` does not compare equal to
    /// itself (IEEE-754 `NaN != NaN`). Accepted as a known caveat: IDA does not emit NaN
    /// float literals, so no real node trips it.
    Fnum(f64),
    /// string literal
    Str(String),
    /// reference to a global/static at `ea`, carrying its symbol name when it has one
    Obj { ea: Ea, name: Option<String> },
    /// reference to a local variable
    Var(LvarId),
    /// an arbitrary decompiler helper name, e.g. `__readfsqword`
    Helper(String),
    /// a bare type used in an expression position (e.g. inside `sizeof`)
    TypeExpr,
    /// empty/absent expression
    Empty,
    /// a statement embedded in an expression — internal to the decompiler, never
    /// present in a finalized (`CMAT_FINAL`) tree. Carried so materialization is
    /// total rather than lossy (the one allowance instead of a catch-all).
    Internal,
}

/// Generate `as_*` accessors that match one [`Cexpr`] variant and project its payload,
/// returning `None` otherwise. Each line gives the method, variant pattern, return type, and
/// how to build it; the macro adds only the `if let`/`Some`/`None` scaffolding.
macro_rules! expr_accessors {
    ( $( $(#[$m:meta])* $fn:ident : $variant:ident $pat:tt => $ret:ty = $build:expr ; )* ) => {
        impl Cexpr {
            $(
                $(#[$m])*
                #[inline]
                #[must_use]
                pub fn $fn(&self) -> Option<$ret> {
                    if let Cexpr::$variant $pat = self {
                        Some($build)
                    } else {
                        None
                    }
                }
            )*
        }
    };
}

expr_accessors! {
    /// `x OP y`: the operator and both operands.
    as_binary: Binary { op, x, y } => (BinOp, ExprId, ExprId) = (*op, *x, *y);
    /// `x OP= y`: the compound-assignment operator and both sides.
    as_assign: Assign { op, x, y } => (AssignOp, ExprId, ExprId) = (*op, *x, *y);
    /// `OP x`: the unary operator and its operand.
    as_unary: Unary { op, x } => (UnOp, ExprId) = (*op, *x);
    /// A ternary's condition and both branches, in order.
    as_ternary: Ternary { cond, then_, else_ } => (ExprId, ExprId, ExprId) = (*cond, *then_, *else_);
    /// `callee(args...)`: the callee and its argument slice.
    as_call: Call { callee, args } => (ExprId, &[ExprId]) = (*callee, args.as_slice());
    /// `array[index]`.
    as_index: Index { array, index } => (ExprId, ExprId) = (*array, *index);
    /// `obj.field`: the object and the member's byte offset.
    as_member_ref: MemberRef { obj, byte_offset } => (ExprId, u32) = (*obj, *byte_offset);
    /// `obj->field`: the object and the member's byte offset.
    as_member_ptr: MemberPtr { obj, byte_offset } => (ExprId, u32) = (*obj, *byte_offset);
    /// `(T)x`: the operand (the target type rides on the node).
    as_cast: Cast { x } => ExprId = *x;
    /// `*x`: the operand and the access size in bytes.
    as_deref: Deref { x, size } => (ExprId, u32) = (*x, *size);
    /// `sizeof(x)`: the operand.
    as_sizeof: Sizeof(x) => ExprId = *x;
    /// An integer literal's raw bits.
    as_num: Num(v) => u64 = *v;
    /// A floating-point literal's value.
    as_fnum: Fnum(v) => f64 = *v;
    /// The local variable a `Var` names.
    as_var: Var(v) => LvarId = *v;
    /// A string literal's text.
    as_str: Str(s) => &str = s.as_str();
    /// A global/static reference: its address and symbol name (if it has one).
    as_obj: Obj { ea, name } => (Ea, Option<&str>) = (*ea, name.as_deref());
    /// A decompiler helper's name, e.g. `__readfsqword`.
    as_helper: Helper(s) => &str = s.as_str();
}

/// One `case` of a `switch`: its values (empty = `default`) and body.
#[derive(Clone, Debug, PartialEq)]
pub struct Case {
    pub values: Vec<u64>,
    pub body: StmtId,
}

/// A statement kind. Child links are arena handles.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Cinsn {
    /// `{ ... }`
    Block(Vec<StmtId>),
    /// `expr;`
    Expr(ExprId),
    /// `if (cond) then_ [else else_]`
    If {
        cond: ExprId,
        then_: StmtId,
        else_: Option<StmtId>,
    },
    /// `for (init; cond; step) body`
    For {
        init: Option<ExprId>,
        cond: Option<ExprId>,
        step: Option<ExprId>,
        body: StmtId,
    },
    /// `while (cond) body`
    While { cond: ExprId, body: StmtId },
    /// `do body while (cond)`
    Do { body: StmtId, cond: ExprId },
    /// `switch (expr) { cases }`
    Switch { expr: ExprId, cases: Vec<Case> },
    /// `break;`
    Break,
    /// `continue;`
    Continue,
    /// `return [expr];`
    Return(Option<ExprId>),
    /// `goto label;`
    Goto { label: i32 },
    /// an inline-asm block, as the addresses of its instructions
    Asm(Vec<Ea>),
    /// `try body { catches }`
    Try { body: StmtId, catches: Vec<StmtId> },
    /// `throw [expr];`
    Throw(Option<ExprId>),
    /// empty/absent statement
    Empty,
}

impl Cexpr {
    /// Visit this expression's child nodes in source order. All children of an
    /// expression are themselves expressions. Push-based so navigation never has to
    /// heap-allocate a child list (see [`Ctree::descendants`](super::Ctree::descendants)).
    pub(crate) fn for_each_child(&self, mut f: impl FnMut(NodeRef)) {
        use Cexpr::{
            Assign, Binary, Call, Cast, Deref, Index, MemberPtr, MemberRef, Sizeof, Ternary, Unary,
        };
        match self {
            Binary { x, y, .. } | Assign { x, y, .. } => {
                f(NodeRef::Expr(*x));
                f(NodeRef::Expr(*y));
            }
            Index { array, index } => {
                f(NodeRef::Expr(*array));
                f(NodeRef::Expr(*index));
            }
            Unary { x, .. } | Cast { x } | Deref { x, .. } | Sizeof(x) => f(NodeRef::Expr(*x)),
            MemberRef { obj, .. } | MemberPtr { obj, .. } => f(NodeRef::Expr(*obj)),
            Ternary { cond, then_, else_ } => {
                f(NodeRef::Expr(*cond));
                f(NodeRef::Expr(*then_));
                f(NodeRef::Expr(*else_));
            }
            Call { callee, args } => {
                f(NodeRef::Expr(*callee));
                args.iter().for_each(|a| f(NodeRef::Expr(*a)));
            }
            // Leaves carry no child handles.
            Self::Num(_)
            | Self::Fnum(_)
            | Self::Str(_)
            | Self::Obj { .. }
            | Self::Var(_)
            | Self::Helper(_)
            | Self::TypeExpr
            | Self::Empty
            | Self::Internal => {}
        }
    }
}

impl Cinsn {
    /// Visit this statement's child nodes in source order. Push-based to avoid
    /// allocating a child list on every navigation step.
    pub(crate) fn for_each_child(&self, mut f: impl FnMut(NodeRef)) {
        use Cinsn::{Block, Do, Expr, For, If, Return, Switch, Throw, Try, While};
        match self {
            Block(stmts) => stmts.iter().for_each(|s| f(NodeRef::Stmt(*s))),
            Expr(e) => f(NodeRef::Expr(*e)),
            If { cond, then_, else_ } => {
                f(NodeRef::Expr(*cond));
                f(NodeRef::Stmt(*then_));
                else_.iter().for_each(|s| f(NodeRef::Stmt(*s)));
            }
            For {
                init,
                cond,
                step,
                body,
            } => {
                init.iter().for_each(|e| f(NodeRef::Expr(*e)));
                cond.iter().for_each(|e| f(NodeRef::Expr(*e)));
                step.iter().for_each(|e| f(NodeRef::Expr(*e)));
                f(NodeRef::Stmt(*body));
            }
            While { cond, body } => {
                f(NodeRef::Expr(*cond));
                f(NodeRef::Stmt(*body));
            }
            Do { body, cond } => {
                f(NodeRef::Stmt(*body));
                f(NodeRef::Expr(*cond));
            }
            Switch { expr, cases } => {
                f(NodeRef::Expr(*expr));
                cases.iter().for_each(|c| f(NodeRef::Stmt(c.body)));
            }
            Return(e) | Throw(e) => e.iter().for_each(|x| f(NodeRef::Expr(*x))),
            Try { body, catches } => {
                f(NodeRef::Stmt(*body));
                catches.iter().for_each(|s| f(NodeRef::Stmt(*s)));
            }
            // No child handles.
            Self::Break | Self::Continue | Self::Goto { .. } | Self::Asm(_) | Self::Empty => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    fn e(n: u32) -> ExprId {
        Idx::from_raw(n)
    }

    /// Each accessor projects its own variant and yields `None` for any other.
    #[test]
    fn expr_accessors_project_their_variant() {
        let (a, b, c) = (e(0), e(1), e(2));

        assert!(
            Cexpr::Binary {
                op: BinOp::Add,
                x: a,
                y: b
            }
            .as_binary()
                == Some((BinOp::Add, a, b))
        );
        assert!(
            Cexpr::Assign {
                op: AssignOp::Assign,
                x: a,
                y: b
            }
            .as_assign()
                == Some((AssignOp::Assign, a, b))
        );
        assert!(
            Cexpr::Unary {
                op: UnOp::Neg,
                x: a
            }
            .as_unary()
                == Some((UnOp::Neg, a))
        );
        assert!(
            Cexpr::Ternary {
                cond: a,
                then_: b,
                else_: c
            }
            .as_ternary()
                == Some((a, b, c))
        );
        assert!(Cexpr::Index { array: a, index: b }.as_index() == Some((a, b)));
        assert!(
            Cexpr::MemberRef {
                obj: a,
                byte_offset: 8
            }
            .as_member_ref()
                == Some((a, 8))
        );
        assert!(
            Cexpr::MemberPtr {
                obj: a,
                byte_offset: 8
            }
            .as_member_ptr()
                == Some((a, 8))
        );
        assert!(Cexpr::Cast { x: a }.as_cast() == Some(a));
        assert!(Cexpr::Deref { x: a, size: 4 }.as_deref() == Some((a, 4)));
        assert!(Cexpr::Sizeof(a).as_sizeof() == Some(a));
        assert!(Cexpr::Num(7).as_num() == Some(7));
        assert!(Cexpr::Fnum(3.5).as_fnum() == Some(3.5));
        assert!(Cexpr::Var(LvarId(3)).as_var() == Some(LvarId(3)));
        assert!(Cexpr::Str("hi".into()).as_str() == Some("hi"));
        assert!(Cexpr::Helper("h".into()).as_helper() == Some("h"));

        let call = Cexpr::Call {
            callee: a,
            args: vec![b, c],
        };
        assert!(let Some((callee, args)) = call.as_call());
        assert!(callee == a && args.len() == 2 && args[0] == b && args[1] == c);

        let obj = Cexpr::Obj {
            ea: Ea::new_const(0x10),
            name: Some("g".into()),
        };
        assert!(obj.as_obj() == Some((Ea::new_const(0x10), Some("g"))));

        // A wrong-variant query is `None`, not a panic.
        assert!(let None = Cexpr::Num(1).as_binary());
    }

    /// `NodeRef` projects to one handle kind and rejects the other.
    #[test]
    fn node_ref_projections() {
        let expr = NodeRef::Expr(e(0));
        let stmt = NodeRef::Stmt(Idx::from_raw(0));
        assert!(expr.as_expr() == Some(e(0)));
        assert!(let None = expr.as_stmt());
        assert!(expr.is_expr() && !expr.is_stmt());
        assert!(stmt.as_stmt() == Some(Idx::from_raw(0)));
        assert!(stmt.is_stmt() && !stmt.is_expr());
    }
}
