//! ctree node kinds: expressions ([`Cexpr`]) and statements ([`Cinsn`]).
//!
//! Mirrors IDA's `cot_*` / `cit_*` split. Child links are arena handles
//! ([`ExprId`]/[`StmtId`]), not boxes, so the tree is flat, `Send`, and navigable in
//! both directions (each [`ExprNode`]/[`StmtNode`] also stores its `parent`).
//! Operators are grouped (see [`BinOp`]/[`UnOp`]/[`AssignOp`]); leaves carry their
//! resolved value.

use super::arena::Idx;
use super::ops::{AssignOp, BinOp, UnOp};
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

/// Index of a local variable in the decompiled function's lvar table.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct LvarId(pub u32);

/// An expression node: its source address, parent, and kind.
#[derive(Clone, Debug)]
pub struct ExprNode {
    pub ea: Ea,
    pub parent: Option<NodeRef>,
    pub kind: Cexpr,
}

/// A statement node: its source address, parent, and kind.
#[derive(Clone, Debug)]
pub struct StmtNode {
    pub ea: Ea,
    pub parent: Option<NodeRef>,
    pub kind: Cinsn,
}

/// An expression kind. Child links are arena handles; leaves carry their value.
#[derive(Clone, Debug)]
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
    /// `obj.field`, the member at byte `offset`
    MemberRef { obj: ExprId, offset: u32 },
    /// `obj->field`, the member at byte `offset`
    MemberPtr { obj: ExprId, offset: u32 },
    /// `(T)x` — the target type is carried on the node (added with the type arena).
    Cast { x: ExprId },
    /// `*x`, dereferencing `size` bytes
    Deref { x: ExprId, size: u32 },
    /// `sizeof(x)`
    Sizeof(ExprId),
    /// integer literal (raw bits; signedness comes from the node's type)
    Num(u64),
    /// floating-point literal
    Fnum(f64),
    /// string literal
    Str(String),
    /// reference to a global/static at this address
    Obj(Ea),
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

/// One `case` of a `switch`: its values (empty = `default`) and body.
#[derive(Clone, Debug)]
pub struct Case {
    pub values: Vec<u64>,
    pub body: StmtId,
}

/// A statement kind. Child links are arena handles.
#[derive(Clone, Debug)]
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
            | Self::Obj(_)
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
