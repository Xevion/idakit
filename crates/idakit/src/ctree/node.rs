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
