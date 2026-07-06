//! ctree node kinds: expressions ([`ExpressionKind`]) and statements ([`StatementKind`]).
//!
//! Mirrors IDA's `cot_*` / `cit_*` split. Child links are arena handles
//! ([`ExpressionId`]/[`StatementId`]), not boxes, so the tree is flat, `Send`, and navigable in
//! both directions (each [`ExpressionNode`]/[`StatementNode`] also stores its `parent`).
//! Operators are grouped (see [`BinOp`]/[`UnOp`]/[`AssignOp`]); leaves carry their
//! resolved value.

use super::ops::{AssignOp, BinOp, UnOp};
use crate::Address;
use crate::arena::Idx;
use crate::types::TypeId;

/// Handle to an [`ExpressionNode`].
pub type ExpressionId = Idx<ExpressionNode>;
/// Handle to a [`StatementNode`].
pub type StatementId = Idx<StatementNode>;

/// A reference to any node -- expression or statement. Used for parent links and
/// uniform navigation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum NodeRef {
    /// An expression node.
    Expression(ExpressionId),
    /// A statement node.
    Statement(StatementId),
}

impl NodeRef {
    /// The expression handle, or `None` if this refers to a statement.
    #[inline]
    #[must_use]
    pub fn as_expression(self) -> Option<ExpressionId> {
        match self {
            NodeRef::Expression(e) => Some(e),
            NodeRef::Statement(_) => None,
        }
    }

    /// The statement handle, or `None` if this refers to an expression.
    #[inline]
    #[must_use]
    pub fn as_statement(self) -> Option<StatementId> {
        match self {
            NodeRef::Statement(s) => Some(s),
            NodeRef::Expression(_) => None,
        }
    }

    /// Whether this refers to an expression.
    #[inline]
    #[must_use]
    pub fn is_expression(self) -> bool {
        matches!(self, NodeRef::Expression(_))
    }

    /// Whether this refers to a statement.
    #[inline]
    #[must_use]
    pub fn is_statement(self) -> bool {
        matches!(self, NodeRef::Statement(_))
    }
}

/// Index of a local variable in the decompiled function's lvar table
/// ([`Ctree::lvar`](super::Ctree::lvar)).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct LocalId(
    /// The variable's index in the lvar table.
    pub u32,
);

/// Where a local variable lives, as the decompiler placed it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LocalLocation {
    /// In a register (the microcode register number).
    Register(u32),
    /// On the stack, at this frame offset.
    Stack(i64),
    /// Scattered or otherwise not a single register/stack slot.
    Other,
}

/// One local variable of a decompiled function: its name, resolved type, and role.
/// [`ExpressionKind::Var`] indexes the tree's lvar table to one of these.
#[derive(Clone, Debug, PartialEq)]
pub struct Local {
    /// The variable's name, as the decompiler named it.
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
    /// Where the decompiler placed the variable (register, stack, or scattered).
    pub location: LocalLocation,
}

/// An expression node: its source address, type, parent, and kind.
///
/// `address` is `None` for synthetic nodes the decompiler introduces with no backing
/// instruction (`Option<Address>` is niche-optimized to a bare `u64`; see [`Address`]).
#[derive(Clone, Debug, PartialEq)]
pub struct ExpressionNode {
    /// The backing instruction's address, or `None` for a synthetic node.
    pub address: Option<Address>,
    /// The expression's resolved type, into the tree's [`TypeTable`](super::TypeTable).
    pub ty: TypeId,
    /// The parent node, or `None` for the root.
    pub parent: Option<NodeRef>,
    /// What this expression is.
    pub kind: ExpressionKind,
}

/// A statement node: its source address, parent, and kind. `address` is `None` for synthetic
/// nodes with no backing instruction.
#[derive(Clone, Debug, PartialEq)]
pub struct StatementNode {
    /// The backing instruction's address, or `None` for a synthetic node.
    pub address: Option<Address>,
    /// The parent node, or `None` for the root.
    pub parent: Option<NodeRef>,
    /// What this statement is.
    pub kind: StatementKind,
}

/// An expression kind. Child links are arena handles; leaves carry their value.
///
/// A closed mirror of the finalized (`CMAT_FINAL`) ctree's `cot_*` set: extraction rejects an
/// unmodeled tag (`UnknownExpressionTag`) rather than widening this. A new node kind in a later
/// IDA is a deliberate, breaking addition, since idakit pins to one minor.
#[derive(Clone, Debug, PartialEq)]
pub enum ExpressionKind {
    /// `x OP y`
    Binary {
        /// The binary operator.
        op: BinOp,
        /// The left operand.
        x: ExpressionId,
        /// The right operand.
        y: ExpressionId,
    },
    /// `x OP= y`
    Assign {
        /// The compound-assignment operator.
        op: AssignOp,
        /// The assignment target.
        x: ExpressionId,
        /// The assigned value.
        y: ExpressionId,
    },
    /// `OP x` (or `x OP` for post-inc/dec)
    Unary {
        /// The unary operator.
        op: UnOp,
        /// The operand.
        x: ExpressionId,
    },
    /// `cond ? then_ : else_`
    Ternary {
        /// The condition.
        cond: ExpressionId,
        /// The value when `cond` is true.
        then_: ExpressionId,
        /// The value when `cond` is false.
        else_: ExpressionId,
    },
    /// `callee(args...)`
    Call {
        /// The called expression.
        callee: ExpressionId,
        /// The arguments, in order.
        args: Vec<ExpressionId>,
    },
    /// `array[index]`
    Index {
        /// The indexed expression.
        array: ExpressionId,
        /// The index expression.
        index: ExpressionId,
    },
    /// `obj.field`, the member at `byte_offset`
    MemberRef {
        /// The aggregate expression.
        obj: ExpressionId,
        /// Offset of the member from the start of the aggregate, in **bytes** (from IDA's
        /// `cot_memref.m`). Contrast [`TypeMember::bit_offset`](super::TypeMember), in bits.
        byte_offset: u32,
    },
    /// `obj->field`, the member at `byte_offset`
    MemberPtr {
        /// The pointer-to-aggregate expression.
        obj: ExpressionId,
        /// Offset of the member from the start of the aggregate, in **bytes** (from IDA's
        /// `cot_memptr.m`). Contrast [`TypeMember::bit_offset`](super::TypeMember), in bits.
        byte_offset: u32,
    },
    /// `(T)x` -- the target type is carried on the node (added with the type arena).
    Cast {
        /// The cast operand.
        x: ExpressionId,
    },
    /// `*x`, dereferencing `size` bytes
    Deref {
        /// The pointer expression.
        x: ExpressionId,
        /// The access size in bytes.
        size: u32,
    },
    /// `sizeof(x)`
    Sizeof(ExpressionId),
    /// integer literal (raw bits; signedness comes from the node's type)
    Num(u64),
    /// floating-point literal.
    ///
    /// `PartialEq` on `ExpressionKind` is structural, so `Fnum(NaN)` does not compare equal to
    /// itself (IEEE-754 `NaN != NaN`). Accepted as a known caveat: IDA does not emit NaN
    /// float literals, so no real node trips it.
    Fnum(f64),
    /// string literal
    Str(String),
    /// reference to a global/static at `address`, carrying its symbol name when it has one
    Obj {
        /// The global's address.
        address: Address,
        /// Its symbol name, if it has one.
        name: Option<String>,
    },
    /// reference to a local variable
    Var(LocalId),
    /// an arbitrary decompiler helper name, e.g. `__readfsqword`
    Helper(String),
    /// a bare type used in an expression position (e.g. inside `sizeof`)
    TypeExpression,
    /// empty/absent expression
    Empty,
    /// a statement embedded in an expression -- internal to the decompiler, never
    /// present in a finalized (`CMAT_FINAL`) tree. Carried so materialization is
    /// total rather than lossy (the one allowance instead of a catch-all).
    Internal,
}

/// Generate `as_*` accessors that match one [`ExpressionKind`] variant and project its payload,
/// returning `None` otherwise. Each line gives the method, variant pattern, return type, and
/// how to build it; the macro adds only the `if let`/`Some`/`None` scaffolding.
macro_rules! expression_accessors {
    ( $( $(#[$m:meta])* $fn:ident : $variant:ident $pat:tt => $ret:ty = $build:expr ; )* ) => {
        impl ExpressionKind {
            $(
                $(#[$m])*
                #[inline]
                #[must_use]
                pub fn $fn(&self) -> Option<$ret> {
                    if let ExpressionKind::$variant $pat = self {
                        Some($build)
                    } else {
                        None
                    }
                }
            )*
        }
    };
}

expression_accessors! {
    /// `x OP y`: the operator and both operands.
    as_binary: Binary { op, x, y } => (BinOp, ExpressionId, ExpressionId) = (*op, *x, *y);
    /// `x OP= y`: the compound-assignment operator and both sides.
    as_assign: Assign { op, x, y } => (AssignOp, ExpressionId, ExpressionId) = (*op, *x, *y);
    /// `OP x`: the unary operator and its operand.
    as_unary: Unary { op, x } => (UnOp, ExpressionId) = (*op, *x);
    /// A ternary's condition and both branches, in order.
    as_ternary: Ternary { cond, then_, else_ } => (ExpressionId, ExpressionId, ExpressionId) = (*cond, *then_, *else_);
    /// `callee(args...)`: the callee and its argument slice.
    as_call: Call { callee, args } => (ExpressionId, &[ExpressionId]) = (*callee, args.as_slice());
    /// `array[index]`.
    as_index: Index { array, index } => (ExpressionId, ExpressionId) = (*array, *index);
    /// `obj.field`: the object and the member's byte offset.
    as_member_ref: MemberRef { obj, byte_offset } => (ExpressionId, u32) = (*obj, *byte_offset);
    /// `obj->field`: the object and the member's byte offset.
    as_member_ptr: MemberPtr { obj, byte_offset } => (ExpressionId, u32) = (*obj, *byte_offset);
    /// `(T)x`: the operand (the target type rides on the node).
    as_cast: Cast { x } => ExpressionId = *x;
    /// `*x`: the operand and the access size in bytes.
    as_deref: Deref { x, size } => (ExpressionId, u32) = (*x, *size);
    /// `sizeof(x)`: the operand.
    as_sizeof: Sizeof(x) => ExpressionId = *x;
    /// An integer literal's raw bits.
    as_num: Num(v) => u64 = *v;
    /// A floating-point literal's value.
    as_fnum: Fnum(v) => f64 = *v;
    /// The local variable a `Var` names.
    as_var: Var(v) => LocalId = *v;
    /// A string literal's text.
    as_str: Str(s) => &str = s.as_str();
    /// A global/static reference: its address and symbol name (if it has one).
    as_obj: Obj { address, name } => (Address, Option<&str>) = (*address, name.as_deref());
    /// A decompiler helper's name, e.g. `__readfsqword`.
    as_helper: Helper(s) => &str = s.as_str();
}

/// One `case` of a `switch`: its values (empty = `default`) and body.
#[derive(Clone, Debug, PartialEq)]
pub struct Case {
    /// The case's match values; empty for the `default` case.
    pub values: Vec<u64>,
    /// The statement run when the case matches.
    pub body: StatementId,
}

/// A statement kind. Child links are arena handles.
///
/// A closed mirror of the finalized ctree's `cit_*` set, on the same terms as
/// [`ExpressionKind`]: unmodeled tags are rejected at extraction, not folded in here.
#[derive(Clone, Debug, PartialEq)]
pub enum StatementKind {
    /// `{ ... }`
    Block(Vec<StatementId>),
    /// `expression;`
    Expression(ExpressionId),
    /// `if (cond) then_ [else else_]`
    If {
        /// The condition.
        cond: ExpressionId,
        /// The branch taken when `cond` is true.
        then_: StatementId,
        /// The `else` branch, if any.
        else_: Option<StatementId>,
    },
    /// `for (init; cond; step) body`
    For {
        /// The initializer, if any.
        init: Option<ExpressionId>,
        /// The loop condition, if any.
        cond: Option<ExpressionId>,
        /// The per-iteration step, if any.
        step: Option<ExpressionId>,
        /// The loop body.
        body: StatementId,
    },
    /// `while (cond) body`
    While {
        /// The loop condition.
        cond: ExpressionId,
        /// The loop body.
        body: StatementId,
    },
    /// `do body while (cond)`
    Do {
        /// The loop body.
        body: StatementId,
        /// The loop condition.
        cond: ExpressionId,
    },
    /// `switch (expression) { cases }`
    Switch {
        /// The switched-on expression.
        expression: ExpressionId,
        /// The cases, including any `default`.
        cases: Vec<Case>,
    },
    /// `break;`
    Break,
    /// `continue;`
    Continue,
    /// `return [expression];`
    Return(Option<ExpressionId>),
    /// `goto label;`
    Goto {
        /// The target label number.
        label: i32,
    },
    /// an inline-asm block, as the addresses of its instructions
    Asm(Vec<Address>),
    /// `try body { catches }`
    Try {
        /// The guarded body.
        body: StatementId,
        /// The catch handlers.
        catches: Vec<StatementId>,
    },
    /// `throw [expression];`
    Throw(Option<ExpressionId>),
    /// empty/absent statement
    Empty,
}

impl ExpressionKind {
    /// Visit this expression's child nodes in source order. All children of an
    /// expression are themselves expressions. Push-based so navigation never has to
    /// heap-allocate a child list (see [`Ctree::descendants`](super::Ctree::descendants)).
    pub(crate) fn for_each_child(&self, mut f: impl FnMut(NodeRef)) {
        use ExpressionKind::{
            Assign, Binary, Call, Cast, Deref, Index, MemberPtr, MemberRef, Sizeof, Ternary, Unary,
        };
        match self {
            Binary { x, y, .. } | Assign { x, y, .. } => {
                f(NodeRef::Expression(*x));
                f(NodeRef::Expression(*y));
            }
            Index { array, index } => {
                f(NodeRef::Expression(*array));
                f(NodeRef::Expression(*index));
            }
            Unary { x, .. } | Cast { x } | Deref { x, .. } | Sizeof(x) => {
                f(NodeRef::Expression(*x))
            }
            MemberRef { obj, .. } | MemberPtr { obj, .. } => f(NodeRef::Expression(*obj)),
            Ternary { cond, then_, else_ } => {
                f(NodeRef::Expression(*cond));
                f(NodeRef::Expression(*then_));
                f(NodeRef::Expression(*else_));
            }
            Call { callee, args } => {
                f(NodeRef::Expression(*callee));
                args.iter().for_each(|a| f(NodeRef::Expression(*a)));
            }
            // Leaves carry no child handles.
            Self::Num(_)
            | Self::Fnum(_)
            | Self::Str(_)
            | Self::Obj { .. }
            | Self::Var(_)
            | Self::Helper(_)
            | Self::TypeExpression
            | Self::Empty
            | Self::Internal => {}
        }
    }
}

impl StatementKind {
    /// Visit this statement's child nodes in source order. Push-based to avoid
    /// allocating a child list on every navigation step.
    pub(crate) fn for_each_child(&self, mut f: impl FnMut(NodeRef)) {
        use StatementKind::{Block, Do, Expression, For, If, Return, Switch, Throw, Try, While};
        match self {
            Block(statements) => statements.iter().for_each(|s| f(NodeRef::Statement(*s))),
            Expression(e) => f(NodeRef::Expression(*e)),
            If { cond, then_, else_ } => {
                f(NodeRef::Expression(*cond));
                f(NodeRef::Statement(*then_));
                else_.iter().for_each(|s| f(NodeRef::Statement(*s)));
            }
            For {
                init,
                cond,
                step,
                body,
            } => {
                init.iter().for_each(|e| f(NodeRef::Expression(*e)));
                cond.iter().for_each(|e| f(NodeRef::Expression(*e)));
                step.iter().for_each(|e| f(NodeRef::Expression(*e)));
                f(NodeRef::Statement(*body));
            }
            While { cond, body } => {
                f(NodeRef::Expression(*cond));
                f(NodeRef::Statement(*body));
            }
            Do { body, cond } => {
                f(NodeRef::Statement(*body));
                f(NodeRef::Expression(*cond));
            }
            Switch { expression, cases } => {
                f(NodeRef::Expression(*expression));
                cases.iter().for_each(|c| f(NodeRef::Statement(c.body)));
            }
            Return(e) | Throw(e) => e.iter().for_each(|x| f(NodeRef::Expression(*x))),
            Try { body, catches } => {
                f(NodeRef::Statement(*body));
                catches.iter().for_each(|s| f(NodeRef::Statement(*s)));
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

    fn e(n: u32) -> ExpressionId {
        Idx::from_raw(n)
    }

    /// Each accessor projects its own variant and yields `None` for any other.
    #[test]
    fn expression_accessors_project_their_variant() {
        let (a, b, c) = (e(0), e(1), e(2));

        assert!(
            ExpressionKind::Binary {
                op: BinOp::Add,
                x: a,
                y: b
            }
            .as_binary()
                == Some((BinOp::Add, a, b))
        );
        assert!(
            ExpressionKind::Assign {
                op: AssignOp::Assign,
                x: a,
                y: b
            }
            .as_assign()
                == Some((AssignOp::Assign, a, b))
        );
        assert!(
            ExpressionKind::Unary {
                op: UnOp::Neg,
                x: a
            }
            .as_unary()
                == Some((UnOp::Neg, a))
        );
        assert!(
            ExpressionKind::Ternary {
                cond: a,
                then_: b,
                else_: c
            }
            .as_ternary()
                == Some((a, b, c))
        );
        assert!(ExpressionKind::Index { array: a, index: b }.as_index() == Some((a, b)));
        assert!(
            ExpressionKind::MemberRef {
                obj: a,
                byte_offset: 8
            }
            .as_member_ref()
                == Some((a, 8))
        );
        assert!(
            ExpressionKind::MemberPtr {
                obj: a,
                byte_offset: 8
            }
            .as_member_ptr()
                == Some((a, 8))
        );
        assert!(ExpressionKind::Cast { x: a }.as_cast() == Some(a));
        assert!(ExpressionKind::Deref { x: a, size: 4 }.as_deref() == Some((a, 4)));
        assert!(ExpressionKind::Sizeof(a).as_sizeof() == Some(a));
        assert!(ExpressionKind::Num(7).as_num() == Some(7));
        assert!(ExpressionKind::Fnum(3.5).as_fnum() == Some(3.5));
        assert!(ExpressionKind::Var(LocalId(3)).as_var() == Some(LocalId(3)));
        assert!(ExpressionKind::Str("hi".into()).as_str() == Some("hi"));
        assert!(ExpressionKind::Helper("h".into()).as_helper() == Some("h"));

        let call = ExpressionKind::Call {
            callee: a,
            args: vec![b, c],
        };
        assert!(let Some((callee, args)) = call.as_call());
        assert!(callee == a && args.len() == 2 && args[0] == b && args[1] == c);

        let obj = ExpressionKind::Obj {
            address: Address::new_const(0x10),
            name: Some("g".into()),
        };
        assert!(obj.as_obj() == Some((Address::new_const(0x10), Some("g"))));

        // A wrong-variant query is `None`, not a panic.
        assert!(let None = ExpressionKind::Num(1).as_binary());
    }

    /// `NodeRef` projects to one handle kind and rejects the other.
    #[test]
    fn node_ref_projections() {
        let expression = NodeRef::Expression(e(0));
        let statement = NodeRef::Statement(Idx::from_raw(0));
        assert!(expression.as_expression() == Some(e(0)));
        assert!(let None = expression.as_statement());
        assert!(expression.is_expression() && !expression.is_statement());
        assert!(statement.as_statement() == Some(Idx::from_raw(0)));
        assert!(statement.is_statement() && !statement.is_expression());
    }
}
