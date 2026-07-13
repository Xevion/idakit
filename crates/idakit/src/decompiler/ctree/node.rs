//! The node kinds of a decompiled function's tree: [`ExpressionKind`] and [`StatementKind`].
//!
//! Child links are arena handles ([`ExpressionId`]/[`StatementId`]), not boxes, so the tree is
//! flat, `Send`, and navigable in both directions (each [`ExpressionNode`]/[`StatementNode`] also
//! stores its `parent`). Operators are grouped (see [`BinaryOp`]/[`UnaryOp`]/[`AssignmentOp`]);
//! leaves carry their resolved value.

use super::ops::{AssignmentOp, BinaryOp, UnaryOp};
use crate::address::Address;
use crate::arena::Idx;
use crate::types::TypeId;

/// A typed handle into the tree's expression arena, naming an [`ExpressionNode`].
pub type ExpressionId = Idx<ExpressionNode>;
/// A typed handle into the tree's statement arena, naming a [`StatementNode`].
pub type StatementId = Idx<StatementNode>;

/// A reference to any node, an expression or a statement. Used for parent links and
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
            Self::Expression(e) => Some(e),
            Self::Statement(_) => None,
        }
    }

    /// The statement handle, or `None` if this refers to an expression.
    #[inline]
    #[must_use]
    pub fn as_statement(self) -> Option<StatementId> {
        match self {
            Self::Statement(s) => Some(s),
            Self::Expression(_) => None,
        }
    }

    /// Whether this refers to an expression.
    #[inline]
    #[must_use]
    pub fn is_expression(self) -> bool {
        matches!(self, Self::Expression(_))
    }

    /// Whether this refers to a statement.
    #[inline]
    #[must_use]
    pub fn is_statement(self) -> bool {
        matches!(self, Self::Statement(_))
    }
}

/// A typed handle into a decompiled function's lvar table, resolved via
/// [`Ctree::lvar`](super::Ctree::lvar).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[doc(alias("lvar_t"))]
pub struct LocalId(
    /// The variable's index in the lvar table.
    pub u32,
);

/// Where a local variable lives, as the decompiler placed it.
///
/// [`Register`](LocalLocation::Register) and [`Stack`](LocalLocation::Stack) cover essentially
/// every x86-64 local; the pair, register-relative, scattered, and static forms are artifacts of
/// other architectures' calling conventions (AArch64 register pairs, AAPCS struct-scatter, MIPS
/// and PPC register-relative), rare to absent on x86-64.
#[derive(Clone, PartialEq, Eq, Debug)]
#[doc(alias("argloc_t"))]
pub enum LocalLocation {
    /// In a single register, by number. A decompiler register location carries no in-register
    /// offset, so none is stored here.
    #[doc(alias("ALOC_REG1"))]
    Register(u32),
    /// Split across a register pair, the low half in `low` and the high half in `high`.
    /// Arises for values wider than one register on register-based ABIs; absent on x86-64.
    #[doc(alias("ALOC_REG2"))]
    RegisterPair {
        /// Register number holding the low half.
        low: u32,
        /// Register number holding the high half.
        high: u32,
    },
    /// On the stack, at this frame offset.
    #[doc(alias("ALOC_STACK"))]
    Stack(i64),
    /// Register-relative, at `[reg + offset]`. Uncommon.
    #[doc(alias("ALOC_RREL"))]
    RegisterRelative {
        /// Base register number.
        reg: u32,
        /// Byte offset added to the base register.
        offset: i64,
    },
    /// At a fixed global address. Uncommon for a local.
    #[doc(alias("ALOC_STATIC"))]
    Static(Address),
    /// Scattered across several register or stack fragments, each covering a byte range of the
    /// value. Arises from struct-by-value on register ABIs; effectively absent on x86-64.
    #[doc(alias("ALOC_DIST"))]
    Scattered(Vec<LocationPiece>),
    /// A processor-specific custom location idakit does not structure.
    #[doc(alias("ALOC_CUSTOM"))]
    Custom,
    /// No location assigned, since the decompiler left the variable unallocated.
    #[doc(alias("ALOC_NONE"))]
    Unallocated,
}

impl LocalLocation {
    /// Build from the facade's decoded location fields. `atype` selects the variant; the remaining
    /// fields form a union, so only the ones `atype` names are meaningful, and `pieces` is filled
    /// only for a scattered location.
    pub(crate) fn from_argloc(
        atype: u32,
        reg1: u32,
        reg2: u32,
        sval: i64,
        pieces: Vec<LocationPiece>,
    ) -> Self {
        match atype {
            0 => Self::Unallocated,
            1 => Self::Stack(sval),
            2 => Self::Scattered(pieces),
            3 => Self::Register(reg1),
            4 => Self::RegisterPair {
                low: reg1,
                high: reg2,
            },
            5 => Self::RegisterRelative {
                reg: reg1,
                offset: sval,
            },
            6 => Self::Static(Address::new_const(sval as u64)),
            // Custom locations are 7 or higher; no other location types are defined.
            _ => Self::Custom,
        }
    }
}

/// One fragment of a [`Scattered`](LocalLocation::Scattered) local, naming where it lives
/// and which byte range of the whole value it covers.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LocationPiece {
    /// Where this fragment lives: a register or stack slot, never itself scattered.
    pub location: LocalLocation,
    /// Byte offset of this fragment within the whole value.
    pub offset: u32,
    /// Byte size of this fragment.
    pub size: u32,
}

/// One local variable of a decompiled function: its name, resolved type, and role.
/// [`ExpressionKind::Var`] indexes the tree's lvar table to one of these.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(alias("lvar_t"))]
pub struct Local {
    /// The variable's name, as the decompiler named it.
    pub name: String,
    /// The variable's type, into the tree's [`TypeTable`](crate::types::TypeTable).
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

/// An expression node with its source address, resolved type, parent, and kind.
///
/// `address` is [`None`] for synthetic nodes the decompiler introduces with no backing
/// instruction; [`Option<Address>`](Address) niche-optimizes to a bare [`u64`].
#[derive(Clone, Debug, PartialEq)]
pub struct ExpressionNode {
    /// The backing instruction's address, or `None` for a synthetic node.
    pub address: Option<Address>,
    /// The expression's resolved type, into the tree's [`TypeTable`](crate::types::TypeTable).
    pub ty: TypeId,
    /// The parent node, or `None` for the root.
    pub parent: Option<NodeRef>,
    /// What this expression is.
    pub kind: ExpressionKind,
}

/// A statement node with its source address, parent, and kind.
///
/// `address` is [`None`] for synthetic nodes with no backing instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
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
/// A closed set covering the finalized decompiler tree. Extraction rejects an unmodelled node tag
/// rather than widening this, so a new expression kind in a later IDA is a deliberate, breaking
/// addition.
#[derive(Clone, Debug, PartialEq)]
#[doc(alias("ctype_t", "cexpr_t"))]
pub enum ExpressionKind {
    /// A binary operation, `x OP y`.
    #[doc(alias("cot_add", "cot_sub"))]
    Binary {
        /// The binary operator.
        op: BinaryOp,
        /// The left operand.
        x: ExpressionId,
        /// The right operand.
        y: ExpressionId,
    },
    /// A compound assignment, `x OP= y`.
    #[doc(alias("cot_asg"))]
    Assign {
        /// The compound-assignment operator.
        op: AssignmentOp,
        /// The assignment target.
        x: ExpressionId,
        /// The assigned value.
        y: ExpressionId,
    },
    /// A unary operation, `OP x` (or `x OP` for post-increment and post-decrement).
    #[doc(alias("cot_neg", "cot_lnot"))]
    Unary {
        /// The unary operator.
        op: UnaryOp,
        /// The operand.
        x: ExpressionId,
    },
    /// A conditional expression, `cond ? then_ : else_`.
    Ternary {
        /// The condition.
        cond: ExpressionId,
        /// The value when `cond` is true.
        then_: ExpressionId,
        /// The value when `cond` is false.
        else_: ExpressionId,
    },
    /// A function call, `callee(args...)`.
    #[doc(alias("cot_call"))]
    Call {
        /// The called expression.
        callee: ExpressionId,
        /// The arguments, in order.
        args: Vec<ExpressionId>,
    },
    /// An array index, `array[index]`.
    #[doc(alias("cot_idx"))]
    Index {
        /// The indexed expression.
        array: ExpressionId,
        /// The index expression.
        index: ExpressionId,
    },
    /// A member access through a value, `obj.field`.
    #[doc(alias("cot_memref"))]
    MemberRef {
        /// The aggregate expression.
        obj: ExpressionId,
        /// Offset of the member from the start of the aggregate, in **bytes**. Contrast
        /// [`TypeMember::bit_offset`](crate::types::TypeMember), in bits.
        byte_offset: u32,
    },
    /// A member access through a pointer, `obj->field`.
    #[doc(alias("cot_memptr"))]
    MemberPtr {
        /// The pointer-to-aggregate expression.
        obj: ExpressionId,
        /// Offset of the member from the start of the aggregate, in **bytes**. Contrast
        /// [`TypeMember::bit_offset`](crate::types::TypeMember), in bits.
        byte_offset: u32,
    },
    /// A cast, `(T)x`; the target type rides on the node.
    #[doc(alias("cot_cast"))]
    Cast {
        /// The cast operand.
        x: ExpressionId,
    },
    /// A pointer dereference, `*x`, reading `size` bytes.
    #[doc(alias("cot_ptr"))]
    Deref {
        /// The pointer expression.
        x: ExpressionId,
        /// The access size in bytes.
        size: u32,
    },
    /// A `sizeof(x)`.
    #[doc(alias("cot_sizeof"))]
    Sizeof(ExpressionId),
    /// An integer literal, as raw bits; signedness comes from the node's type.
    #[doc(alias("cot_num"))]
    Num(u64),
    /// A floating-point literal.
    ///
    /// `PartialEq` on `ExpressionKind` is structural, so `Fnum(NaN)` does not compare equal to
    /// itself (IEEE-754 `NaN != NaN`). This is an accepted caveat: IDA emits no NaN float
    /// literals, so no real node trips it.
    #[doc(alias("cot_fnum"))]
    Fnum(f64),
    /// A string literal.
    #[doc(alias("cot_str"))]
    Str(String),
    /// A reference to a global or static at `address`, with its symbol name when it has one.
    #[doc(alias("cot_obj"))]
    Obj {
        /// The global's address.
        address: Address,
        /// Its symbol name, if it has one.
        name: Option<String>,
    },
    /// A reference to a local variable.
    #[doc(alias("cot_var"))]
    Var(LocalId),
    /// A decompiler helper name, e.g. `__readfsqword`.
    #[doc(alias("cot_helper"))]
    Helper(String),
    /// A bare type in expression position, e.g. inside `sizeof`.
    #[doc(alias("cot_type"))]
    TypeExpression,
    /// An empty or absent expression.
    #[doc(alias("cot_empty"))]
    Empty,
    /// A statement embedded in an expression.
    ///
    /// Internal to the decompiler, never present in a finalized tree. Carried so materialization
    /// stays total rather than lossy, the one allowance instead of a catch-all.
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
    as_binary: Binary { op, x, y } => (BinaryOp, ExpressionId, ExpressionId) = (*op, *x, *y);
    /// `x OP= y`: the compound-assignment operator and both sides.
    as_assign: Assign { op, x, y } => (AssignmentOp, ExpressionId, ExpressionId) = (*op, *x, *y);
    /// `OP x`: the unary operator and its operand.
    as_unary: Unary { op, x } => (UnaryOp, ExpressionId) = (*op, *x);
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Case {
    /// The case's match values; empty for the `default` case.
    pub values: Vec<u64>,
    /// The statement run when the case matches.
    pub body: StatementId,
}

/// A statement kind. Child links are arena handles.
///
/// A closed set on the same terms as [`ExpressionKind`]: it covers the finalized decompiler tree,
/// and extraction rejects an unmodelled tag rather than folding it in here.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(alias("cinsn_t"))]
pub enum StatementKind {
    /// A block of statements, `{ ... }`.
    #[doc(alias("cit_block"))]
    Block(Vec<StatementId>),
    /// An expression statement, `expression;`.
    #[doc(alias("cit_expr"))]
    Expression(ExpressionId),
    /// A conditional, `if (cond) then_ [else else_]`.
    #[doc(alias("cit_if"))]
    If {
        /// The condition.
        cond: ExpressionId,
        /// The branch taken when `cond` is true.
        then_: StatementId,
        /// The `else` branch, if any.
        else_: Option<StatementId>,
    },
    /// A C-style `for` loop, `for (init; cond; step) body`.
    #[doc(alias("cit_for"))]
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
    /// A `while` loop, `while (cond) body`.
    #[doc(alias("cit_while"))]
    While {
        /// The loop condition.
        cond: ExpressionId,
        /// The loop body.
        body: StatementId,
    },
    /// A `do`/`while` loop, `do body while (cond)`.
    #[doc(alias("cit_do"))]
    Do {
        /// The loop body.
        body: StatementId,
        /// The loop condition.
        cond: ExpressionId,
    },
    /// A `switch`, `switch (expression) { cases }`.
    #[doc(alias("cit_switch"))]
    Switch {
        /// The switched-on expression.
        expression: ExpressionId,
        /// The cases, including any `default`.
        cases: Vec<Case>,
    },
    /// A `break;`.
    #[doc(alias("cit_break"))]
    Break,
    /// A `continue;`.
    #[doc(alias("cit_continue"))]
    Continue,
    /// A `return [expression];`.
    #[doc(alias("cit_return"))]
    Return(Option<ExpressionId>),
    /// A `goto label;`.
    #[doc(alias("cit_goto"))]
    Goto {
        /// The target label number.
        label: i32,
    },
    /// An inline-asm block, as the addresses of its instructions.
    #[doc(alias("cit_asm"))]
    Asm(Vec<Address>),
    /// A `try`/catch, `try body { catches }`.
    #[doc(alias("cit_try"))]
    Try {
        /// The guarded body.
        body: StatementId,
        /// The catch handlers.
        catches: Vec<StatementId>,
    },
    /// A `throw [expression];`.
    #[doc(alias("cit_throw"))]
    Throw(Option<ExpressionId>),
    /// An empty or absent statement.
    #[doc(alias("cit_empty"))]
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
                f(NodeRef::Expression(*x));
            }
            MemberRef { obj, .. } | MemberPtr { obj, .. } => f(NodeRef::Expression(*obj)),
            Ternary { cond, then_, else_ } => {
                f(NodeRef::Expression(*cond));
                f(NodeRef::Expression(*then_));
                f(NodeRef::Expression(*else_));
            }
            Call { callee, args } => {
                f(NodeRef::Expression(*callee));
                for a in args {
                    f(NodeRef::Expression(*a));
                }
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
            Block(statements) => {
                for s in statements {
                    f(NodeRef::Statement(*s));
                }
            }
            Expression(e) => f(NodeRef::Expression(*e)),
            If { cond, then_, else_ } => {
                f(NodeRef::Expression(*cond));
                f(NodeRef::Statement(*then_));
                if let Some(s) = else_ {
                    f(NodeRef::Statement(*s));
                }
            }
            For {
                init,
                cond,
                step,
                body,
            } => {
                if let Some(e) = init {
                    f(NodeRef::Expression(*e));
                }
                if let Some(e) = cond {
                    f(NodeRef::Expression(*e));
                }
                if let Some(e) = step {
                    f(NodeRef::Expression(*e));
                }
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
                for c in cases {
                    f(NodeRef::Statement(c.body));
                }
            }
            Return(e) | Throw(e) => {
                if let Some(x) = e {
                    f(NodeRef::Expression(*x));
                }
            }
            Try { body, catches } => {
                f(NodeRef::Statement(*body));
                for s in catches {
                    f(NodeRef::Statement(*s));
                }
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
                op: BinaryOp::Add,
                x: a,
                y: b
            }
            .as_binary()
                == Some((BinaryOp::Add, a, b))
        );
        assert!(
            ExpressionKind::Assign {
                op: AssignmentOp::Assign,
                x: a,
                y: b
            }
            .as_assign()
                == Some((AssignmentOp::Assign, a, b))
        );
        assert!(
            ExpressionKind::Unary {
                op: UnaryOp::Neg,
                x: a
            }
            .as_unary()
                == Some((UnaryOp::Neg, a))
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

    /// `from_argloc` maps each location discriminant to its variant, reading only the fields that
    /// discriminant selects, and folds custom locations (7 or higher) into `Custom`.
    #[test]
    fn from_argloc_maps_every_atype() {
        use LocalLocation::*;
        assert!(LocalLocation::from_argloc(0, 0, 0, 0, vec![]) == Unallocated);
        assert!(LocalLocation::from_argloc(1, 0, 0, -8, vec![]) == Stack(-8));
        assert!(LocalLocation::from_argloc(3, 5, 0, 0, vec![]) == Register(5));
        assert!(LocalLocation::from_argloc(4, 5, 6, 0, vec![]) == RegisterPair { low: 5, high: 6 });
        assert!(
            LocalLocation::from_argloc(5, 5, 0, 16, vec![])
                == RegisterRelative { reg: 5, offset: 16 }
        );
        assert!(
            LocalLocation::from_argloc(6, 0, 0, 0x1000, vec![])
                == Static(Address::new_const(0x1000))
        );
        // Custom is 7 or higher.
        assert!(LocalLocation::from_argloc(7, 0, 0, 0, vec![]) == Custom);
        assert!(LocalLocation::from_argloc(42, 0, 0, 0, vec![]) == Custom);

        // A scattered location carries its fragments verbatim.
        let piece = LocationPiece {
            location: Stack(16),
            offset: 0,
            size: 8,
        };
        assert!(
            LocalLocation::from_argloc(2, 0, 0, 0, vec![piece.clone()]) == Scattered(vec![piece])
        );
    }
}
