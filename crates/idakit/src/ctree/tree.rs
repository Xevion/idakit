//! [`Ctree`]: a decompiled function's ctree, as owned interned arenas plus the root
//! statement. Built through [`CtreeBuilder`], which wires every node's `parent` link
//! once the tree is complete.

use super::node::{
    ExpressionId, ExpressionKind, ExpressionNode, Local, LocalId, NodeRef, StatementId,
    StatementKind, StatementNode,
};
use super::ops::{AssignOp, BinOp, UnOp};
use crate::Address;
use crate::arena::Arena;
use crate::types::{TypeBuilder, TypeData, TypeId, TypeTable};

/// Visit `node`'s children, dispatching to the right arena. Shared by every navigation
/// path (read-only walks and the build-time parent pass) so the expression/statement split lives
/// in one place.
#[inline]
fn for_each_child(
    expressions: &Arena<ExpressionNode>,
    statements: &Arena<StatementNode>,
    node: NodeRef,
    f: impl FnMut(NodeRef),
) {
    match node {
        NodeRef::Expression(id) => expressions[id].kind.for_each_child(f),
        NodeRef::Statement(id) => statements[id].kind.for_each_child(f),
    }
}

/// A decompiled function's ctree. The root is always a block statement.
///
/// Owned and `Send`: materialized on the kernel thread, then analyzed anywhere. A
/// read-only analysis snapshot -- there is no in-place mutation, and it does not track
/// the live database, so it goes stale if the function is re-decompiled. Writing back to
/// IDA is a separate concern, not routed through these handles.
///
/// Real trees come from decompiling a function ([`Idb::decompile`](crate::Idb::decompile));
/// [`CtreeBuilder`] builds one directly, with no kernel, for testing matchers against a
/// known shape:
///
/// ```
/// use idakit::Address;
/// use idakit::ctree::{CtreeBuilder, Local, LocalLocation, TypeData, TypeKind};
///
/// let mut b = CtreeBuilder::new();
/// let ty = b.intern_type(TypeData {
///     kind: TypeKind::Unknown,
///     size: None,
/// });
/// let arg = b.push_lvar(Local {
///     name: "a".into(),
///     ty,
///     is_arg: true,
///     is_result: false,
///     is_byref: false,
///     width: 8,
///     comment: None,
///     location: LocalLocation::Register(0),
/// });
///
/// // `foo(a);`
/// let a = b.var(ty, arg);
/// let foo = b.obj(ty, Address::new_const(0x1000), Some("foo"));
/// let call = b.call_expression(ty, foo, vec![a]);
/// let stmt = b.expression_statement(call);
/// let block = b.block(vec![stmt]);
/// let tree = b.finish(block);
///
/// // Whole-tree scans find the call and the local reference without walking the tree shape.
/// assert_eq!(
///     tree.calls().collect::<Vec<_>>(),
///     vec![(call, foo, [a].as_slice())]
/// );
/// assert_eq!(tree.vars().map(|(_, v)| v).collect::<Vec<_>>(), vec![arg]);
/// ```
#[derive(Debug)]
pub struct Ctree {
    expressions: Arena<ExpressionNode>,
    statements: Arena<StatementNode>,
    types: TypeTable,
    lvars: Vec<Local>,
    root: StatementId,
}

impl Ctree {
    /// The root statement (a block).
    #[inline]
    #[must_use]
    pub fn root(&self) -> StatementId {
        self.root
    }

    /// The expression node behind a handle.
    #[inline]
    #[must_use]
    pub fn expression(&self, id: ExpressionId) -> &ExpressionNode {
        &self.expressions[id]
    }

    /// The statement node behind a handle.
    #[inline]
    #[must_use]
    pub fn statement(&self, id: StatementId) -> &StatementNode {
        &self.statements[id]
    }

    /// The expression *kind* behind a handle: shorthand for [`expression(id)`](Self::expression)`.kind`,
    /// the form matchers want when projecting with the [`ExpressionKind`] `as_*` accessors.
    #[inline]
    #[must_use]
    pub fn kind(&self, id: ExpressionId) -> &ExpressionKind {
        &self.expressions[id].kind
    }

    /// The statement *kind* behind a handle: shorthand for [`statement(id)`](Self::statement)`.kind`.
    #[inline]
    #[must_use]
    pub fn statement_kind(&self, id: StatementId) -> &StatementKind {
        &self.statements[id].kind
    }

    /// The type behind a handle (e.g. an [`ExpressionNode::ty`]).
    #[inline]
    #[must_use]
    pub fn type_of(&self, id: TypeId) -> &TypeData {
        self.types.get(id)
    }

    /// The local variable a [`ExpressionKind::Var`] refers to.
    #[inline]
    #[must_use]
    pub fn lvar(&self, id: LocalId) -> &Local {
        &self.lvars[id.0 as usize]
    }

    /// Every local variable of the function, in lvar-index order.
    pub fn lvars(&self) -> impl ExactSizeIterator<Item = &Local> {
        self.lvars.iter()
    }

    /// The first argument local -- the implicit `this` in a member function, or simply the
    /// first parameter otherwise. `None` for a function that takes no arguments. A pure
    /// structural accessor: it reads the lvar table's argument flags and makes no
    /// assumption about calling convention.
    #[must_use]
    pub fn this_lvar(&self) -> Option<LocalId> {
        self.lvars
            .iter()
            .position(|lv| lv.is_arg)
            .map(|i| LocalId(i as u32))
    }

    /// Every expression node, flat, in allocation order -- for whole-tree scans like
    /// "find all calls" that don't need the tree shape.
    pub fn expressions(&self) -> impl ExactSizeIterator<Item = (ExpressionId, &ExpressionNode)> {
        self.expressions.iter()
    }

    /// Every statement node, flat, in allocation order.
    pub fn statements(&self) -> impl ExactSizeIterator<Item = (StatementId, &StatementNode)> {
        self.statements.iter()
    }

    /// Every call in the tree as `(node, callee, args)` -- the whole-tree scan behind
    /// "find every call" without re-spelling the [`as_call`](ExpressionKind::as_call) filter.
    pub fn calls(&self) -> impl Iterator<Item = (ExpressionId, ExpressionId, &[ExpressionId])> {
        self.expressions()
            .filter_map(|(id, node)| node.kind.as_call().map(|(callee, args)| (id, callee, args)))
    }

    /// Every assignment in the tree as `(node, op, lhs, rhs)`.
    pub fn assigns(
        &self,
    ) -> impl Iterator<Item = (ExpressionId, AssignOp, ExpressionId, ExpressionId)> {
        self.expressions()
            .filter_map(|(id, node)| node.kind.as_assign().map(|(op, x, y)| (id, op, x, y)))
    }

    /// Every local-variable reference in the tree as `(node, lvar)`.
    pub fn vars(&self) -> impl Iterator<Item = (ExpressionId, LocalId)> {
        self.expressions()
            .filter_map(|(id, node)| node.kind.as_var().map(|v| (id, v)))
    }

    /// Every interned type, flat.
    pub fn types(&self) -> impl ExactSizeIterator<Item = (TypeId, &TypeData)> {
        self.types.iter()
    }

    /// The first expression node whose source address is `address`, or `None` if none is.
    /// Several nodes can share one address; this returns the first in allocation order and
    /// [`items_at`](Self::items_at) yields them all.
    #[must_use]
    pub fn expression_at(&self, address: Address) -> Option<ExpressionId> {
        self.expressions()
            .find(|(_, node)| node.address == Some(address))
            .map(|(id, _)| id)
    }

    /// The first statement node whose source address is `address`, or `None`.
    #[must_use]
    pub fn statement_at(&self, address: Address) -> Option<StatementId> {
        self.statements()
            .find(|(_, node)| node.address == Some(address))
            .map(|(id, _)| id)
    }

    /// Every node -- expression then statement -- whose source address is `address`, in
    /// allocation order. The flat, address-keyed counterpart to the structural
    /// [`descendants`](Self::descendants) walk: it answers "what did the decompiler place at
    /// this instruction?" without navigating the tree.
    pub fn items_at(&self, address: Address) -> impl Iterator<Item = NodeRef> + '_ {
        let expressions = self
            .expressions()
            .filter(move |(_, node)| node.address == Some(address))
            .map(|(id, _)| NodeRef::Expression(id));
        let statements = self
            .statements()
            .filter(move |(_, node)| node.address == Some(address))
            .map(|(id, _)| NodeRef::Statement(id));
        expressions.chain(statements)
    }

    /// This node's parent, or `None` for the root.
    #[inline]
    #[must_use]
    pub fn parent(&self, node: NodeRef) -> Option<NodeRef> {
        match node {
            NodeRef::Expression(id) => self.expressions[id].parent,
            NodeRef::Statement(id) => self.statements[id].parent,
        }
    }

    /// This node's direct children, in source order.
    #[must_use]
    pub fn children(&self, node: NodeRef) -> Vec<NodeRef> {
        let mut v = Vec::new();
        for_each_child(&self.expressions, &self.statements, node, |c| v.push(c));
        v
    }

    /// Visit each direct child without allocating -- the push-based form that
    /// [`children`](Self::children) buffers into a `Vec`.
    pub fn children_for_each(&self, node: NodeRef, f: impl FnMut(NodeRef)) {
        for_each_child(&self.expressions, &self.statements, node, f);
    }

    /// A pre-order walk of `node` and all its descendants (the node itself first).
    #[must_use]
    pub fn descendants(&self, node: NodeRef) -> Descendants<'_> {
        Descendants {
            tree: self,
            stack: vec![node],
        }
    }

    /// Like [`descendants`](Self::descendants) but yielding only the expression handles,
    /// skipping statements.
    pub fn expression_descendants(&self, node: NodeRef) -> impl Iterator<Item = ExpressionId> + '_ {
        self.descendants(node).filter_map(NodeRef::as_expression)
    }
}

/// Pre-order depth-first iterator over a subtree; see [`Ctree::descendants`].
pub struct Descendants<'a> {
    tree: &'a Ctree,
    stack: Vec<NodeRef>,
}

impl Iterator for Descendants<'_> {
    type Item = NodeRef;

    fn next(&mut self) -> Option<NodeRef> {
        let node = self.stack.pop()?;
        // Push children straight onto the stack (no intermediate child list), then
        // reverse just that suffix so the first child is popped -- and visited -- next.
        let base = self.stack.len();
        for_each_child(&self.tree.expressions, &self.tree.statements, node, |c| {
            self.stack.push(c);
        });
        self.stack[base..].reverse();
        Some(node)
    }
}

/// Builds a [`Ctree`]: allocate nodes (children first, since a parent references its
/// children's handles), then [`finish`](CtreeBuilder::finish) to wire parent links.
#[derive(Debug)]
pub struct CtreeBuilder {
    expressions: Arena<ExpressionNode>,
    statements: Arena<StatementNode>,
    types: TypeBuilder,
    lvars: Vec<Local>,
}

impl CtreeBuilder {
    /// An empty builder. Allocate nodes children-first, then [`finish`](Self::finish).
    #[must_use]
    pub fn new() -> Self {
        Self {
            expressions: Arena::new(),
            statements: Arena::new(),
            types: TypeBuilder::new(),
            lvars: Vec::new(),
        }
    }

    /// The type builder, for the walk's type callbacks and its finish-time checks.
    pub(crate) fn types(&self) -> &TypeBuilder {
        &self.types
    }

    /// The type builder, mutably, for the walk's type callbacks.
    pub(crate) fn types_mut(&mut self) -> &mut TypeBuilder {
        &mut self.types
    }

    /// Intern a type, returning a shared handle to pass to [`expression`](Self::expression).
    pub fn intern_type(&mut self, data: TypeData) -> TypeId {
        self.types.intern(data)
    }

    /// Reserve a placeholder type handle to fill later via [`fill_type`](Self::fill_type)
    /// -- the recursion break for aggregate extraction
    /// (see [`TypeTable::alloc_placeholder`]).
    pub fn alloc_type_placeholder(&mut self) -> TypeId {
        self.types.alloc_placeholder()
    }

    /// Supply the body of a placeholder from [`alloc_type_placeholder`](Self::alloc_type_placeholder).
    pub fn fill_type(&mut self, id: TypeId, data: TypeData) {
        self.types.fill(id, data);
    }

    /// The byte size of an already-interned type, if known. Lets a typedef adopt its
    /// target's size so the alias node is self-describing.
    #[must_use]
    pub fn type_size(&self, id: TypeId) -> Option<u64> {
        self.types.type_size(id)
    }

    /// Append a local variable; the returned [`LocalId`] (its index) is what
    /// [`ExpressionKind::Var`] carries.
    pub fn push_lvar(&mut self, lvar: Local) -> LocalId {
        let id = LocalId(u32::try_from(self.lvars.len()).expect("ctree exceeded u32 lvars"));
        self.lvars.push(lvar);
        id
    }

    /// `Var(lvar)`.
    pub fn var(&mut self, ty: TypeId, lvar: LocalId) -> ExpressionId {
        self.expression(ty, ExpressionKind::Var(lvar)).call()
    }

    /// An integer literal (raw bits; signedness rides on `ty`).
    pub fn num(&mut self, ty: TypeId, value: u64) -> ExpressionId {
        self.expression(ty, ExpressionKind::Num(value)).call()
    }

    /// A floating-point literal.
    pub fn fnum(&mut self, ty: TypeId, value: f64) -> ExpressionId {
        self.expression(ty, ExpressionKind::Fnum(value)).call()
    }

    /// A global/static reference at `address`, with its symbol name when it has one.
    pub fn obj(&mut self, ty: TypeId, address: Address, name: Option<&str>) -> ExpressionId {
        self.expression(
            ty,
            ExpressionKind::Obj {
                address,
                name: name.map(str::to_owned),
            },
        )
        .call()
    }

    /// A string literal.
    pub fn string(&mut self, ty: TypeId, s: impl Into<String>) -> ExpressionId {
        self.expression(ty, ExpressionKind::Str(s.into())).call()
    }

    /// A decompiler helper name, e.g. `__readfsqword`.
    pub fn helper(&mut self, ty: TypeId, s: impl Into<String>) -> ExpressionId {
        self.expression(ty, ExpressionKind::Helper(s.into())).call()
    }

    /// `(ty)x`.
    pub fn cast(&mut self, ty: TypeId, x: ExpressionId) -> ExpressionId {
        self.expression(ty, ExpressionKind::Cast { x }).call()
    }

    /// `*x`, reading `size` bytes.
    pub fn deref(&mut self, ty: TypeId, x: ExpressionId, size: u32) -> ExpressionId {
        self.expression(ty, ExpressionKind::Deref { x, size })
            .call()
    }

    /// `OP x`.
    pub fn unary(&mut self, ty: TypeId, op: UnOp, x: ExpressionId) -> ExpressionId {
        self.expression(ty, ExpressionKind::Unary { op, x }).call()
    }

    /// `x OP y`.
    pub fn binary(
        &mut self,
        ty: TypeId,
        op: BinOp,
        x: ExpressionId,
        y: ExpressionId,
    ) -> ExpressionId {
        self.expression(ty, ExpressionKind::Binary { op, x, y })
            .call()
    }

    /// `x OP= y`.
    pub fn assign(
        &mut self,
        ty: TypeId,
        op: AssignOp,
        x: ExpressionId,
        y: ExpressionId,
    ) -> ExpressionId {
        self.expression(ty, ExpressionKind::Assign { op, x, y })
            .call()
    }

    /// `cond ? then_ : else_`.
    pub fn ternary(
        &mut self,
        ty: TypeId,
        cond: ExpressionId,
        then_: ExpressionId,
        else_: ExpressionId,
    ) -> ExpressionId {
        self.expression(ty, ExpressionKind::Ternary { cond, then_, else_ })
            .call()
    }

    /// `array[index]`.
    pub fn index(&mut self, ty: TypeId, array: ExpressionId, index: ExpressionId) -> ExpressionId {
        self.expression(ty, ExpressionKind::Index { array, index })
            .call()
    }

    /// `obj.field` at `byte_offset`.
    pub fn member_ref(&mut self, ty: TypeId, obj: ExpressionId, byte_offset: u32) -> ExpressionId {
        self.expression(ty, ExpressionKind::MemberRef { obj, byte_offset })
            .call()
    }

    /// `obj->field` at `byte_offset`.
    pub fn member_ptr(&mut self, ty: TypeId, obj: ExpressionId, byte_offset: u32) -> ExpressionId {
        self.expression(ty, ExpressionKind::MemberPtr { obj, byte_offset })
            .call()
    }

    /// `callee(args...)`.
    pub fn call_expression(
        &mut self,
        ty: TypeId,
        callee: ExpressionId,
        args: Vec<ExpressionId>,
    ) -> ExpressionId {
        self.expression(ty, ExpressionKind::Call { callee, args })
            .call()
    }

    /// `sizeof(x)`.
    pub fn sizeof(&mut self, ty: TypeId, x: ExpressionId) -> ExpressionId {
        self.expression(ty, ExpressionKind::Sizeof(x)).call()
    }

    /// `e;` -- an expression in statement position.
    pub fn expression_statement(&mut self, e: ExpressionId) -> StatementId {
        self.statement(StatementKind::Expression(e)).call()
    }

    /// `{ ... }`.
    pub fn block(&mut self, statements: Vec<StatementId>) -> StatementId {
        self.statement(StatementKind::Block(statements)).call()
    }

    /// `return [value];`.
    pub fn ret(&mut self, value: Option<ExpressionId>) -> StatementId {
        self.statement(StatementKind::Return(value)).call()
    }

    /// Finalize the tree rooted at `root`, wiring every node's `parent` link by one
    /// pre-order pass from the root.
    #[must_use]
    pub fn finish(mut self, root: StatementId) -> Ctree {
        // Reading a node's children borrows an arena while writing the children's
        // `parent` needs `&mut` to the same arena, so the two phases can't share one
        // borrow. `kids` decouples them; reused across the walk, it allocates once
        // (growing to the largest fan-out) rather than per node.
        let mut stack = vec![NodeRef::Statement(root)];
        let mut kids: Vec<NodeRef> = Vec::new();
        let mut visited = 0usize;
        while let Some(node) = stack.pop() {
            visited += 1;
            kids.clear();
            for_each_child(&self.expressions, &self.statements, node, |c| kids.push(c));
            for &child in &kids {
                match child {
                    NodeRef::Expression(id) => self.expressions[id].parent = Some(node),
                    NodeRef::Statement(id) => self.statements[id].parent = Some(node),
                }
                stack.push(child);
            }
        }
        // Every allocated node must be reachable from the root: a node left unattached
        // is a builder bug. The walk can't loop, since a child's arena index is always
        // smaller than its parent's (the handle must exist to construct the parent), so
        // no node is reached twice and `visited` is an exact count.
        debug_assert_eq!(
            visited,
            self.expressions.len() + self.statements.len(),
            "ctree has nodes unreachable from the root"
        );
        Ctree {
            expressions: self.expressions,
            statements: self.statements,
            types: self.types.into_table(),
            lvars: self.lvars,
            root,
        }
    }
}

#[bon::bon]
impl CtreeBuilder {
    /// Allocate an expression node (parent set later by [`finish`](Self::finish)). `ty` and
    /// `kind` are positional; `address` defaults to `None` (a synthetic node) and is set with
    /// `.address(addr)` for a node with a backing instruction. The per-variant constructors
    /// (e.g. [`var`](Self::var), [`assign`](Self::assign)) are sugar over this for the
    /// common `address`-less case.
    #[builder]
    pub fn expression(
        &mut self,
        #[builder(start_fn)] ty: TypeId,
        #[builder(start_fn)] kind: ExpressionKind,
        address: Option<Address>,
    ) -> ExpressionId {
        self.expressions.alloc(ExpressionNode {
            address,
            ty,
            parent: None,
            kind,
        })
    }

    /// Allocate a statement node (parent set later by [`finish`](Self::finish)). `address`
    /// defaults to `None`; set it with `.address(addr)` for a node with a backing instruction.
    #[builder]
    pub fn statement(
        &mut self,
        #[builder(start_fn)] kind: StatementKind,
        address: Option<Address>,
    ) -> StatementId {
        self.statements.alloc(StatementNode {
            address,
            parent: None,
            kind,
        })
    }
}

impl Default for CtreeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctree::node::{Local, LocalId, LocalLocation};
    use crate::ctree::ops::{AssignOp, BinOp};
    use crate::types::TypeKind;
    use assert2::assert;

    fn int32() -> TypeData {
        TypeData {
            kind: TypeKind::Int {
                bytes: 4,
                signed: true,
            },
            size: Some(4),
        }
    }

    fn lvar(name: &str, ty: TypeId, is_arg: bool) -> Local {
        Local {
            name: name.into(),
            ty,
            is_arg,
            is_result: false,
            is_byref: false,
            width: 4,
            comment: None,
            location: LocalLocation::Register(0),
        }
    }

    /// Build `{ return a + b; }` and return the tree plus its handles.
    fn sample() -> (
        Ctree,
        StatementId,
        StatementId,
        ExpressionId,
        ExpressionId,
        ExpressionId,
    ) {
        let mut b = CtreeBuilder::new();
        let int = b.intern_type(int32());
        let va = b.var(int, LocalId(0));
        let vb = b.var(int, LocalId(1));
        let add = b.binary(int, BinOp::Add, va, vb);
        let ret = b.ret(Some(add));
        let block = b.block(vec![ret]);
        let tree = b.finish(block);
        (tree, block, ret, add, va, vb)
    }

    #[test]
    fn finish_wires_parent_links() {
        let (tree, block, ret, add, va, vb) = sample();
        assert!(tree.root() == block);
        assert!(let None = tree.parent(NodeRef::Statement(block)));
        assert!(tree.parent(NodeRef::Statement(ret)) == Some(NodeRef::Statement(block)));
        assert!(tree.parent(NodeRef::Expression(add)) == Some(NodeRef::Statement(ret)));
        assert!(tree.parent(NodeRef::Expression(va)) == Some(NodeRef::Expression(add)));
        assert!(tree.parent(NodeRef::Expression(vb)) == Some(NodeRef::Expression(add)));
    }

    #[test]
    fn descendants_are_pre_order() {
        let (tree, block, ret, add, va, vb) = sample();
        let walk: Vec<NodeRef> = tree.descendants(NodeRef::Statement(block)).collect();
        assert!(
            walk == vec![
                NodeRef::Statement(block),
                NodeRef::Statement(ret),
                NodeRef::Expression(add),
                NodeRef::Expression(va),
                NodeRef::Expression(vb),
            ]
        );
    }

    #[test]
    fn children_of_a_leaf_are_empty() {
        let (tree, _block, _ret, _add, va, _vb) = sample();
        assert!(tree.children(NodeRef::Expression(va)).is_empty());
    }

    #[test]
    fn expression_descendants_skips_statements() {
        let (tree, block, _ret, add, va, vb) = sample();
        // Statements (block, return) are filtered out; the three expressions survive in pre-order.
        let expressions: Vec<ExpressionId> = tree
            .expression_descendants(NodeRef::Statement(block))
            .collect();
        assert!(expressions == vec![add, va, vb]);
    }

    /// `kind`/`statement_kind` resolve a handle straight to its node kind -- the shorthand the
    /// matchers project from.
    #[test]
    fn kind_resolves_handles_to_their_node_kind() {
        let (tree, block, ret, add, va, _vb) = sample();
        assert!(let ExpressionKind::Binary { .. } = tree.kind(add));
        assert!(let ExpressionKind::Var(_) = tree.kind(va));
        assert!(let StatementKind::Block(_) = tree.statement_kind(block));
        assert!(let StatementKind::Return(_) = tree.statement_kind(ret));
    }

    /// The semantic iterators enumerate every call/assign/var in the tree; building the
    /// sample with the per-variant sugar actuates that side too.
    #[test]
    fn semantic_iterators_enumerate_their_kind() {
        let mut b = CtreeBuilder::new();
        let int = b.intern_type(int32());
        let x = b.var(int, LocalId(0));
        let a = b.var(int, LocalId(1));
        let f = b.obj(int, Address::new_const(0x40), Some("f"));
        let call = b.call_expression(int, f, vec![a]);
        let asg = b.assign(int, AssignOp::Assign, x, call);
        let st = b.expression_statement(asg);
        let block = b.block(vec![st]);
        let tree = b.finish(block);

        let calls: Vec<_> = tree.calls().collect();
        assert!(calls == vec![(call, f, [a].as_slice())]);
        assert!(tree.assigns().collect::<Vec<_>>() == vec![(asg, AssignOp::Assign, x, call)]);
        // Both `Var` references surface, in allocation order.
        assert!(tree.vars().map(|(_, v)| v).collect::<Vec<_>>() == vec![LocalId(0), LocalId(1)]);
    }

    #[test]
    fn flat_iteration_covers_every_node() {
        let (tree, _block, _ret, _add, _va, _vb) = sample();
        // 3 expressions (va, vb, add), 2 statements (ret, block), 1 type (int, deduped across expressions).
        assert!(tree.expressions().count() == 3);
        assert!(tree.statements().count() == 2);
        assert!(tree.types().count() == 1);
        let binaries = tree
            .expressions()
            .filter(|(_, e)| matches!(e.kind, ExpressionKind::Binary { .. }))
            .count();
        assert!(binaries == 1);
    }

    /// The flat, address-keyed lookups find nodes by their backing instruction address:
    /// `expression_at`/`statement_at` return the first of each kind, `items_at` yields every
    /// node sharing an address (expressions first), and an address no node carries is empty.
    #[test]
    fn flat_queries_find_nodes_by_address() {
        let mut b = CtreeBuilder::new();
        let int = b.intern_type(int32());
        let a0 = Address::new_const(0x1000);
        let a1 = Address::new_const(0x1004);

        // An expression at a0, wrapped in a statement also at a0; a second statement at a1.
        let v = b
            .expression(int, ExpressionKind::Var(LocalId(0)))
            .address(a0)
            .call();
        let s0 = b.statement(StatementKind::Expression(v)).address(a0).call();
        let s1 = b.statement(StatementKind::Return(None)).address(a1).call();
        let block = b.block(vec![s0, s1]);
        let tree = b.finish(block);

        assert!(tree.expression_at(a0) == Some(v));
        assert!(tree.statement_at(a0) == Some(s0));
        assert!(tree.statement_at(a1) == Some(s1));
        // No expression sits at a1, and nothing at all at an unmapped address.
        assert!(tree.expression_at(a1).is_none());
        assert!(tree.statement_at(Address::new_const(0x2000)).is_none());

        // items_at yields the expression then the statement that share a0; the address-less
        // block never appears.
        assert!(
            tree.items_at(a0).collect::<Vec<_>>()
                == vec![NodeRef::Expression(v), NodeRef::Statement(s0)]
        );
        assert!(tree.items_at(a1).collect::<Vec<_>>() == vec![NodeRef::Statement(s1)]);
        assert!(tree.items_at(Address::new_const(0x2000)).next().is_none());
    }

    #[test]
    fn expression_carries_its_resolved_type() {
        let (tree, _block, _ret, add, _va, _vb) = sample();
        let ty = tree.expression(add).ty;
        assert!(
            tree.type_of(ty).kind
                == TypeKind::Int {
                    bytes: 4,
                    signed: true
                }
        );
    }

    /// `this_lvar` returns the first argument local -- the implicit receiver -- and `None`
    /// when the function takes no arguments.
    #[test]
    fn this_lvar_is_the_first_argument() {
        let mut b = CtreeBuilder::new();
        let int = b.intern_type(int32());
        // A leading non-arg local must not be mistaken for the receiver.
        b.push_lvar(lvar("local", int, false));
        let this = b.push_lvar(lvar("this", int, true));
        b.push_lvar(lvar("arg2", int, true));
        let v = b.var(int, this);
        let st = b.expression_statement(v);
        let block = b.block(vec![st]);
        let tree = b.finish(block);
        assert!(tree.this_lvar() == Some(this));
    }

    #[test]
    fn this_lvar_is_none_without_arguments() {
        let mut b = CtreeBuilder::new();
        let int = b.intern_type(int32());
        b.push_lvar(lvar("local", int, false));
        let block = b.block(vec![]);
        let tree = b.finish(block);
        assert!(let None = tree.this_lvar());
    }

    /// The marquee invariant: a materialized ctree is `Send + Sync`, so
    /// it can be shipped off the kernel thread to a worker for analysis. Fails to
    /// compile if a non-`Send` field is ever added.
    #[test]
    fn ctree_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Ctree>();
    }
}
