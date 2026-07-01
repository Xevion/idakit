//! [`Ctree`]: a decompiled function's ctree, as owned interned arenas plus the root
//! statement. Built through [`CtreeBuilder`], which wires every node's `parent` link
//! once the tree is complete.

use super::arena::Arena;
use super::node::{Cexpr, Cinsn, ExprId, ExprNode, Lvar, LvarId, NodeRef, StmtId, StmtNode};
use super::ops::{AssignOp, BinOp, UnOp};
use super::types::{TypeData, TypeId, TypeTable};
use crate::Ea;

/// Visit `node`'s children, dispatching to the right arena. Shared by every navigation
/// path (read-only walks and the build-time parent pass) so the expr/stmt split lives
/// in one place.
#[inline]
fn for_each_child(
    exprs: &Arena<ExprNode>,
    stmts: &Arena<StmtNode>,
    node: NodeRef,
    f: impl FnMut(NodeRef),
) {
    match node {
        NodeRef::Expr(id) => exprs[id].kind.for_each_child(f),
        NodeRef::Stmt(id) => stmts[id].kind.for_each_child(f),
    }
}

/// A decompiled function's ctree. The root is always a block statement.
///
/// Owned and `Send`: materialized on the kernel thread, then analyzed anywhere. A
/// read-only analysis snapshot -- there is no in-place mutation, and it does not track
/// the live database, so it goes stale if the function is re-decompiled. Writing back to
/// IDA is a separate concern, not routed through these handles.
#[derive(Debug)]
pub struct Ctree {
    exprs: Arena<ExprNode>,
    stmts: Arena<StmtNode>,
    types: TypeTable,
    lvars: Vec<Lvar>,
    root: StmtId,
}

impl Ctree {
    /// The root statement (a block).
    #[inline]
    #[must_use]
    pub fn root(&self) -> StmtId {
        self.root
    }

    /// The expression node behind a handle.
    #[inline]
    #[must_use]
    pub fn expr(&self, id: ExprId) -> &ExprNode {
        &self.exprs[id]
    }

    /// The statement node behind a handle.
    #[inline]
    #[must_use]
    pub fn stmt(&self, id: StmtId) -> &StmtNode {
        &self.stmts[id]
    }

    /// The expression *kind* behind a handle: shorthand for [`expr(id)`](Self::expr)`.kind`,
    /// the form matchers want when projecting with the [`Cexpr`] `as_*` accessors.
    #[inline]
    #[must_use]
    pub fn kind(&self, id: ExprId) -> &Cexpr {
        &self.exprs[id].kind
    }

    /// The statement *kind* behind a handle: shorthand for [`stmt(id)`](Self::stmt)`.kind`.
    #[inline]
    #[must_use]
    pub fn stmt_kind(&self, id: StmtId) -> &Cinsn {
        &self.stmts[id].kind
    }

    /// The type behind a handle (e.g. an [`ExprNode::ty`]).
    #[inline]
    #[must_use]
    pub fn type_of(&self, id: TypeId) -> &TypeData {
        self.types.get(id)
    }

    /// The local variable a [`Cexpr::Var`] refers to.
    #[inline]
    #[must_use]
    pub fn lvar(&self, id: LvarId) -> &Lvar {
        &self.lvars[id.0 as usize]
    }

    /// Every local variable of the function, in lvar-index order.
    pub fn lvars(&self) -> impl ExactSizeIterator<Item = &Lvar> {
        self.lvars.iter()
    }

    /// The first argument local -- the implicit `this` in a member function, or simply the
    /// first parameter otherwise. `None` for a function that takes no arguments. A pure
    /// structural accessor: it reads the lvar table's argument flags and makes no
    /// assumption about calling convention.
    #[must_use]
    pub fn this_lvar(&self) -> Option<LvarId> {
        self.lvars
            .iter()
            .position(|lv| lv.is_arg)
            .map(|i| LvarId(i as u32))
    }

    /// Every expression node, flat, in allocation order -- for whole-tree scans like
    /// "find all calls" that don't need the tree shape.
    pub fn exprs(&self) -> impl ExactSizeIterator<Item = (ExprId, &ExprNode)> {
        self.exprs.iter()
    }

    /// Every statement node, flat, in allocation order.
    pub fn stmts(&self) -> impl ExactSizeIterator<Item = (StmtId, &StmtNode)> {
        self.stmts.iter()
    }

    /// Every call in the tree as `(node, callee, args)` -- the whole-tree scan behind
    /// "find every call" without re-spelling the [`as_call`](Cexpr::as_call) filter.
    pub fn calls(&self) -> impl Iterator<Item = (ExprId, ExprId, &[ExprId])> {
        self.exprs()
            .filter_map(|(id, node)| node.kind.as_call().map(|(callee, args)| (id, callee, args)))
    }

    /// Every assignment in the tree as `(node, op, lhs, rhs)`.
    pub fn assigns(&self) -> impl Iterator<Item = (ExprId, AssignOp, ExprId, ExprId)> {
        self.exprs()
            .filter_map(|(id, node)| node.kind.as_assign().map(|(op, x, y)| (id, op, x, y)))
    }

    /// Every local-variable reference in the tree as `(node, lvar)`.
    pub fn vars(&self) -> impl Iterator<Item = (ExprId, LvarId)> {
        self.exprs()
            .filter_map(|(id, node)| node.kind.as_var().map(|v| (id, v)))
    }

    /// Every interned type, flat.
    pub fn types(&self) -> impl ExactSizeIterator<Item = (TypeId, &TypeData)> {
        self.types.iter()
    }

    /// This node's parent, or `None` for the root.
    #[inline]
    #[must_use]
    pub fn parent(&self, node: NodeRef) -> Option<NodeRef> {
        match node {
            NodeRef::Expr(id) => self.exprs[id].parent,
            NodeRef::Stmt(id) => self.stmts[id].parent,
        }
    }

    /// This node's direct children, in source order.
    #[must_use]
    pub fn children(&self, node: NodeRef) -> Vec<NodeRef> {
        let mut v = Vec::new();
        for_each_child(&self.exprs, &self.stmts, node, |c| v.push(c));
        v
    }

    /// Visit each direct child without allocating -- the push-based form that
    /// [`children`](Self::children) buffers into a `Vec`.
    pub fn children_for_each(&self, node: NodeRef, f: impl FnMut(NodeRef)) {
        for_each_child(&self.exprs, &self.stmts, node, f);
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
    pub fn expr_descendants(&self, node: NodeRef) -> impl Iterator<Item = ExprId> + '_ {
        self.descendants(node).filter_map(NodeRef::as_expr)
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
        for_each_child(&self.tree.exprs, &self.tree.stmts, node, |c| {
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
    exprs: Arena<ExprNode>,
    stmts: Arena<StmtNode>,
    types: TypeTable,
    lvars: Vec<Lvar>,
}

impl CtreeBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            exprs: Arena::new(),
            stmts: Arena::new(),
            types: TypeTable::new(),
            lvars: Vec::new(),
        }
    }

    /// Intern a type, returning a shared handle to pass to [`expr`](Self::expr).
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
        self.types.get(id).size
    }

    /// Append a local variable; the returned [`LvarId`] (its index) is what
    /// [`Cexpr::Var`] carries.
    pub fn push_lvar(&mut self, lvar: Lvar) -> LvarId {
        let id = LvarId(u32::try_from(self.lvars.len()).expect("ctree exceeded u32 lvars"));
        self.lvars.push(lvar);
        id
    }

    /// `Var(lvar)`.
    pub fn var(&mut self, ty: TypeId, lvar: LvarId) -> ExprId {
        self.expr(ty, Cexpr::Var(lvar)).call()
    }

    /// An integer literal (raw bits; signedness rides on `ty`).
    pub fn num(&mut self, ty: TypeId, value: u64) -> ExprId {
        self.expr(ty, Cexpr::Num(value)).call()
    }

    /// A floating-point literal.
    pub fn fnum(&mut self, ty: TypeId, value: f64) -> ExprId {
        self.expr(ty, Cexpr::Fnum(value)).call()
    }

    /// A global/static reference at `ea`, with its symbol name when it has one.
    pub fn obj(&mut self, ty: TypeId, ea: Ea, name: Option<&str>) -> ExprId {
        self.expr(
            ty,
            Cexpr::Obj {
                ea,
                name: name.map(str::to_owned),
            },
        )
        .call()
    }

    /// A string literal.
    pub fn string(&mut self, ty: TypeId, s: impl Into<String>) -> ExprId {
        self.expr(ty, Cexpr::Str(s.into())).call()
    }

    /// A decompiler helper name, e.g. `__readfsqword`.
    pub fn helper(&mut self, ty: TypeId, s: impl Into<String>) -> ExprId {
        self.expr(ty, Cexpr::Helper(s.into())).call()
    }

    /// `(ty)x`.
    pub fn cast(&mut self, ty: TypeId, x: ExprId) -> ExprId {
        self.expr(ty, Cexpr::Cast { x }).call()
    }

    /// `*x`, reading `size` bytes.
    pub fn deref(&mut self, ty: TypeId, x: ExprId, size: u32) -> ExprId {
        self.expr(ty, Cexpr::Deref { x, size }).call()
    }

    /// `OP x`.
    pub fn unary(&mut self, ty: TypeId, op: UnOp, x: ExprId) -> ExprId {
        self.expr(ty, Cexpr::Unary { op, x }).call()
    }

    /// `x OP y`.
    pub fn binary(&mut self, ty: TypeId, op: BinOp, x: ExprId, y: ExprId) -> ExprId {
        self.expr(ty, Cexpr::Binary { op, x, y }).call()
    }

    /// `x OP= y`.
    pub fn assign(&mut self, ty: TypeId, op: AssignOp, x: ExprId, y: ExprId) -> ExprId {
        self.expr(ty, Cexpr::Assign { op, x, y }).call()
    }

    /// `cond ? then_ : else_`.
    pub fn ternary(&mut self, ty: TypeId, cond: ExprId, then_: ExprId, else_: ExprId) -> ExprId {
        self.expr(ty, Cexpr::Ternary { cond, then_, else_ }).call()
    }

    /// `array[index]`.
    pub fn index(&mut self, ty: TypeId, array: ExprId, index: ExprId) -> ExprId {
        self.expr(ty, Cexpr::Index { array, index }).call()
    }

    /// `obj.field` at `byte_offset`.
    pub fn member_ref(&mut self, ty: TypeId, obj: ExprId, byte_offset: u32) -> ExprId {
        self.expr(ty, Cexpr::MemberRef { obj, byte_offset }).call()
    }

    /// `obj->field` at `byte_offset`.
    pub fn member_ptr(&mut self, ty: TypeId, obj: ExprId, byte_offset: u32) -> ExprId {
        self.expr(ty, Cexpr::MemberPtr { obj, byte_offset }).call()
    }

    /// `callee(args...)`.
    pub fn call_expr(&mut self, ty: TypeId, callee: ExprId, args: Vec<ExprId>) -> ExprId {
        self.expr(ty, Cexpr::Call { callee, args }).call()
    }

    /// `sizeof(x)`.
    pub fn sizeof(&mut self, ty: TypeId, x: ExprId) -> ExprId {
        self.expr(ty, Cexpr::Sizeof(x)).call()
    }

    /// `e;` -- an expression in statement position.
    pub fn expr_stmt(&mut self, e: ExprId) -> StmtId {
        self.stmt(Cinsn::Expr(e)).call()
    }

    /// `{ ... }`.
    pub fn block(&mut self, stmts: Vec<StmtId>) -> StmtId {
        self.stmt(Cinsn::Block(stmts)).call()
    }

    /// `return [value];`.
    pub fn ret(&mut self, value: Option<ExprId>) -> StmtId {
        self.stmt(Cinsn::Return(value)).call()
    }

    /// Finalize the tree rooted at `root`, wiring every node's `parent` link by one
    /// pre-order pass from the root.
    #[must_use]
    pub fn finish(mut self, root: StmtId) -> Ctree {
        // Reading a node's children borrows an arena while writing the children's
        // `parent` needs `&mut` to the same arena, so the two phases can't share one
        // borrow. `kids` decouples them; reused across the walk, it allocates once
        // (growing to the largest fan-out) rather than per node.
        let mut stack = vec![NodeRef::Stmt(root)];
        let mut kids: Vec<NodeRef> = Vec::new();
        let mut visited = 0usize;
        while let Some(node) = stack.pop() {
            visited += 1;
            kids.clear();
            for_each_child(&self.exprs, &self.stmts, node, |c| kids.push(c));
            for &child in &kids {
                match child {
                    NodeRef::Expr(id) => self.exprs[id].parent = Some(node),
                    NodeRef::Stmt(id) => self.stmts[id].parent = Some(node),
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
            self.exprs.len() + self.stmts.len(),
            "ctree has nodes unreachable from the root"
        );
        Ctree {
            exprs: self.exprs,
            stmts: self.stmts,
            types: self.types,
            lvars: self.lvars,
            root,
        }
    }
}

#[bon::bon]
impl CtreeBuilder {
    /// Allocate an expression node (parent set later by [`finish`](Self::finish)). `ty` and
    /// `kind` are positional; `ea` defaults to `None` (a synthetic node) and is set with
    /// `.ea(addr)` for a node with a backing instruction. The per-variant constructors
    /// (e.g. [`var`](Self::var), [`assign`](Self::assign)) are sugar over this for the
    /// common `ea`-less case.
    #[builder]
    pub fn expr(
        &mut self,
        #[builder(start_fn)] ty: TypeId,
        #[builder(start_fn)] kind: Cexpr,
        ea: Option<Ea>,
    ) -> ExprId {
        self.exprs.alloc(ExprNode {
            ea,
            ty,
            parent: None,
            kind,
        })
    }

    /// Allocate a statement node (parent set later by [`finish`](Self::finish)). `ea`
    /// defaults to `None`; set it with `.ea(addr)` for a node with a backing instruction.
    #[builder]
    pub fn stmt(&mut self, #[builder(start_fn)] kind: Cinsn, ea: Option<Ea>) -> StmtId {
        self.stmts.alloc(StmtNode {
            ea,
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
    use crate::ctree::node::{Lvar, LvarId, LvarLocation};
    use crate::ctree::ops::{AssignOp, BinOp};
    use crate::ctree::types::TypeKind;
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

    fn lvar(name: &str, ty: TypeId, is_arg: bool) -> Lvar {
        Lvar {
            name: name.into(),
            ty,
            is_arg,
            is_result: false,
            is_byref: false,
            width: 4,
            comment: None,
            location: LvarLocation::Other,
        }
    }

    /// Build `{ return a + b; }` and return the tree plus its handles.
    fn sample() -> (Ctree, StmtId, StmtId, ExprId, ExprId, ExprId) {
        let mut b = CtreeBuilder::new();
        let int = b.intern_type(int32());
        let va = b.var(int, LvarId(0));
        let vb = b.var(int, LvarId(1));
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
        assert!(let None = tree.parent(NodeRef::Stmt(block)));
        assert!(tree.parent(NodeRef::Stmt(ret)) == Some(NodeRef::Stmt(block)));
        assert!(tree.parent(NodeRef::Expr(add)) == Some(NodeRef::Stmt(ret)));
        assert!(tree.parent(NodeRef::Expr(va)) == Some(NodeRef::Expr(add)));
        assert!(tree.parent(NodeRef::Expr(vb)) == Some(NodeRef::Expr(add)));
    }

    #[test]
    fn descendants_are_pre_order() {
        let (tree, block, ret, add, va, vb) = sample();
        let walk: Vec<NodeRef> = tree.descendants(NodeRef::Stmt(block)).collect();
        assert!(
            walk == vec![
                NodeRef::Stmt(block),
                NodeRef::Stmt(ret),
                NodeRef::Expr(add),
                NodeRef::Expr(va),
                NodeRef::Expr(vb),
            ]
        );
    }

    #[test]
    fn children_of_a_leaf_are_empty() {
        let (tree, _block, _ret, _add, va, _vb) = sample();
        assert!(tree.children(NodeRef::Expr(va)).is_empty());
    }

    #[test]
    fn expr_descendants_skips_statements() {
        let (tree, block, _ret, add, va, vb) = sample();
        // Statements (block, return) are filtered out; the three exprs survive in pre-order.
        let exprs: Vec<ExprId> = tree.expr_descendants(NodeRef::Stmt(block)).collect();
        assert!(exprs == vec![add, va, vb]);
    }

    /// `kind`/`stmt_kind` resolve a handle straight to its node kind -- the shorthand the
    /// matchers project from.
    #[test]
    fn kind_resolves_handles_to_their_node_kind() {
        let (tree, block, ret, add, va, _vb) = sample();
        assert!(let Cexpr::Binary { .. } = tree.kind(add));
        assert!(let Cexpr::Var(_) = tree.kind(va));
        assert!(let Cinsn::Block(_) = tree.stmt_kind(block));
        assert!(let Cinsn::Return(_) = tree.stmt_kind(ret));
    }

    /// The semantic iterators enumerate every call/assign/var in the tree; building the
    /// sample with the per-variant sugar actuates that side too.
    #[test]
    fn semantic_iterators_enumerate_their_kind() {
        let mut b = CtreeBuilder::new();
        let int = b.intern_type(int32());
        let x = b.var(int, LvarId(0));
        let a = b.var(int, LvarId(1));
        let f = b.obj(int, Ea::new_const(0x40), Some("f"));
        let call = b.call_expr(int, f, vec![a]);
        let asg = b.assign(int, AssignOp::Assign, x, call);
        let st = b.expr_stmt(asg);
        let block = b.block(vec![st]);
        let tree = b.finish(block);

        let calls: Vec<_> = tree.calls().collect();
        assert!(calls == vec![(call, f, [a].as_slice())]);
        assert!(tree.assigns().collect::<Vec<_>>() == vec![(asg, AssignOp::Assign, x, call)]);
        // Both `Var` references surface, in allocation order.
        assert!(tree.vars().map(|(_, v)| v).collect::<Vec<_>>() == vec![LvarId(0), LvarId(1)]);
    }

    #[test]
    fn flat_iteration_covers_every_node() {
        let (tree, _block, _ret, _add, _va, _vb) = sample();
        // 3 exprs (va, vb, add), 2 stmts (ret, block), 1 type (int, deduped across exprs).
        assert!(tree.exprs().count() == 3);
        assert!(tree.stmts().count() == 2);
        assert!(tree.types().count() == 1);
        let binaries = tree
            .exprs()
            .filter(|(_, e)| matches!(e.kind, Cexpr::Binary { .. }))
            .count();
        assert!(binaries == 1);
    }

    #[test]
    fn expr_carries_its_resolved_type() {
        let (tree, _block, _ret, add, _va, _vb) = sample();
        let ty = tree.expr(add).ty;
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
        let st = b.expr_stmt(v);
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
