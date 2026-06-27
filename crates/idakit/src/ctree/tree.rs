//! [`Ctree`]: a decompiled function's ctree, as owned interned arenas plus the root
//! statement. Built through [`CtreeBuilder`], which wires every node's `parent` link
//! once the tree is complete.

use super::arena::Arena;
use super::node::{Cexpr, Cinsn, ExprId, ExprNode, Lvar, LvarId, NodeRef, StmtId, StmtNode};
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
/// read-only analysis snapshot — there is no in-place mutation, and it does not track
/// the live database, so it goes stale if the function is re-decompiled. Writing back to
/// IDA is a separate concern, not routed through these handles.
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

    /// Every expression node, flat, in allocation order — for whole-tree scans like
    /// "find all calls" that don't need the tree shape.
    pub fn exprs(&self) -> impl ExactSizeIterator<Item = (ExprId, &ExprNode)> {
        self.exprs.iter()
    }

    /// Every statement node, flat, in allocation order.
    pub fn stmts(&self) -> impl ExactSizeIterator<Item = (StmtId, &StmtNode)> {
        self.stmts.iter()
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

    /// Visit each direct child without allocating — the push-based form that
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
        // reverse just that suffix so the first child is popped — and visited — next.
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
    /// — the recursion break for aggregate extraction
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

    /// Allocate an expression node of type `ty` (parent set later by
    /// [`finish`](Self::finish)). `ea` is `None` for a synthetic node.
    pub fn expr(&mut self, ea: Option<Ea>, ty: TypeId, kind: Cexpr) -> ExprId {
        self.exprs.alloc(ExprNode {
            ea,
            ty,
            parent: None,
            kind,
        })
    }

    /// Allocate a statement node (parent set later by [`finish`](Self::finish)). `ea` is
    /// `None` for a synthetic node.
    pub fn stmt(&mut self, ea: Option<Ea>, kind: Cinsn) -> StmtId {
        self.stmts.alloc(StmtNode {
            ea,
            parent: None,
            kind,
        })
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

impl Default for CtreeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctree::node::LvarId;
    use crate::ctree::ops::BinOp;
    use crate::ctree::types::TypeKind;

    fn int32() -> TypeData {
        TypeData {
            kind: TypeKind::Int {
                bytes: 4,
                signed: true,
            },
            size: Some(4),
        }
    }

    /// Build `{ return a + b; }` and return the tree plus its handles.
    fn sample() -> (Ctree, StmtId, StmtId, ExprId, ExprId, ExprId) {
        let ea = Some(Ea::new_const(0x1000));
        let mut b = CtreeBuilder::new();
        let int = b.intern_type(int32());
        let va = b.expr(ea, int, Cexpr::Var(LvarId(0)));
        let vb = b.expr(ea, int, Cexpr::Var(LvarId(1)));
        let add = b.expr(
            ea,
            int,
            Cexpr::Binary {
                op: BinOp::Add,
                x: va,
                y: vb,
            },
        );
        let ret = b.stmt(ea, Cinsn::Return(Some(add)));
        let block = b.stmt(ea, Cinsn::Block(vec![ret]));
        let tree = b.finish(block);
        (tree, block, ret, add, va, vb)
    }

    #[test]
    fn finish_wires_parent_links() {
        let (tree, block, ret, add, va, vb) = sample();
        assert_eq!(tree.root(), block);
        assert_eq!(tree.parent(NodeRef::Stmt(block)), None);
        assert_eq!(tree.parent(NodeRef::Stmt(ret)), Some(NodeRef::Stmt(block)));
        assert_eq!(tree.parent(NodeRef::Expr(add)), Some(NodeRef::Stmt(ret)));
        assert_eq!(tree.parent(NodeRef::Expr(va)), Some(NodeRef::Expr(add)));
        assert_eq!(tree.parent(NodeRef::Expr(vb)), Some(NodeRef::Expr(add)));
    }

    #[test]
    fn descendants_are_pre_order() {
        let (tree, block, ret, add, va, vb) = sample();
        let walk: Vec<NodeRef> = tree.descendants(NodeRef::Stmt(block)).collect();
        assert_eq!(
            walk,
            vec![
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
    fn flat_iteration_covers_every_node() {
        let (tree, _block, _ret, _add, _va, _vb) = sample();
        // 3 exprs (va, vb, add), 2 stmts (ret, block), 1 type (int, deduped across exprs).
        assert_eq!(tree.exprs().count(), 3);
        assert_eq!(tree.stmts().count(), 2);
        assert_eq!(tree.types().count(), 1);
        let binaries = tree
            .exprs()
            .filter(|(_, e)| matches!(e.kind, Cexpr::Binary { .. }))
            .count();
        assert_eq!(binaries, 1);
    }

    #[test]
    fn expr_carries_its_resolved_type() {
        let (tree, _block, _ret, add, _va, _vb) = sample();
        let ty = tree.expr(add).ty;
        assert_eq!(
            tree.type_of(ty).kind,
            TypeKind::Int {
                bytes: 4,
                signed: true
            }
        );
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
