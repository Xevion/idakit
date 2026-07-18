//! Building a [`Ctree`] from the facade's streaming ctree walk.
//!
//! The facade ([`idakit_sys::cfunc_walk_ctree`]) is a pure SDK walker, reading a decompiled
//! function depth-first and, per node, calling one method of the `cxx` opaque
//! [`CtreeVisitor`](idakit_sys::CtreeVisitor) it drives. Children are emitted before their
//! parents, so each call receives its children as the handles their own calls returned.
//! [`CallbackBuilder`] is the [`idakit_sys::CtreeSink`] the visitor forwards into and holds
//! the in-progress arenas; its safe methods are also what the tests drive directly.
//!
//! All identity and meaning live here, not in the facade: an operator's `ctype` maps to
//! [`BinaryOp`]/[`AssignmentOp`]/[`UnaryOp`] (their discriminants *are* the ctype values) or a
//! [`StructuralTag`]; named aggregate types are interned by name with a placeholder so
//! recursion resolves; structural types dedup through the type table.

use idakit_sys::{EnumConstInfo, MemberInfo, NONE};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use snafu::Snafu;
use strum::VariantArray;

use super::node::{
    Case, ExpressionId, ExpressionKind, Local, LocalId, LocalLocation, LocationPiece, StatementId,
    StatementKind,
};
use super::ops::{AssignmentOp, BinaryOp, UnaryOp};
use super::tree::{Ctree, CtreeBuilder};
use crate::address::Address;
use crate::arena::Idx;
use crate::types::{SinkAdapter, TypeBuilder, TypeSink, raw, tid};

/// A structural `ctype_t` tag the generic operator callback dispatches by name.
///
/// Operators proper go through the [`BinaryOp`]/[`AssignmentOp`]/[`UnaryOp`] `TryFrom<u16>`
/// derives instead; this covers the rest of the range idakit models. A tag outside the set is
/// rejected as [`ExtractError::UnknownExpressionTag`], not absorbed.
// raw ctype_t values from hexrays.hpp (IDA 9.3)
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoPrimitive, TryFromPrimitive, VariantArray)]
#[repr(u32)]
enum StructuralTag {
    Empty = 0,
    Tern = 16,
    Cast = 48,
    Idx = 58,
    /// A statement appearing in expression position. Never present in a finalized tree;
    /// collapsed to [`ExpressionKind::Internal`] rather than erroring.
    Insn = 66,
    Sizeof = 67,
    Type = 69,
}

/// Why a ctree walk could not be turned into a [`Ctree`].
#[derive(Debug, Snafu, PartialEq, Eq)]
#[snafu(visibility(pub(crate)))]
pub enum ExtractError {
    /// A node carried an expression `ctype` the walker does not model.
    #[snafu(display("unmodeled expression ctype {tag}"))]
    UnknownExpressionTag {
        /// The unmodeled raw `ctype_t` value.
        tag: u32,
    },

    /// A node required an address but carried the `BADADDR` sentinel.
    #[snafu(display("a node carries the BADADDR sentinel as a required address"))]
    BadAddress,

    /// A scalar's byte width exceeds any real scalar.
    #[snafu(display("a scalar reports {bytes} bytes, wider than any real scalar"))]
    ScalarTooWide {
        /// The over-wide byte count.
        bytes: u32,
    },

    /// Aggregate extraction left type placeholders that were never filled.
    #[snafu(display("{count} type placeholder(s) were referenced but never filled"))]
    UnfilledType {
        /// How many placeholders remained unfilled.
        count: usize,
    },
}

/// A node's own source address: `None` for a synthetic node (the BADADDR sentinel).
fn node_address(raw: u64) -> Option<Address> {
    Address::try_new(raw)
}

fn eid(raw: u32) -> ExpressionId {
    Idx::from_raw(raw)
}

fn sid(raw: u32) -> StatementId {
    Idx::from_raw(raw)
}

fn opt_e(raw: u32) -> Option<ExpressionId> {
    (raw != NONE).then(|| eid(raw))
}

fn opt_s(raw: u32) -> Option<StatementId> {
    (raw != NONE).then(|| sid(raw))
}

/// Accumulates the owned ctree as the facade walks. Its methods are the safe surface the
/// [`idakit_sys::CtreeSink`] impl below (and the unit tests) call; each returns the new node's
/// handle as a bare `u32` for the facade to thread to the parent. Node building lives here; type
/// building is delegated to the [`CtreeBuilder`]'s [`TypeBuilder`](crate::types::TypeBuilder).
pub(crate) struct CallbackBuilder {
    b: CtreeBuilder,
    /// First deferred *node* failure; checked at [`finish`](Self::finish) alongside the
    /// type builder's own signals.
    error: Option<ExtractError>,
}

impl CallbackBuilder {
    fn new() -> Self {
        Self {
            b: CtreeBuilder::new(),
            error: None,
        }
    }

    /// Record a deferred failure, keeping only the first and dropping later failures in the
    /// same walk. Callers must not assume every problem surfaces at
    /// [`finish`](Self::finish), only that a failed walk reports *some* error.
    fn fail(&mut self, e: ExtractError) {
        if self.error.is_none() {
            self.error = Some(e);
        }
    }

    fn push_expression(&mut self, address: u64, ty: u32, kind: ExpressionKind) -> u32 {
        raw(self
            .b
            .expression(tid(ty), kind)
            .maybe_address(node_address(address))
            .call())
    }

    fn push_statement(&mut self, address: u64, kind: StatementKind) -> u32 {
        raw(self
            .b
            .statement(kind)
            .maybe_address(node_address(address))
            .call())
    }

    fn num(&mut self, address: u64, value: u64, ty: u32) -> u32 {
        self.push_expression(address, ty, ExpressionKind::Num(value))
    }

    fn fnum(&mut self, address: u64, value: f64, ty: u32) -> u32 {
        self.push_expression(address, ty, ExpressionKind::Fnum(value))
    }

    fn obj(&mut self, address: u64, target: u64, name: Option<String>, ty: u32) -> u32 {
        if let Some(addr) = Address::try_new(target) {
            self.push_expression(
                address,
                ty,
                ExpressionKind::Obj {
                    address: addr,
                    name,
                },
            )
        } else {
            self.fail(ExtractError::BadAddress);
            self.push_expression(address, ty, ExpressionKind::Empty)
        }
    }

    fn var(&mut self, address: u64, idx: u32, ty: u32) -> u32 {
        self.push_expression(address, ty, ExpressionKind::Var(LocalId(idx)))
    }

    fn string(&mut self, address: u64, s: String, ty: u32) -> u32 {
        self.push_expression(address, ty, ExpressionKind::Str(s))
    }

    fn helper(&mut self, address: u64, s: String, ty: u32) -> u32 {
        self.push_expression(address, ty, ExpressionKind::Helper(s))
    }

    fn call(&mut self, address: u64, callee: u32, args: &[u32], ty: u32) -> u32 {
        let args = args.iter().map(|&a| eid(a)).collect();
        self.push_expression(
            address,
            ty,
            ExpressionKind::Call {
                callee: eid(callee),
                args,
            },
        )
    }

    fn memref(&mut self, address: u64, obj: u32, offset: u32, ty: u32) -> u32 {
        self.push_expression(
            address,
            ty,
            ExpressionKind::MemberRef {
                obj: eid(obj),
                byte_offset: offset,
            },
        )
    }

    fn memptr(&mut self, address: u64, obj: u32, offset: u32, ty: u32) -> u32 {
        self.push_expression(
            address,
            ty,
            ExpressionKind::MemberPtr {
                obj: eid(obj),
                byte_offset: offset,
            },
        )
    }

    fn deref(&mut self, address: u64, x: u32, size: u32, ty: u32) -> u32 {
        self.push_expression(address, ty, ExpressionKind::Deref { x: eid(x), size })
    }

    fn op(&mut self, address: u64, ctype: u32, x: u32, y: u32, z: u32, ty: u32) -> u32 {
        let kind = self.classify(ctype, x, y, z);
        self.push_expression(address, ty, kind)
    }

    /// Map a generic operator `ctype` to its expression kind. Assignment ctypes overlap
    /// the binary numeric range, so probe assignments first.
    fn classify(&mut self, ctype: u32, x: u32, y: u32, z: u32) -> ExpressionKind {
        if ctype == u32::from(StructuralTag::Insn) {
            return ExpressionKind::Internal;
        }
        let op16 = u16::try_from(ctype).ok();
        if let Some(op) = op16.and_then(|v| AssignmentOp::try_from(v).ok()) {
            return ExpressionKind::Assign {
                op,
                x: eid(x),
                y: eid(y),
            };
        }
        if let Some(op) = op16.and_then(|v| BinaryOp::try_from(v).ok()) {
            return ExpressionKind::Binary {
                op,
                x: eid(x),
                y: eid(y),
            };
        }
        if let Some(op) = op16.and_then(|v| UnaryOp::try_from(v).ok()) {
            return ExpressionKind::Unary { op, x: eid(x) };
        }
        match StructuralTag::try_from(ctype) {
            Ok(StructuralTag::Tern) => ExpressionKind::Ternary {
                cond: eid(x),
                then_: eid(y),
                else_: eid(z),
            },
            Ok(StructuralTag::Cast) => ExpressionKind::Cast { x: eid(x) },
            Ok(StructuralTag::Idx) => ExpressionKind::Index {
                array: eid(x),
                index: eid(y),
            },
            Ok(StructuralTag::Sizeof) => ExpressionKind::Sizeof(eid(x)),
            Ok(StructuralTag::Empty) => ExpressionKind::Empty,
            Ok(StructuralTag::Type) => ExpressionKind::TypeExpression,
            // Consumed by the early return above; collapsed the same way if it ever reaches here.
            Ok(StructuralTag::Insn) => ExpressionKind::Internal,
            Err(_) => {
                self.fail(ExtractError::UnknownExpressionTag { tag: ctype });
                ExpressionKind::Internal
            }
        }
    }

    fn block(&mut self, address: u64, kids: &[u32]) -> u32 {
        let kids = kids.iter().map(|&s| sid(s)).collect();
        self.push_statement(address, StatementKind::Block(kids))
    }

    fn expression_statement(&mut self, address: u64, e: u32) -> u32 {
        self.push_statement(address, StatementKind::Expression(eid(e)))
    }

    fn if_(&mut self, address: u64, cond: u32, then_s: u32, else_s: u32) -> u32 {
        self.push_statement(
            address,
            StatementKind::If {
                cond: eid(cond),
                then_: sid(then_s),
                else_: opt_s(else_s),
            },
        )
    }

    fn for_(&mut self, address: u64, init: u32, cond: u32, step: u32, body: u32) -> u32 {
        self.push_statement(
            address,
            StatementKind::For {
                init: opt_e(init),
                cond: opt_e(cond),
                step: opt_e(step),
                body: sid(body),
            },
        )
    }

    fn while_(&mut self, address: u64, cond: u32, body: u32) -> u32 {
        self.push_statement(
            address,
            StatementKind::While {
                cond: eid(cond),
                body: sid(body),
            },
        )
    }

    fn do_(&mut self, address: u64, body: u32, cond: u32) -> u32 {
        self.push_statement(
            address,
            StatementKind::Do {
                body: sid(body),
                cond: eid(cond),
            },
        )
    }

    fn switch(&mut self, address: u64, expression: u32, cases: Vec<Case>) -> u32 {
        self.push_statement(
            address,
            StatementKind::Switch {
                expression: eid(expression),
                cases,
            },
        )
    }

    fn return_(&mut self, address: u64, e: u32) -> u32 {
        self.push_statement(address, StatementKind::Return(opt_e(e)))
    }

    fn goto(&mut self, address: u64, label: i32) -> u32 {
        self.push_statement(address, StatementKind::Goto { label })
    }

    fn asm(&mut self, address: u64, addrs: &[u64]) -> u32 {
        let mut out = Vec::with_capacity(addrs.len());
        for &a in addrs {
            match Address::try_new(a) {
                Some(e) => out.push(e),
                None => self.fail(ExtractError::BadAddress),
            }
        }
        self.push_statement(address, StatementKind::Asm(out))
    }

    fn try_(&mut self, address: u64, body: u32, catches: &[u32]) -> u32 {
        let catches = catches.iter().map(|&s| sid(s)).collect();
        self.push_statement(
            address,
            StatementKind::Try {
                body: sid(body),
                catches,
            },
        )
    }

    fn throw(&mut self, address: u64, e: u32) -> u32 {
        self.push_statement(address, StatementKind::Throw(opt_e(e)))
    }

    fn break_(&mut self, address: u64) -> u32 {
        self.push_statement(address, StatementKind::Break)
    }

    fn continue_(&mut self, address: u64) -> u32 {
        self.push_statement(address, StatementKind::Continue)
    }

    fn empty_statement(&mut self, address: u64) -> u32 {
        self.push_statement(address, StatementKind::Empty)
    }

    fn push_local(&mut self, local: Local) {
        self.b.push_local(local);
    }

    fn finish(mut self, root: u32) -> Result<Ctree, ExtractError> {
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        // Type-side failures the builder recorded but can't name (it is error-type-agnostic):
        // an over-wide scalar left a placeholder in its place, or a named type was referenced
        // but never filled (it would stay `TypeShape::Unknown`). Surface them, don't ship a gap.
        if let Some(bytes) = self.b.types().too_wide() {
            return Err(ExtractError::ScalarTooWide { bytes });
        }
        let unfilled = self.b.types().unfilled();
        if unfilled != 0 {
            return Err(ExtractError::UnfilledType { count: unfilled });
        }
        Ok(self.b.finish(sid(root)))
    }
}

impl TypeSink for CallbackBuilder {
    fn type_builder(&mut self) -> &mut TypeBuilder {
        self.b.types_mut()
    }
}

/// The ctree walk drives the `cxx` type visitor over a raw pointer to the builder (so it can share
/// one provenance with the node context), which needs [`CallbackBuilder`] to be the sink itself
/// rather than a borrowed [`SinkAdapter`]. Each method forwards through a fresh adapter, so the
/// span-marshalling lives in one place; the trait is named by path so its methods don't shadow the
/// [`TypeSink`] ones the unit tests call on a [`CallbackBuilder`].
impl idakit_sys::TypeWalkSink for CallbackBuilder {
    fn scalar(&mut self, kind: u32, bytes: u32, signed: u32, size: u64, has_size: u32) -> u32 {
        idakit_sys::TypeWalkSink::scalar(
            &mut SinkAdapter(self),
            kind,
            bytes,
            signed,
            size,
            has_size,
        )
    }
    fn ptr(&mut self, target: u32, size: u64, has_size: u32) -> u32 {
        idakit_sys::TypeWalkSink::ptr(&mut SinkAdapter(self), target, size, has_size)
    }
    fn array(&mut self, elem: u32, nelems: u64, size: u64, has_size: u32) -> u32 {
        idakit_sys::TypeWalkSink::array(&mut SinkAdapter(self), elem, nelems, size, has_size)
    }
    fn func(&mut self, ret: u32, params: &[u32], vararg: u32) -> u32 {
        idakit_sys::TypeWalkSink::func(&mut SinkAdapter(self), ret, params, vararg)
    }
    fn opaque(&mut self, name: String) -> u32 {
        idakit_sys::TypeWalkSink::opaque(&mut SinkAdapter(self), name)
    }
    fn named_ref(&mut self, name: String) -> u32 {
        idakit_sys::TypeWalkSink::named_ref(&mut SinkAdapter(self), name)
    }
    fn anon(&mut self) -> u32 {
        idakit_sys::TypeWalkSink::anon(&mut SinkAdapter(self))
    }
    fn fill_struct(
        &mut self,
        id: u32,
        is_union: bool,
        members: &[MemberInfo],
        size: u64,
        has_size: u32,
    ) {
        idakit_sys::TypeWalkSink::fill_struct(
            &mut SinkAdapter(self),
            id,
            is_union,
            members,
            size,
            has_size,
        );
    }
    fn fill_enum(
        &mut self,
        id: u32,
        underlying: u32,
        consts: &[EnumConstInfo],
        size: u64,
        has_size: u32,
        is_bitmask: bool,
        repr_vtype: u32,
        repr_signed: bool,
        repr_leading_zeros: bool,
    ) {
        idakit_sys::TypeWalkSink::fill_enum(
            &mut SinkAdapter(self),
            id,
            underlying,
            consts,
            size,
            has_size,
            is_bitmask,
            repr_vtype,
            repr_signed,
            repr_leading_zeros,
        );
    }
    fn fill_typedef(&mut self, id: u32, underlying: u32) {
        idakit_sys::TypeWalkSink::fill_typedef(&mut SinkAdapter(self), id, underlying);
    }
}

/// The node half of the ctree walk: each method forwards its owned arguments into the matching
/// safe method above. Names, string literals, and comments arrive as owned `String`, decoded
/// leniently facade-side (IDA emits UTF-8; any undecodable unit is U+FFFD).
impl idakit_sys::CtreeSink for CallbackBuilder {
    fn e_num(&mut self, ea: u64, value: u64, ty: u32) -> u32 {
        self.num(ea, value, ty)
    }

    fn e_fnum(&mut self, ea: u64, value: f64, ty: u32) -> u32 {
        self.fnum(ea, value, ty)
    }

    fn e_obj(&mut self, ea: u64, target: u64, name: String, ty: u32) -> u32 {
        self.obj(ea, target, (!name.is_empty()).then_some(name), ty)
    }

    fn e_var(&mut self, ea: u64, idx: u32, ty: u32) -> u32 {
        self.var(ea, idx, ty)
    }

    fn e_str(&mut self, ea: u64, text: String, ty: u32) -> u32 {
        self.string(ea, text, ty)
    }

    fn e_helper(&mut self, ea: u64, name: String, ty: u32) -> u32 {
        self.helper(ea, name, ty)
    }

    fn e_call(&mut self, ea: u64, callee: u32, args: &[u32], ty: u32) -> u32 {
        self.call(ea, callee, args, ty)
    }

    fn e_memref(&mut self, ea: u64, obj: u32, offset: u32, ty: u32) -> u32 {
        self.memref(ea, obj, offset, ty)
    }

    fn e_memptr(&mut self, ea: u64, obj: u32, offset: u32, ty: u32) -> u32 {
        self.memptr(ea, obj, offset, ty)
    }

    fn e_deref(&mut self, ea: u64, x: u32, size: u32, ty: u32) -> u32 {
        self.deref(ea, x, size, ty)
    }

    fn e_op(&mut self, ea: u64, ctype: u32, x: u32, y: u32, z: u32, ty: u32) -> u32 {
        self.op(ea, ctype, x, y, z, ty)
    }

    fn s_block(&mut self, ea: u64, kids: &[u32]) -> u32 {
        self.block(ea, kids)
    }

    fn s_expr(&mut self, ea: u64, e: u32) -> u32 {
        self.expression_statement(ea, e)
    }

    fn s_if(&mut self, ea: u64, cond: u32, then_s: u32, else_s: u32) -> u32 {
        self.if_(ea, cond, then_s, else_s)
    }

    fn s_for(&mut self, ea: u64, init: u32, cond: u32, step: u32, body: u32) -> u32 {
        self.for_(ea, init, cond, step, body)
    }

    fn s_while(&mut self, ea: u64, cond: u32, body: u32) -> u32 {
        self.while_(ea, cond, body)
    }

    fn s_do(&mut self, ea: u64, body: u32, cond: u32) -> u32 {
        self.do_(ea, body, cond)
    }

    fn s_switch(
        &mut self,
        ea: u64,
        expr: u32,
        bodies: &[u32],
        value_counts: &[u32],
        values: &[u64],
    ) -> u32 {
        let mut pos = 0usize;
        let cases = bodies
            .iter()
            .zip(value_counts)
            .map(|(&body, &n)| {
                let n = n as usize;
                let vals = values[pos..pos + n].to_vec();
                pos += n;
                Case {
                    values: vals,
                    body: sid(body),
                }
            })
            .collect();
        self.switch(ea, expr, cases)
    }

    fn s_break(&mut self, ea: u64) -> u32 {
        self.break_(ea)
    }

    fn s_continue(&mut self, ea: u64) -> u32 {
        self.continue_(ea)
    }

    fn s_return(&mut self, ea: u64, e: u32) -> u32 {
        self.return_(ea, e)
    }

    fn s_goto(&mut self, ea: u64, label: i32) -> u32 {
        self.goto(ea, label)
    }

    fn s_asm(&mut self, ea: u64, addrs: &[u64]) -> u32 {
        self.asm(ea, addrs)
    }

    fn s_try(&mut self, ea: u64, body: u32, catches: &[u32]) -> u32 {
        self.try_(ea, body, catches)
    }

    fn s_throw(&mut self, ea: u64, e: u32) -> u32 {
        self.throw(ea, e)
    }

    fn s_empty(&mut self, ea: u64) -> u32 {
        self.empty_statement(ea)
    }

    fn l_lvar(
        &mut self,
        name: String,
        ty: u32,
        flags: u32,
        width: u32,
        comment: String,
        atype: u32,
        reg1: u32,
        reg2: u32,
        sval: i64,
        pieces: &[idakit_sys::LocPiece],
    ) {
        let pieces = pieces
            .iter()
            .map(|p| LocationPiece {
                location: LocalLocation::from_argloc(p.atype, p.reg, 0, p.sval, Vec::new()),
                offset: p.off,
                size: p.size,
            })
            .collect();
        let location = LocalLocation::from_argloc(atype, reg1, reg2, sval, pieces);
        let comment = (!comment.is_empty()).then_some(comment);
        let local = Local {
            name,
            ty: tid(ty),
            is_arg: flags & 1 != 0,
            is_result: flags & 2 != 0,
            is_byref: flags & 4 != 0,
            width,
            comment,
            location,
        };
        self.push_local(local);
    }
}

/// Walk a decompiled function's ctree into an owned [`Ctree`]. `cfunc` is a live handle from
/// [`DecompiledFunction`](crate::DecompiledFunction); the walk runs on this (kernel) thread and
/// copies everything it needs, so the result outlives the handle.
pub(crate) fn walk(cfunc: &idakit_sys::CFunc) -> Result<Ctree, ExtractError> {
    let mut cb = CallbackBuilder::new();
    // Derive both the node sink and the type sink from one raw pointer to `cb`, so the
    // per-callback reborrows (nodes via `nodes`, node types via `types`) share a provenance and
    // never conflict; the walk drives them one callback at a time.
    let cb_ptr: *mut CallbackBuilder = &raw mut cb;
    // SAFETY: `cb_ptr` points to the live, stack-local `cb` and outlives the walk; the walk is
    // single-threaded and non-reentrant, so the sink stays unaliased per callback.
    let mut nodes =
        unsafe { idakit_sys::CtreeVisitor::from_raw(cb_ptr as *mut dyn idakit_sys::CtreeSink) };
    // SAFETY: same provenance and non-reentrancy guarantee as `nodes`, for the node-type sink.
    let mut types = unsafe {
        idakit_sys::TypeWalkVisitor::from_raw(cb_ptr as *mut dyn idakit_sys::TypeWalkSink)
    };
    let tv_addr = (&mut types as *mut idakit_sys::TypeWalkVisitor) as usize;
    // SAFETY: `cfunc` is a live handle (a `&CFunc` cannot be null); `tv_addr` is `types`' own
    // address, reinterpreted back to a `TypeWalkVisitor&` on the C++ side for its own calls.
    let root = unsafe { idakit_sys::cfunc_walk_ctree(cfunc, &mut nodes, tv_addr) };
    cb.finish(root)
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use idakit_sys as sys;

    use super::*;
    use crate::types::{TypeMember, TypeShape};

    /// Raw operator-tag discriminants used by the operator tests.
    const COT_ASGADD: u32 = 6;
    const COT_ADD: u32 = 35;
    const COT_SUB: u32 = 36;
    const COT_NEG: u32 = 47;

    fn int_ty(cb: &mut CallbackBuilder) -> u32 {
        cb.scalar(3, 4, 1, 4, 1)
    }

    /// `{ return a + b; }`: operands then the add, a return, a block.
    #[test]
    fn builds_return_of_a_binary() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        let a = cb.var(0, 0, it);
        let b = cb.var(0, 1, it);
        let add = cb.op(0, COT_ADD, a, b, NONE, it);
        let ret = cb.return_(0, add);
        let blk = cb.block(0, &[ret]);
        let tree = cb.finish(blk).expect("well-formed");

        assert!(matches!(
            tree.statement(tree.root()).kind,
            StatementKind::Block(_)
        ));
        let kinds: Vec<&ExpressionKind> = tree.expressions().map(|(_, e)| &e.kind).collect();
        assert!(matches!(
            kinds[2],
            ExpressionKind::Binary {
                op: BinaryOp::Add,
                ..
            }
        ));
    }

    /// Operator-family dispatch: assignment / binary / unary ctypes land on the right
    /// variant (assignment ctypes overlap the binary numeric range, so order matters).
    #[test]
    fn dispatches_operator_families() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        let v0 = cb.var(0, 0, it);
        let v1 = cb.var(0, 1, it);
        let asg = cb.op(0, COT_ASGADD, v0, v1, NONE, it);
        let v2 = cb.var(0, 2, it);
        let v3 = cb.var(0, 3, it);
        let bin = cb.op(0, COT_SUB, v2, v3, NONE, it);
        let v4 = cb.var(0, 4, it);
        let un = cb.op(0, COT_NEG, v4, NONE, NONE, it);
        let s0 = cb.expression_statement(0, asg);
        let s1 = cb.expression_statement(0, bin);
        let s2 = cb.expression_statement(0, un);
        let blk = cb.block(0, &[s0, s1, s2]);
        let tree = cb.finish(blk).expect("well-formed");

        let kinds: Vec<&ExpressionKind> = tree.expressions().map(|(_, e)| &e.kind).collect();
        assert!(matches!(
            kinds[eid(asg).index()],
            ExpressionKind::Assign {
                op: AssignmentOp::AddAssign,
                ..
            }
        ));
        assert!(matches!(
            kinds[eid(bin).index()],
            ExpressionKind::Binary {
                op: BinaryOp::Sub,
                ..
            }
        ));
        assert!(matches!(
            kinds[eid(un).index()],
            ExpressionKind::Unary {
                op: UnaryOp::Neg,
                ..
            }
        ));
    }

    /// A call with two args, a helper callee, a string literal, and an int literal.
    #[test]
    fn builds_call_with_args() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        let callee = cb.helper(0, "printf".into(), it);
        let fmt = cb.string(0, "%d".into(), it);
        let n = cb.num(0, 42, it);
        let call = cb.call(0, callee, &[fmt, n], it);
        let s = cb.expression_statement(0, call);
        let blk = cb.block(0, &[s]);
        let tree = cb.finish(blk).expect("well-formed");

        assert!(let ExpressionKind::Call { callee, args } = &tree.expression(eid(call)).kind);
        assert!(
            matches!(tree.expression(*callee).kind, ExpressionKind::Helper(ref h) if h == "printf")
        );
        assert!(args.len() == 2);
        assert!(matches!(tree.expression(args[0]).kind, ExpressionKind::Str(ref s) if s == "%d"));
        assert!(matches!(
            tree.expression(args[1]).kind,
            ExpressionKind::Num(42)
        ));
    }

    /// `if` with and without an `else`, exercising the optional-child sentinel.
    #[test]
    fn builds_if_with_optional_else() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        let c0 = cb.var(0, 0, it);
        let c1 = cb.var(0, 1, it);
        let t0 = cb.break_(0);
        let t1 = cb.continue_(0);
        let els = cb.break_(0);
        let if_with = cb.if_(0, c0, t0, els);
        let if_without = cb.if_(0, c1, t1, NONE);
        let blk = cb.block(0, &[if_with, if_without]);
        let tree = cb.finish(blk).expect("well-formed");

        let statements: Vec<&StatementKind> = tree.statements().map(|(_, s)| &s.kind).collect();
        assert!(matches!(
            statements[sid(if_with).index()],
            StatementKind::If { else_: Some(_), .. }
        ));
        assert!(matches!(
            statements[sid(if_without).index()],
            StatementKind::If { else_: None, .. }
        ));
    }

    /// `for`, `switch` (with the case-values pool), `try`/catches, and `asm`: the
    /// variadic statements whose child wiring is easiest to get wrong.
    #[test]
    fn builds_variadic_statements() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);

        // for (; cond; ) body; only the condition present.
        let cond = cb.var(0, 0, it);
        let body = cb.break_(0);
        let for_s = cb.for_(0, NONE, cond, NONE, body);

        // switch (sw) { case 1, 2: b1; default: b2; }
        let sw = cb.var(0, 1, it);
        let b1 = cb.break_(0);
        let b2 = cb.continue_(0);
        let cases = vec![
            Case {
                values: vec![1, 2],
                body: sid(b1),
            },
            Case {
                values: vec![],
                body: sid(b2),
            },
        ];
        let switch_s = cb.switch(0, sw, cases);

        // try guarded { } catch { }
        let guard = cb.block(0, &[]);
        let catch = cb.block(0, &[]);
        let try_s = cb.try_(0, guard, &[catch]);

        // asm at two addresses
        let asm_s = cb.asm(0, &[0x1000, 0x1004]);

        let blk = cb.block(0, &[for_s, switch_s, try_s, asm_s]);
        let tree = cb.finish(blk).expect("well-formed");

        let get = |s: u32| tree.statement(sid(s)).kind.clone();
        assert!(matches!(
            get(for_s),
            StatementKind::For {
                init: None,
                cond: Some(_),
                step: None,
                ..
            }
        ));
        assert!(let StatementKind::Switch { cases, .. } = get(switch_s));
        assert!(cases.len() == 2);
        assert!(cases[0].values == vec![1, 2]);
        assert!(cases[1].values.is_empty());
        assert!(let StatementKind::Try { catches, .. } = get(try_s));
        assert!(catches.len() == 1);
        assert!(let StatementKind::Asm(addrs) = get(asm_s));
        assert!(addrs.len() == 2);
    }

    /// A recursive aggregate: `struct Node { Node *next; }`. The placeholder lets the
    /// member pointer resolve back to the struct before its body is filled.
    #[test]
    fn builds_recursive_struct() {
        let mut cb = CallbackBuilder::new();
        let node = cb.named_ref("Node".into());
        let ptr = cb.ptr(node, 8, 1);
        let members = vec![TypeMember {
            name: "next".into(),
            bit_offset: 0,
            ty: tid(ptr),
            bitfield_width: None,
            repr: None,
        }];
        cb.fill_struct(node, false, members, 8, 1);

        // a variable typed as the struct, so the tree has a reachable node.
        let v = cb.var(0, 0, node);
        let s = cb.expression_statement(0, v);
        let blk = cb.block(0, &[s]);
        let tree = cb.finish(blk).expect("well-formed");

        assert!(let TypeShape::Struct { name, members } = &tree.type_of(tid(node)).shape);
        assert!(name.as_deref() == Some("Node"));
        assert!(members.len() == 1);
        assert!(members[0].name == "next");
        // the member pointer resolves back to the struct itself
        assert!(matches!(tree.type_of(members[0].ty).shape, TypeShape::Ptr(t) if t == tid(node)));
    }

    /// A typedef keeps its alias name and points at the (separately interned) underlying.
    #[test]
    fn typedef_wraps_its_underlying() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        let alias = cb.named_ref("size_t".into());
        cb.fill_typedef(alias, it);

        let v = cb.var(0, 0, alias);
        let s = cb.expression_statement(0, v);
        let blk = cb.block(0, &[s]);
        let tree = cb.finish(blk).expect("well-formed");

        let alias_ty = tree.type_of(tid(alias));
        assert!(let TypeShape::Typedef { name, underlying } = &alias_ty.shape);
        assert!(name == "size_t");
        assert!(matches!(
            tree.type_of(*underlying).shape,
            TypeShape::Int { bytes: 4, .. }
        ));
        // the alias adopts its target's size, so the node is self-describing
        assert!(alias_ty.size == Some(4));
    }

    /// A second reference to the same named type returns the same handle.
    #[test]
    fn named_types_dedup_by_name() {
        let mut cb = CallbackBuilder::new();
        let a = cb.named_ref("Foo".into());
        let b = cb.named_ref("Foo".into());
        assert!(a == b);
    }

    /// A bodyless named type resolves to an `Opaque` leaf carrying its name: a complete,
    /// non-placeholder type. `finish` accepts it (no leftover `Unknown`), and a repeat
    /// name dedups to one handle.
    #[test]
    fn opaque_type_carries_its_name() {
        let mut cb = CallbackBuilder::new();
        let fwd = cb.opaque("SomeHandle".into());
        assert!(fwd == cb.opaque("SomeHandle".into()));

        let v = cb.var(0, 0, fwd);
        let s = cb.expression_statement(0, v);
        let blk = cb.block(0, &[s]);
        let tree = cb.finish(blk).expect("opaque is a complete type");

        assert!(let TypeShape::Opaque(name) = &tree.type_of(tid(fwd)).shape);
        assert!(name == "SomeHandle");
    }

    /// Completeness: every structural tag round-trips through its raw value, so a `TryFrom` that
    /// stops agreeing with `Into` fails here. Both derives read one discriminant list, so this
    /// says nothing about whether that list matches the SDK; `structural_tag_ids_align_with_the_facade`
    /// is what pins it.
    #[test]
    fn structural_tag_every_variant_round_trips() {
        for &tag in StructuralTag::VARIANTS {
            assert!(StructuralTag::try_from(u32::from(tag)) == Ok(tag));
        }
    }

    /// Pin the tags to the facade's reported `ctype_t` values: the facade lists them in this
    /// enum's discriminant order, so a header renumbering mismatches and a variant added without
    /// a facade entry trips the length check. Pure constant source, no kernel, so it runs as a
    /// unit test.
    #[test]
    fn structural_tag_ids_align_with_the_facade() {
        let ids = sys::structural_tag_ctype_ids();
        assert!(
            ids.len() == StructuralTag::VARIANTS.len(),
            "facade lists {} ids for {} variants",
            ids.len(),
            StructuralTag::VARIANTS.len()
        );
        for (i, &tag) in StructuralTag::VARIANTS.iter().enumerate() {
            assert!(
                ids[i] == u32::from(tag),
                "structural tag {tag:?}: facade ctype_t {} != discriminant {}",
                ids[i],
                u32::from(tag)
            );
        }
    }

    /// An unmodeled ctype is a loud error (the `Internal` fallback is reserved for
    /// `cot_insn`), surfaced at `finish`.
    #[test]
    fn rejects_unknown_ctype() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        let v = cb.var(0, 0, it);
        let bad = cb.op(0, 999, v, NONE, NONE, it);
        let s = cb.expression_statement(0, bad);
        let blk = cb.block(0, &[s]);
        assert!(cb.finish(blk).err() == Some(ExtractError::UnknownExpressionTag { tag: 999 }));
    }

    /// `cot_insn` (a statement in expression position) collapses to `Internal` instead of
    /// erroring, the one allowance, since a finalized tree never contains it.
    #[test]
    fn cot_insn_collapses_to_internal() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        let instruction = cb.op(0, u32::from(StructuralTag::Insn), NONE, NONE, NONE, it);
        let s = cb.expression_statement(0, instruction);
        let blk = cb.block(0, &[s]);
        let tree = cb.finish(blk).expect("internal is not an error");
        assert!(matches!(
            tree.expression(eid(instruction)).kind,
            ExpressionKind::Internal
        ));
    }

    /// A float literal carries its real value, round-tripped through `fnum`.
    #[test]
    #[expect(
        clippy::float_cmp,
        reason = "3.5 round-trips exactly through f64; this is a bitwise round-trip check"
    )]
    fn float_literal_round_trips() {
        let mut cb = CallbackBuilder::new();
        let ft = cb.scalar(4, 8, 0, 8, 1);
        let f = cb.fnum(0, 3.5, ft);
        let s = cb.expression_statement(0, f);
        let blk = cb.block(0, &[s]);
        let tree = cb.finish(blk).expect("well-formed");
        assert!(matches!(tree.expression(eid(f)).kind, ExpressionKind::Fnum(v) if v == 3.5));
    }

    /// Locals land in the table in push order and `Var` resolves to them.
    #[test]
    fn locals_resolve_through_the_table() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        cb.push_local(Local {
            name: "argc".into(),
            ty: tid(it),
            is_arg: true,
            is_result: false,
            is_byref: false,
            width: 4,
            comment: None,
            location: LocalLocation::Stack(-4),
        });
        let v = cb.var(0, 0, it);
        let s = cb.expression_statement(0, v);
        let blk = cb.block(0, &[s]);
        let tree = cb.finish(blk).expect("well-formed");

        assert!(let ExpressionKind::Var(id) = &tree.expression(eid(v)).kind);
        let lv = tree.local(*id);
        assert!(lv.name == "argc");
        assert!(lv.is_arg);
        assert!(lv.location == LocalLocation::Stack(-4));
    }

    /// Drive the [`idakit_sys::CtreeSink`] node callbacks that finalized decompiler output rarely
    /// carries (member accesses on untyped pointers, string literals, `continue`/`goto`/asm/
    /// `throw`/`try`), asserting each returned handle resolves to its own node. Two wired-in
    /// leaders keep every target off handles 0 and 1, so a callback that returns a constant handle
    /// mis-threads its node and trips the match.
    #[test]
    fn sink_node_callbacks_thread_their_handles() {
        use sys::CtreeSink;

        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        let v0 = cb.var(0, 0, it);
        let v1 = cb.var(0, 1, it);

        let mref = CtreeSink::e_memref(&mut cb, 0, v0, 4, it);
        let mptr = CtreeSink::e_memptr(&mut cb, 0, v1, 8, it);
        let text = CtreeSink::e_str(&mut cb, 0, "lit".into(), it);
        let thrown = cb.num(0, 7, it);

        let s_mref = cb.expression_statement(0, mref);
        let s_mptr = cb.expression_statement(0, mptr);
        let s_text = cb.expression_statement(0, text);
        let cont = CtreeSink::s_continue(&mut cb, 0);
        let go = CtreeSink::s_goto(&mut cb, 0, 42);
        let asm = CtreeSink::s_asm(&mut cb, 0, &[0x1000, 0x1004]);
        let thr = CtreeSink::s_throw(&mut cb, 0, thrown);
        let guard = cb.block(0, &[]);
        let catch = cb.block(0, &[]);
        let tri = CtreeSink::s_try(&mut cb, 0, guard, &[catch]);

        let blk = cb.block(0, &[s_mref, s_mptr, s_text, cont, go, asm, thr, tri]);
        let tree = cb.finish(blk).expect("well-formed");

        assert!(matches!(
            tree.expression(eid(mref)).kind,
            ExpressionKind::MemberRef { byte_offset: 4, .. }
        ));
        assert!(matches!(
            tree.expression(eid(mptr)).kind,
            ExpressionKind::MemberPtr { byte_offset: 8, .. }
        ));
        assert!(
            matches!(tree.expression(eid(text)).kind, ExpressionKind::Str(ref s) if s == "lit")
        );
        assert!(matches!(
            tree.statement(sid(cont)).kind,
            StatementKind::Continue
        ));
        assert!(matches!(
            tree.statement(sid(go)).kind,
            StatementKind::Goto { label: 42 }
        ));
        assert!(let StatementKind::Asm(addrs) = &tree.statement(sid(asm)).kind);
        assert!(addrs.len() == 2);
        assert!(matches!(
            tree.statement(sid(thr)).kind,
            StatementKind::Throw(Some(_))
        ));
        assert!(let StatementKind::Try { catches, .. } = &tree.statement(sid(tri)).kind);
        assert!(catches.len() == 1);
    }

    /// Drive the [`idakit_sys::TypeWalkSink`] forwarders (the ones the ctree walk uses, distinct
    /// from the [`TypeSink`] methods the other tests call) and assert each builds its shape.
    /// `named_ref` dedups by name, so a constant return collapses the three distinct named types
    /// onto one handle; `anon` must hand out a fresh handle each call; a no-op `fill_*` leaves an
    /// unfilled placeholder that `finish` rejects.
    #[test]
    fn type_walk_forwarders_build_their_shapes() {
        use sys::TypeWalkSink;

        let mut cb = CallbackBuilder::new();
        let int = int_ty(&mut cb);

        let arr = TypeWalkSink::array(&mut cb, int, 3, 12, 1);
        let func = TypeWalkSink::func(&mut cb, int, &[int, int], 0);
        let opq = TypeWalkSink::opaque(&mut cb, "Handle".into());

        let node = TypeWalkSink::named_ref(&mut cb, "Node".into());
        let members = vec![MemberInfo {
            name: "v".into(),
            bit_offset: 0,
            ty: int,
            bitfield_width: 0,
            repr_vtype: 0,
            repr_signed: false,
            repr_leading_zeros: false,
        }];
        TypeWalkSink::fill_struct(&mut cb, node, false, &members, 4, 1);

        let color = TypeWalkSink::named_ref(&mut cb, "Color".into());
        let consts = vec![EnumConstInfo {
            name: "RED".into(),
            value: 1,
        }];
        TypeWalkSink::fill_enum(&mut cb, color, int, &consts, 4, 1, false, 0, false, false);

        let alias = TypeWalkSink::named_ref(&mut cb, "myint".into());
        TypeWalkSink::fill_typedef(&mut cb, alias, int);

        let a1 = TypeWalkSink::anon(&mut cb);
        let a2 = TypeWalkSink::anon(&mut cb);
        assert!(a1 != a2, "anon reused a handle: {a1} == {a2}");
        TypeWalkSink::fill_struct(&mut cb, a1, false, &[], 0, 1);
        TypeWalkSink::fill_struct(&mut cb, a2, true, &[], 0, 1);

        // The three named types must stay distinct; a constant `named_ref` collapses them.
        assert!(node != color && node != alias && color != alias);

        let blk = cb.block(0, &[]);
        let tree = cb.finish(blk).expect("every placeholder filled");

        assert!(matches!(
            tree.type_of(tid(arr)).shape,
            TypeShape::Array { .. }
        ));
        assert!(matches!(
            tree.type_of(tid(func)).shape,
            TypeShape::Function { .. }
        ));
        assert!(let TypeShape::Opaque(name) = &tree.type_of(tid(opq)).shape);
        assert!(name == "Handle");
        assert!(let TypeShape::Struct { name, members } = &tree.type_of(tid(node)).shape);
        assert!(name.as_deref() == Some("Node") && members.len() == 1);
        assert!(let TypeShape::Enum { name, .. } = &tree.type_of(tid(color)).shape);
        assert!(name.as_deref() == Some("Color"));
        assert!(let TypeShape::Typedef { name, .. } = &tree.type_of(tid(alias)).shape);
        assert!(name == "myint");
    }
}
