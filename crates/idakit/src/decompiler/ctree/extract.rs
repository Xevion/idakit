//! Building a [`Ctree`] from the facade's streaming ctree walk.
//!
//! The facade ([`idakit_sys::idakit_cfunc_walk_ctree`]) is a pure SDK walker, reading a
//! decompiled function depth-first and, per node, calling one callback in [`VTBL`] to mint
//! the owned node. Children are emitted before their parents, so each callback receives
//! its children as the handles their own callbacks returned. [`CallbackBuilder`] holds
//! the in-progress arenas; the `extern "C"` shims are thin adapters that decode the FFI
//! arguments and call its safe methods (which the tests drive directly).
//!
//! All identity and meaning live here, not in the facade: an operator's `ctype` maps to
//! [`BinaryOp`]/[`AssignmentOp`]/[`UnaryOp`] (their discriminants *are* the ctype values) or one of
//! the structural [`ct`] constants; named aggregate types are interned by name with a
//! placeholder so recursion resolves; structural types dedup through the type table.

use std::ffi::{c_char, c_void};

use idakit_sys::{CaseDesc, EmitVtbl, IDAKIT_NONE, LvarLoc};
use snafu::Snafu;

use super::node::{
    Case, ExpressionId, ExpressionKind, Local, LocalId, LocalLocation, LocationPiece, StatementId,
    StatementKind,
};
use super::ops::{AssignmentOp, BinaryOp, UnaryOp};
use super::tree::{Ctree, CtreeBuilder};
use crate::address::Address;
use crate::arena::Idx;
use crate::ffi::{lossy, slice};
use crate::types::{TypeBuilder, TypeSink, raw, tid, type_vtbl};

/// Structural `ctype_t` values the generic operator callback dispatches by name
/// (operators proper go through the `TryFrom<u16>` derives).
mod ct {
    pub const EMPTY: u32 = 0;
    pub const TERN: u32 = 16;
    pub const CAST: u32 = 48;
    pub const IDX: u32 = 58;
    /// `cot_insn`: a statement in expression position. Never present in a finalized tree;
    /// collapsed to [`ExpressionKind::Internal`](super::ExpressionKind::Internal) rather than erroring.
    pub const INSN: u32 = 66;
    pub const SIZEOF: u32 = 67;
    pub const TYPE: u32 = 69;
}

/// Why a ctree walk could not be turned into a [`Ctree`].
#[derive(Debug, Snafu, PartialEq, Eq)]
pub enum ExtractError {
    /// The facade returned no walkable ctree (a null `cfunc`).
    #[snafu(display("the facade could not walk the ctree (null cfunc)"))]
    WalkFailed,

    /// A node carried an expression `ctype` the walker does not model.
    #[snafu(display("unmodeled expression ctype {tag}"))]
    UnknownExpressionTag {
        /// The unmodeled raw `ctype_t` value.
        tag: u32,
    },

    /// A node required an address but carried the `BADADDR` sentinel.
    #[snafu(display("a node carries the BADADDR sentinel as a required address"))]
    BadEa,

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
fn node_ea(raw: u64) -> Option<Address> {
    Address::try_new(raw)
}

fn eid(raw: u32) -> ExpressionId {
    Idx::from_raw(raw)
}

fn sid(raw: u32) -> StatementId {
    Idx::from_raw(raw)
}

fn opt_e(raw: u32) -> Option<ExpressionId> {
    (raw != IDAKIT_NONE).then(|| eid(raw))
}

fn opt_s(raw: u32) -> Option<StatementId> {
    (raw != IDAKIT_NONE).then(|| sid(raw))
}

/// Accumulates the owned ctree as the facade walks. Its methods are the safe surface the
/// `extern "C"` shims (and the unit tests) call; each returns the new node's handle as a
/// bare `u32` for the facade to thread to the parent. Node building lives here; type
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
            .maybe_address(node_ea(address))
            .call())
    }

    fn push_statement(&mut self, address: u64, kind: StatementKind) -> u32 {
        raw(self
            .b
            .statement(kind)
            .maybe_address(node_ea(address))
            .call())
    }

    fn num(&mut self, address: u64, value: u64, ty: u32) -> u32 {
        self.push_expression(address, ty, ExpressionKind::Num(value))
    }

    fn fnum(&mut self, address: u64, value: f64, ty: u32) -> u32 {
        self.push_expression(address, ty, ExpressionKind::Fnum(value))
    }

    fn obj(&mut self, address: u64, target: u64, name: Option<String>, ty: u32) -> u32 {
        match Address::try_new(target) {
            Some(addr) => self.push_expression(
                address,
                ty,
                ExpressionKind::Obj {
                    address: addr,
                    name,
                },
            ),
            None => {
                self.fail(ExtractError::BadEa);
                self.push_expression(address, ty, ExpressionKind::Empty)
            }
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
        if ctype == ct::INSN {
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
        match ctype {
            ct::TERN => ExpressionKind::Ternary {
                cond: eid(x),
                then_: eid(y),
                else_: eid(z),
            },
            ct::CAST => ExpressionKind::Cast { x: eid(x) },
            ct::IDX => ExpressionKind::Index {
                array: eid(x),
                index: eid(y),
            },
            ct::SIZEOF => ExpressionKind::Sizeof(eid(x)),
            ct::EMPTY => ExpressionKind::Empty,
            ct::TYPE => ExpressionKind::TypeExpression,
            other => {
                self.fail(ExtractError::UnknownExpressionTag { tag: other });
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
                None => self.fail(ExtractError::BadEa),
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

    fn push_lvar(&mut self, lvar: Local) {
        self.b.push_lvar(lvar);
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

/// Reborrow the opaque context as the builder the walk threads through every callback. The
/// raw pointer is taken by reference so the returned lifetime is tied to its (stack) holder
/// and cannot be chosen as `'static`.
///
/// # Safety
/// `*ctx` must be the `*mut CallbackBuilder` passed to `idakit_cfunc_walk_ctree`, unaliased
/// for the call (the walk is single-threaded and never re-enters a callback).
// Reborrowing a `&mut` from a `&` (clippy::mut_from_ref) is intentional: taking `ctx` by
// reference bounds the returned lifetime to its stack holder (see above), and the
// single-threaded, non-re-entrant walk guarantees the builder is unaliased for each call.
#[allow(clippy::mut_from_ref)]
unsafe fn builder(ctx: &*mut c_void) -> &mut CallbackBuilder {
    unsafe { &mut *(*ctx as *mut CallbackBuilder) }
}

unsafe extern "C" fn cb_num(ctx: *mut c_void, address: u64, value: u64, ty: u32) -> u32 {
    unsafe { builder(&ctx) }.num(address, value, ty)
}
unsafe extern "C" fn cb_fnum(ctx: *mut c_void, address: u64, value: f64, ty: u32) -> u32 {
    unsafe { builder(&ctx) }.fnum(address, value, ty)
}
unsafe extern "C" fn cb_obj(
    ctx: *mut c_void,
    address: u64,
    target: u64,
    name: *const c_char,
    name_len: usize,
    ty: u32,
) -> u32 {
    let name = unsafe { lossy(name, name_len) };
    unsafe { builder(&ctx) }.obj(address, target, name, ty)
}
unsafe extern "C" fn cb_var(ctx: *mut c_void, address: u64, idx: u32, ty: u32) -> u32 {
    unsafe { builder(&ctx) }.var(address, idx, ty)
}
unsafe extern "C" fn cb_str(
    ctx: *mut c_void,
    address: u64,
    s: *const c_char,
    len: usize,
    ty: u32,
) -> u32 {
    let s = unsafe { lossy(s, len) }.unwrap_or_default();
    unsafe { builder(&ctx) }.string(address, s, ty)
}
unsafe extern "C" fn cb_helper(
    ctx: *mut c_void,
    address: u64,
    s: *const c_char,
    len: usize,
    ty: u32,
) -> u32 {
    let s = unsafe { lossy(s, len) }.unwrap_or_default();
    unsafe { builder(&ctx) }.helper(address, s, ty)
}
unsafe extern "C" fn cb_call(
    ctx: *mut c_void,
    address: u64,
    callee: u32,
    args: *const u32,
    nargs: usize,
    ty: u32,
) -> u32 {
    let args = unsafe { slice(&args, nargs) };
    unsafe { builder(&ctx) }.call(address, callee, args, ty)
}
unsafe extern "C" fn cb_memref(
    ctx: *mut c_void,
    address: u64,
    obj: u32,
    offset: u32,
    ty: u32,
) -> u32 {
    unsafe { builder(&ctx) }.memref(address, obj, offset, ty)
}
unsafe extern "C" fn cb_memptr(
    ctx: *mut c_void,
    address: u64,
    obj: u32,
    offset: u32,
    ty: u32,
) -> u32 {
    unsafe { builder(&ctx) }.memptr(address, obj, offset, ty)
}
unsafe extern "C" fn cb_deref(ctx: *mut c_void, address: u64, x: u32, size: u32, ty: u32) -> u32 {
    unsafe { builder(&ctx) }.deref(address, x, size, ty)
}
unsafe extern "C" fn cb_op(
    ctx: *mut c_void,
    address: u64,
    ctype: u32,
    x: u32,
    y: u32,
    z: u32,
    ty: u32,
) -> u32 {
    unsafe { builder(&ctx) }.op(address, ctype, x, y, z, ty)
}

unsafe extern "C" fn cb_block(
    ctx: *mut c_void,
    address: u64,
    kids: *const u32,
    nkids: usize,
) -> u32 {
    let kids = unsafe { slice(&kids, nkids) };
    unsafe { builder(&ctx) }.block(address, kids)
}
unsafe extern "C" fn cb_expr(ctx: *mut c_void, address: u64, e: u32) -> u32 {
    unsafe { builder(&ctx) }.expression_statement(address, e)
}
unsafe extern "C" fn cb_if(
    ctx: *mut c_void,
    address: u64,
    cond: u32,
    then_s: u32,
    else_s: u32,
) -> u32 {
    unsafe { builder(&ctx) }.if_(address, cond, then_s, else_s)
}
unsafe extern "C" fn cb_for(
    ctx: *mut c_void,
    address: u64,
    init: u32,
    cond: u32,
    step: u32,
    body: u32,
) -> u32 {
    unsafe { builder(&ctx) }.for_(address, init, cond, step, body)
}
unsafe extern "C" fn cb_while(ctx: *mut c_void, address: u64, cond: u32, body: u32) -> u32 {
    unsafe { builder(&ctx) }.while_(address, cond, body)
}
unsafe extern "C" fn cb_do(ctx: *mut c_void, address: u64, body: u32, cond: u32) -> u32 {
    unsafe { builder(&ctx) }.do_(address, body, cond)
}
unsafe extern "C" fn cb_switch(
    ctx: *mut c_void,
    address: u64,
    expression: u32,
    cases: *const CaseDesc,
    ncases: usize,
) -> u32 {
    let cds = unsafe { slice(&cases, ncases) };
    let cases = cds
        .iter()
        .map(|cd| Case {
            values: unsafe { slice(&cd.values, cd.nvalues) }.to_vec(),
            body: sid(cd.body),
        })
        .collect();
    unsafe { builder(&ctx) }.switch(address, expression, cases)
}
unsafe extern "C" fn cb_break(ctx: *mut c_void, address: u64) -> u32 {
    unsafe { builder(&ctx) }.break_(address)
}
unsafe extern "C" fn cb_continue(ctx: *mut c_void, address: u64) -> u32 {
    unsafe { builder(&ctx) }.continue_(address)
}
unsafe extern "C" fn cb_return(ctx: *mut c_void, address: u64, e: u32) -> u32 {
    unsafe { builder(&ctx) }.return_(address, e)
}
unsafe extern "C" fn cb_goto(ctx: *mut c_void, address: u64, label: i32) -> u32 {
    unsafe { builder(&ctx) }.goto(address, label)
}
unsafe extern "C" fn cb_asm(ctx: *mut c_void, address: u64, addrs: *const u64, n: usize) -> u32 {
    let addrs = unsafe { slice(&addrs, n) };
    unsafe { builder(&ctx) }.asm(address, addrs)
}
unsafe extern "C" fn cb_try(
    ctx: *mut c_void,
    address: u64,
    body: u32,
    catches: *const u32,
    n: usize,
) -> u32 {
    let catches = unsafe { slice(&catches, n) };
    unsafe { builder(&ctx) }.try_(address, body, catches)
}
unsafe extern "C" fn cb_throw(ctx: *mut c_void, address: u64, e: u32) -> u32 {
    unsafe { builder(&ctx) }.throw(address, e)
}
unsafe extern "C" fn cb_empty(ctx: *mut c_void, address: u64) -> u32 {
    unsafe { builder(&ctx) }.empty_statement(address)
}

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn cb_lvar(
    ctx: *mut c_void,
    name: *const c_char,
    name_len: usize,
    ty: u32,
    flags: u32,
    width: u32,
    comment: *const c_char,
    comment_len: usize,
    loc: *const LvarLoc,
) {
    // SAFETY: `loc` is a valid, non-null pointer for the duration of this call (facade invariant).
    let loc = unsafe { &*loc };
    // ALOC_DIST (2): read the scattered fragments; each is a scalar (register/stack) argloc.
    let pieces = if loc.atype == 2 && !loc.pieces.is_null() {
        // SAFETY: `pieces` points at `npieces` valid `LocPiece`, live for this call.
        let raw = unsafe { slice(&loc.pieces, loc.npieces as usize) };
        raw.iter()
            .map(|p| LocationPiece {
                location: LocalLocation::from_argloc(p.atype, p.reg, 0, p.sval, Vec::new()),
                offset: p.off,
                size: p.size,
            })
            .collect()
    } else {
        Vec::new()
    };
    let location = LocalLocation::from_argloc(loc.atype, loc.reg1, loc.reg2, loc.sval, pieces);
    let lvar = Local {
        name: unsafe { lossy(name, name_len) }.unwrap_or_default(),
        ty: tid(ty),
        is_arg: flags & 1 != 0,
        is_result: flags & 2 != 0,
        is_byref: flags & 4 != 0,
        width,
        comment: unsafe { lossy(comment, comment_len) },
        location,
    };
    unsafe { builder(&ctx) }.push_lvar(lvar);
}

/// The callback table handed to the facade. Field order matches `idakit_emit_vtbl_t`.
static VTBL: EmitVtbl = EmitVtbl {
    e_num: cb_num,
    e_fnum: cb_fnum,
    e_obj: cb_obj,
    e_var: cb_var,
    e_str: cb_str,
    e_helper: cb_helper,
    e_call: cb_call,
    e_memref: cb_memref,
    e_memptr: cb_memptr,
    e_deref: cb_deref,
    e_op: cb_op,
    s_block: cb_block,
    s_expr: cb_expr,
    s_if: cb_if,
    s_for: cb_for,
    s_while: cb_while,
    s_do: cb_do,
    s_switch: cb_switch,
    s_break: cb_break,
    s_continue: cb_continue,
    s_return: cb_return,
    s_goto: cb_goto,
    s_asm: cb_asm,
    s_try: cb_try,
    s_throw: cb_throw,
    s_empty: cb_empty,
    types: type_vtbl::<CallbackBuilder>(),
    l_lvar: cb_lvar,
};

/// Walk a decompiled function's ctree into an owned [`Ctree`]. `cfunc` is a live
/// `idakit_decompile` handle (see [`DecompiledFunction`](crate::DecompiledFunction)); the walk runs on this (kernel)
/// thread and copies everything it needs, so the result outlives the handle.
pub(crate) fn walk(cfunc: *mut c_void) -> Result<Ctree, ExtractError> {
    let mut cb = CallbackBuilder::new();
    let mut root: u32 = 0;
    // SAFETY: `cfunc` is a live handle (caller's invariant); `VTBL` is static; `cb` is a
    // valid out-context borrowed only during the call; `root` is a valid out-param.
    let rc = unsafe {
        idakit_sys::idakit_cfunc_walk_ctree(
            cfunc,
            &VTBL,
            (&mut cb as *mut CallbackBuilder).cast(),
            &mut root,
        )
    };
    if rc != 0 {
        return Err(ExtractError::WalkFailed);
    }
    cb.finish(root)
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;
    use crate::types::{TypeMember, TypeShape};

    /// `cot_*` discriminants used by the operator tests (from hexrays.hpp).
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
        let add = cb.op(0, COT_ADD, a, b, IDAKIT_NONE, it);
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
        let asg = cb.op(0, COT_ASGADD, v0, v1, IDAKIT_NONE, it);
        let v2 = cb.var(0, 2, it);
        let v3 = cb.var(0, 3, it);
        let bin = cb.op(0, COT_SUB, v2, v3, IDAKIT_NONE, it);
        let v4 = cb.var(0, 4, it);
        let un = cb.op(0, COT_NEG, v4, IDAKIT_NONE, IDAKIT_NONE, it);
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
        let if_without = cb.if_(0, c1, t1, IDAKIT_NONE);
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

        // for (; cond; ) body;  -- only the condition present.
        let cond = cb.var(0, 0, it);
        let body = cb.break_(0);
        let for_s = cb.for_(0, IDAKIT_NONE, cond, IDAKIT_NONE, body);

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

    /// An unmodeled ctype is a loud error (the `Internal` fallback is reserved for
    /// `cot_insn`), surfaced at `finish`.
    #[test]
    fn rejects_unknown_ctype() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        let v = cb.var(0, 0, it);
        let bad = cb.op(0, 999, v, IDAKIT_NONE, IDAKIT_NONE, it);
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
        let instruction = cb.op(0, ct::INSN, IDAKIT_NONE, IDAKIT_NONE, IDAKIT_NONE, it);
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
    fn float_literal_round_trips() {
        let mut cb = CallbackBuilder::new();
        let ft = cb.scalar(4, 8, 0, 8, 1);
        let f = cb.fnum(0, 3.5, ft);
        let s = cb.expression_statement(0, f);
        let blk = cb.block(0, &[s]);
        let tree = cb.finish(blk).expect("well-formed");
        assert!(matches!(tree.expression(eid(f)).kind, ExpressionKind::Fnum(v) if v == 3.5));
    }

    /// Lvars land in the table in push order and `Var` resolves to them.
    #[test]
    fn lvars_resolve_through_the_table() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        cb.push_lvar(Local {
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
        let lv = tree.lvar(*id);
        assert!(lv.name == "argc");
        assert!(lv.is_arg);
        assert!(lv.location == LocalLocation::Stack(-4));
    }
}
