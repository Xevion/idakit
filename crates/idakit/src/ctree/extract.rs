//! Building a [`Ctree`] from the facade's streaming ctree walk.
//!
//! The facade ([`idakit_sys::idakit_cfunc_walk_ctree`]) is a pure SDK walker: it reads a
//! decompiled function depth-first and, per node, calls one callback in [`VTBL`] to mint
//! the owned node. Children are emitted before their parents, so each callback receives
//! its children as the handles their own callbacks returned. [`CallbackBuilder`] holds
//! the in-progress arenas; the `extern "C"` shims are thin adapters that decode the FFI
//! arguments and call its safe methods (which the tests drive directly).
//!
//! All identity and meaning live here, not in the facade: an operator's `ctype` maps to
//! [`BinOp`]/[`AssignOp`]/[`UnOp`] (their discriminants *are* the ctype values) or one of
//! the structural [`ct`] constants; named aggregate types are interned by name with a
//! placeholder so recursion resolves; structural types dedup through the type table.

use std::collections::HashMap;
use std::ffi::{c_char, c_void};

use idakit_sys::{CaseDesc, EmitVtbl, EnumConstDesc, IDAKIT_NONE, MemberDesc};
use snafu::Snafu;

use super::node::{Case, Cexpr, Cinsn, ExprId, Lvar, LvarId, LvarLocation, StmtId};
use super::ops::{AssignOp, BinOp, UnOp};
use super::tree::{Ctree, CtreeBuilder};
use super::types::{EnumMember, TypeData, TypeId, TypeKind, TypeMember};
use crate::Ea;
use crate::arena::Idx;

/// Structural `ctype_t` values the generic operator callback dispatches by name
/// (operators proper go through `from_raw`).
mod ct {
    pub const EMPTY: u32 = 0;
    pub const TERN: u32 = 16;
    pub const CAST: u32 = 48;
    pub const IDX: u32 = 58;
    /// `cot_insn`: a statement in expression position -- never present in a finalized
    /// tree, collapsed to [`Cexpr::Internal`](super::Cexpr::Internal) rather than erroring.
    pub const INSN: u32 = 66;
    pub const SIZEOF: u32 = 67;
    pub const TYPE: u32 = 69;
}

/// Scalar-kind tags the facade's `t_scalar` callback uses to pick a [`TypeKind`]; `0` is
/// the catch-all that maps to [`TypeKind::Unknown`](super::TypeKind::Unknown).
mod scalar_kind {
    pub const VOID: u32 = 1;
    pub const BOOL: u32 = 2;
    pub const INT: u32 = 3;
    pub const FLOAT: u32 = 4;
}

/// Why a ctree walk could not be turned into a [`Ctree`].
#[derive(Debug, Snafu, PartialEq, Eq)]
pub enum ExtractError {
    #[snafu(display("the facade could not walk the ctree (null cfunc)"))]
    WalkFailed,

    #[snafu(display("unmodeled expression ctype {tag}"))]
    UnknownExprTag { tag: u32 },

    #[snafu(display("a node carries the BADADDR sentinel as a required address"))]
    BadEa,

    #[snafu(display("a scalar reports {bytes} bytes, wider than any real scalar"))]
    ScalarTooWide { bytes: u32 },

    #[snafu(display("{count} type placeholder(s) were referenced but never filled"))]
    UnfilledType { count: usize },
}

/// A node's own source address: `None` for a synthetic node (the BADADDR sentinel).
fn node_ea(raw: u64) -> Option<Ea> {
    Ea::try_new(raw)
}

fn eid(raw: u32) -> ExprId {
    Idx::from_raw(raw)
}

fn sid(raw: u32) -> StmtId {
    Idx::from_raw(raw)
}

fn tid(raw: u32) -> TypeId {
    Idx::from_raw(raw)
}

fn opt_e(raw: u32) -> Option<ExprId> {
    (raw != IDAKIT_NONE).then(|| eid(raw))
}

fn opt_s(raw: u32) -> Option<StmtId> {
    (raw != IDAKIT_NONE).then(|| sid(raw))
}

fn raw<T>(id: Idx<T>) -> u32 {
    id.index() as u32
}

fn opt_size(size: u64, has_size: u32) -> Option<u64> {
    (has_size != 0).then_some(size)
}

/// Accumulates the owned ctree as the facade walks. Its methods are the safe surface the
/// `extern "C"` shims (and the unit tests) call; each returns the new node's handle as a
/// bare `u32` for the facade to thread to the parent.
pub(crate) struct CallbackBuilder {
    b: CtreeBuilder,
    /// Named aggregate/typedef -> its interned handle (recursion + dedup).
    name2type: HashMap<Box<str>, TypeId>,
    /// Placeholder handle -> its name (`None` = anonymous), pending its body.
    pending: HashMap<TypeId, Option<Box<str>>>,
    /// First deferred failure; checked at [`finish`](Self::finish).
    error: Option<ExtractError>,
}

impl CallbackBuilder {
    fn new() -> Self {
        Self {
            b: CtreeBuilder::new(),
            name2type: HashMap::new(),
            pending: HashMap::new(),
            error: None,
        }
    }

    /// Record a deferred failure. Only the first error is kept -- later failures in the
    /// same walk are dropped -- so callers must not assume every problem surfaces at
    /// [`finish`](Self::finish), only that a failed walk reports *some* error.
    fn fail(&mut self, e: ExtractError) {
        if self.error.is_none() {
            self.error = Some(e);
        }
    }

    fn push_expr(&mut self, ea: u64, ty: u32, kind: Cexpr) -> u32 {
        raw(self.b.expr(tid(ty), kind).maybe_ea(node_ea(ea)).call())
    }

    fn push_stmt(&mut self, ea: u64, kind: Cinsn) -> u32 {
        raw(self.b.stmt(kind).maybe_ea(node_ea(ea)).call())
    }

    fn num(&mut self, ea: u64, value: u64, ty: u32) -> u32 {
        self.push_expr(ea, ty, Cexpr::Num(value))
    }

    fn fnum(&mut self, ea: u64, value: f64, ty: u32) -> u32 {
        self.push_expr(ea, ty, Cexpr::Fnum(value))
    }

    fn obj(&mut self, ea: u64, target: u64, name: Option<String>, ty: u32) -> u32 {
        match Ea::try_new(target) {
            Some(addr) => self.push_expr(ea, ty, Cexpr::Obj { ea: addr, name }),
            None => {
                self.fail(ExtractError::BadEa);
                self.push_expr(ea, ty, Cexpr::Empty)
            }
        }
    }

    fn var(&mut self, ea: u64, idx: u32, ty: u32) -> u32 {
        self.push_expr(ea, ty, Cexpr::Var(LvarId(idx)))
    }

    fn string(&mut self, ea: u64, s: String, ty: u32) -> u32 {
        self.push_expr(ea, ty, Cexpr::Str(s))
    }

    fn helper(&mut self, ea: u64, s: String, ty: u32) -> u32 {
        self.push_expr(ea, ty, Cexpr::Helper(s))
    }

    fn call(&mut self, ea: u64, callee: u32, args: &[u32], ty: u32) -> u32 {
        let args = args.iter().map(|&a| eid(a)).collect();
        self.push_expr(
            ea,
            ty,
            Cexpr::Call {
                callee: eid(callee),
                args,
            },
        )
    }

    fn memref(&mut self, ea: u64, obj: u32, offset: u32, ty: u32) -> u32 {
        self.push_expr(
            ea,
            ty,
            Cexpr::MemberRef {
                obj: eid(obj),
                byte_offset: offset,
            },
        )
    }

    fn memptr(&mut self, ea: u64, obj: u32, offset: u32, ty: u32) -> u32 {
        self.push_expr(
            ea,
            ty,
            Cexpr::MemberPtr {
                obj: eid(obj),
                byte_offset: offset,
            },
        )
    }

    fn deref(&mut self, ea: u64, x: u32, size: u32, ty: u32) -> u32 {
        self.push_expr(ea, ty, Cexpr::Deref { x: eid(x), size })
    }

    fn op(&mut self, ea: u64, ctype: u32, x: u32, y: u32, z: u32, ty: u32) -> u32 {
        let kind = self.classify(ctype, x, y, z);
        self.push_expr(ea, ty, kind)
    }

    /// Map a generic operator `ctype` to its expression kind. Assignment ctypes overlap
    /// the binary numeric range, so probe assignments first.
    fn classify(&mut self, ctype: u32, x: u32, y: u32, z: u32) -> Cexpr {
        if ctype == ct::INSN {
            return Cexpr::Internal;
        }
        let op16 = u16::try_from(ctype).ok();
        if let Some(op) = op16.and_then(AssignOp::from_raw) {
            return Cexpr::Assign {
                op,
                x: eid(x),
                y: eid(y),
            };
        }
        if let Some(op) = op16.and_then(BinOp::from_raw) {
            return Cexpr::Binary {
                op,
                x: eid(x),
                y: eid(y),
            };
        }
        if let Some(op) = op16.and_then(UnOp::from_raw) {
            return Cexpr::Unary { op, x: eid(x) };
        }
        match ctype {
            ct::TERN => Cexpr::Ternary {
                cond: eid(x),
                then_: eid(y),
                else_: eid(z),
            },
            ct::CAST => Cexpr::Cast { x: eid(x) },
            ct::IDX => Cexpr::Index {
                array: eid(x),
                index: eid(y),
            },
            ct::SIZEOF => Cexpr::Sizeof(eid(x)),
            ct::EMPTY => Cexpr::Empty,
            ct::TYPE => Cexpr::TypeExpr,
            other => {
                self.fail(ExtractError::UnknownExprTag { tag: other });
                Cexpr::Internal
            }
        }
    }

    fn block(&mut self, ea: u64, kids: &[u32]) -> u32 {
        let kids = kids.iter().map(|&s| sid(s)).collect();
        self.push_stmt(ea, Cinsn::Block(kids))
    }

    fn expr_stmt(&mut self, ea: u64, e: u32) -> u32 {
        self.push_stmt(ea, Cinsn::Expr(eid(e)))
    }

    fn if_(&mut self, ea: u64, cond: u32, then_s: u32, else_s: u32) -> u32 {
        self.push_stmt(
            ea,
            Cinsn::If {
                cond: eid(cond),
                then_: sid(then_s),
                else_: opt_s(else_s),
            },
        )
    }

    fn for_(&mut self, ea: u64, init: u32, cond: u32, step: u32, body: u32) -> u32 {
        self.push_stmt(
            ea,
            Cinsn::For {
                init: opt_e(init),
                cond: opt_e(cond),
                step: opt_e(step),
                body: sid(body),
            },
        )
    }

    fn while_(&mut self, ea: u64, cond: u32, body: u32) -> u32 {
        self.push_stmt(
            ea,
            Cinsn::While {
                cond: eid(cond),
                body: sid(body),
            },
        )
    }

    fn do_(&mut self, ea: u64, body: u32, cond: u32) -> u32 {
        self.push_stmt(
            ea,
            Cinsn::Do {
                body: sid(body),
                cond: eid(cond),
            },
        )
    }

    fn switch(&mut self, ea: u64, expr: u32, cases: Vec<Case>) -> u32 {
        self.push_stmt(
            ea,
            Cinsn::Switch {
                expr: eid(expr),
                cases,
            },
        )
    }

    fn return_(&mut self, ea: u64, e: u32) -> u32 {
        self.push_stmt(ea, Cinsn::Return(opt_e(e)))
    }

    fn goto(&mut self, ea: u64, label: i32) -> u32 {
        self.push_stmt(ea, Cinsn::Goto { label })
    }

    fn asm(&mut self, ea: u64, addrs: &[u64]) -> u32 {
        let mut out = Vec::with_capacity(addrs.len());
        for &a in addrs {
            match Ea::try_new(a) {
                Some(e) => out.push(e),
                None => self.fail(ExtractError::BadEa),
            }
        }
        self.push_stmt(ea, Cinsn::Asm(out))
    }

    fn try_(&mut self, ea: u64, body: u32, catches: &[u32]) -> u32 {
        let catches = catches.iter().map(|&s| sid(s)).collect();
        self.push_stmt(
            ea,
            Cinsn::Try {
                body: sid(body),
                catches,
            },
        )
    }

    fn throw(&mut self, ea: u64, e: u32) -> u32 {
        self.push_stmt(ea, Cinsn::Throw(opt_e(e)))
    }

    fn break_(&mut self, ea: u64) -> u32 {
        self.push_stmt(ea, Cinsn::Break)
    }

    fn continue_(&mut self, ea: u64) -> u32 {
        self.push_stmt(ea, Cinsn::Continue)
    }

    fn empty_stmt(&mut self, ea: u64) -> u32 {
        self.push_stmt(ea, Cinsn::Empty)
    }

    fn scalar(&mut self, kind: u32, bytes: u32, signed: u32, size: u64, has_size: u32) -> u32 {
        let width = match u8::try_from(bytes) {
            Ok(w) => w,
            Err(_) => {
                self.fail(ExtractError::ScalarTooWide { bytes });
                0
            }
        };
        let kind = match kind {
            scalar_kind::VOID => TypeKind::Void,
            scalar_kind::BOOL => TypeKind::Bool,
            scalar_kind::INT => TypeKind::Int {
                bytes: width,
                signed: signed != 0,
            },
            scalar_kind::FLOAT => TypeKind::Float { bytes: width },
            _ => TypeKind::Unknown,
        };
        raw(self.b.intern_type(TypeData {
            kind,
            size: opt_size(size, has_size),
        }))
    }

    fn ptr(&mut self, target: u32, size: u64, has_size: u32) -> u32 {
        raw(self.b.intern_type(TypeData {
            kind: TypeKind::Ptr(tid(target)),
            size: opt_size(size, has_size),
        }))
    }

    fn array(&mut self, elem: u32, nelems: u64, size: u64, has_size: u32) -> u32 {
        raw(self.b.intern_type(TypeData {
            kind: TypeKind::Array {
                elem: tid(elem),
                len: nelems,
            },
            size: opt_size(size, has_size),
        }))
    }

    fn func(&mut self, ret: u32, params: &[u32], vararg: u32) -> u32 {
        let params = params.iter().map(|&p| tid(p)).collect();
        raw(self.b.intern_type(TypeData {
            kind: TypeKind::Func {
                ret: tid(ret),
                params,
                varargs: vararg != 0,
            },
            size: None,
        }))
    }

    fn named_ref(&mut self, name: String) -> u32 {
        if let Some(&id) = self.name2type.get(name.as_str()) {
            return raw(id);
        }
        let id = self.b.alloc_type_placeholder();
        let key: Box<str> = name.into_boxed_str();
        self.name2type.insert(key.clone(), id);
        self.pending.insert(id, Some(key));
        raw(id)
    }

    fn anon(&mut self) -> u32 {
        let id = self.b.alloc_type_placeholder();
        self.pending.insert(id, None);
        raw(id)
    }

    fn take_name(&mut self, id: TypeId) -> Option<String> {
        self.pending.remove(&id).flatten().map(String::from)
    }

    fn fill_struct(
        &mut self,
        id: u32,
        is_union: bool,
        members: Vec<TypeMember>,
        size: u64,
        has_size: u32,
    ) {
        let id = tid(id);
        let name = self.take_name(id);
        let kind = if is_union {
            TypeKind::Union { name, members }
        } else {
            TypeKind::Struct { name, members }
        };
        self.b.fill_type(
            id,
            TypeData {
                kind,
                size: opt_size(size, has_size),
            },
        );
    }

    fn fill_enum(
        &mut self,
        id: u32,
        underlying: u32,
        members: Vec<EnumMember>,
        size: u64,
        has_size: u32,
    ) {
        let id = tid(id);
        let name = self.take_name(id);
        self.b.fill_type(
            id,
            TypeData {
                kind: TypeKind::Enum {
                    name,
                    underlying: tid(underlying),
                    members,
                },
                size: opt_size(size, has_size),
            },
        );
    }

    fn fill_typedef(&mut self, id: u32, underlying: u32) {
        let id = tid(id);
        let underlying = tid(underlying);
        let name = self.take_name(id).unwrap_or_default();
        // A typedef is a transparent alias, so it adopts its target's size.
        let size = self.b.type_size(underlying);
        self.b.fill_type(
            id,
            TypeData {
                kind: TypeKind::Typedef { name, underlying },
                size,
            },
        );
    }

    fn push_lvar(&mut self, lvar: Lvar) {
        self.b.push_lvar(lvar);
    }

    fn finish(mut self, root: u32) -> Result<Ctree, ExtractError> {
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        // A placeholder left in `pending` was referenced but never filled, so it would
        // stay `TypeKind::Unknown` in the tree -- surface it rather than ship a silent gap.
        if !self.pending.is_empty() {
            return Err(ExtractError::UnfilledType {
                count: self.pending.len(),
            });
        }
        Ok(self.b.finish(sid(root)))
    }
}

/// Borrow a facade array as a slice; a zero length yields an empty slice without
/// dereferencing the (possibly null) pointer. The pointer is taken by reference so the
/// returned lifetime is tied to its (stack) holder and cannot be chosen as `'static`.
///
/// # Safety
/// For a non-zero `len`, `*ptr` must point to `len` initialized `T` valid for the borrow.
unsafe fn slice<T>(ptr: &*const T, len: usize) -> &[T] {
    if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(*ptr, len) }
    }
}

/// Decode a pooled string lossily (IDA names and literals are not guaranteed UTF-8);
/// `None` for an empty/null span.
///
/// # Safety
/// For a non-zero `len`, `ptr` must point to `len` readable bytes.
unsafe fn lossy(ptr: *const c_char, len: usize) -> Option<String> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    Some(String::from_utf8_lossy(bytes).into_owned())
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

unsafe extern "C" fn cb_num(ctx: *mut c_void, ea: u64, value: u64, ty: u32) -> u32 {
    unsafe { builder(&ctx) }.num(ea, value, ty)
}
unsafe extern "C" fn cb_fnum(ctx: *mut c_void, ea: u64, value: f64, ty: u32) -> u32 {
    unsafe { builder(&ctx) }.fnum(ea, value, ty)
}
unsafe extern "C" fn cb_obj(
    ctx: *mut c_void,
    ea: u64,
    target: u64,
    name: *const c_char,
    name_len: usize,
    ty: u32,
) -> u32 {
    let name = unsafe { lossy(name, name_len) };
    unsafe { builder(&ctx) }.obj(ea, target, name, ty)
}
unsafe extern "C" fn cb_var(ctx: *mut c_void, ea: u64, idx: u32, ty: u32) -> u32 {
    unsafe { builder(&ctx) }.var(ea, idx, ty)
}
unsafe extern "C" fn cb_str(
    ctx: *mut c_void,
    ea: u64,
    s: *const c_char,
    len: usize,
    ty: u32,
) -> u32 {
    let s = unsafe { lossy(s, len) }.unwrap_or_default();
    unsafe { builder(&ctx) }.string(ea, s, ty)
}
unsafe extern "C" fn cb_helper(
    ctx: *mut c_void,
    ea: u64,
    s: *const c_char,
    len: usize,
    ty: u32,
) -> u32 {
    let s = unsafe { lossy(s, len) }.unwrap_or_default();
    unsafe { builder(&ctx) }.helper(ea, s, ty)
}
unsafe extern "C" fn cb_call(
    ctx: *mut c_void,
    ea: u64,
    callee: u32,
    args: *const u32,
    nargs: usize,
    ty: u32,
) -> u32 {
    let args = unsafe { slice(&args, nargs) };
    unsafe { builder(&ctx) }.call(ea, callee, args, ty)
}
unsafe extern "C" fn cb_memref(ctx: *mut c_void, ea: u64, obj: u32, offset: u32, ty: u32) -> u32 {
    unsafe { builder(&ctx) }.memref(ea, obj, offset, ty)
}
unsafe extern "C" fn cb_memptr(ctx: *mut c_void, ea: u64, obj: u32, offset: u32, ty: u32) -> u32 {
    unsafe { builder(&ctx) }.memptr(ea, obj, offset, ty)
}
unsafe extern "C" fn cb_deref(ctx: *mut c_void, ea: u64, x: u32, size: u32, ty: u32) -> u32 {
    unsafe { builder(&ctx) }.deref(ea, x, size, ty)
}
unsafe extern "C" fn cb_op(
    ctx: *mut c_void,
    ea: u64,
    ctype: u32,
    x: u32,
    y: u32,
    z: u32,
    ty: u32,
) -> u32 {
    unsafe { builder(&ctx) }.op(ea, ctype, x, y, z, ty)
}

unsafe extern "C" fn cb_block(ctx: *mut c_void, ea: u64, kids: *const u32, nkids: usize) -> u32 {
    let kids = unsafe { slice(&kids, nkids) };
    unsafe { builder(&ctx) }.block(ea, kids)
}
unsafe extern "C" fn cb_expr(ctx: *mut c_void, ea: u64, e: u32) -> u32 {
    unsafe { builder(&ctx) }.expr_stmt(ea, e)
}
unsafe extern "C" fn cb_if(ctx: *mut c_void, ea: u64, cond: u32, then_s: u32, else_s: u32) -> u32 {
    unsafe { builder(&ctx) }.if_(ea, cond, then_s, else_s)
}
unsafe extern "C" fn cb_for(
    ctx: *mut c_void,
    ea: u64,
    init: u32,
    cond: u32,
    step: u32,
    body: u32,
) -> u32 {
    unsafe { builder(&ctx) }.for_(ea, init, cond, step, body)
}
unsafe extern "C" fn cb_while(ctx: *mut c_void, ea: u64, cond: u32, body: u32) -> u32 {
    unsafe { builder(&ctx) }.while_(ea, cond, body)
}
unsafe extern "C" fn cb_do(ctx: *mut c_void, ea: u64, body: u32, cond: u32) -> u32 {
    unsafe { builder(&ctx) }.do_(ea, body, cond)
}
unsafe extern "C" fn cb_switch(
    ctx: *mut c_void,
    ea: u64,
    expr: u32,
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
    unsafe { builder(&ctx) }.switch(ea, expr, cases)
}
unsafe extern "C" fn cb_break(ctx: *mut c_void, ea: u64) -> u32 {
    unsafe { builder(&ctx) }.break_(ea)
}
unsafe extern "C" fn cb_continue(ctx: *mut c_void, ea: u64) -> u32 {
    unsafe { builder(&ctx) }.continue_(ea)
}
unsafe extern "C" fn cb_return(ctx: *mut c_void, ea: u64, e: u32) -> u32 {
    unsafe { builder(&ctx) }.return_(ea, e)
}
unsafe extern "C" fn cb_goto(ctx: *mut c_void, ea: u64, label: i32) -> u32 {
    unsafe { builder(&ctx) }.goto(ea, label)
}
unsafe extern "C" fn cb_asm(ctx: *mut c_void, ea: u64, addrs: *const u64, n: usize) -> u32 {
    let addrs = unsafe { slice(&addrs, n) };
    unsafe { builder(&ctx) }.asm(ea, addrs)
}
unsafe extern "C" fn cb_try(
    ctx: *mut c_void,
    ea: u64,
    body: u32,
    catches: *const u32,
    n: usize,
) -> u32 {
    let catches = unsafe { slice(&catches, n) };
    unsafe { builder(&ctx) }.try_(ea, body, catches)
}
unsafe extern "C" fn cb_throw(ctx: *mut c_void, ea: u64, e: u32) -> u32 {
    unsafe { builder(&ctx) }.throw(ea, e)
}
unsafe extern "C" fn cb_empty(ctx: *mut c_void, ea: u64) -> u32 {
    unsafe { builder(&ctx) }.empty_stmt(ea)
}

unsafe extern "C" fn cb_scalar(
    ctx: *mut c_void,
    kind: u32,
    bytes: u32,
    signed: u32,
    size: u64,
    has_size: u32,
) -> u32 {
    unsafe { builder(&ctx) }.scalar(kind, bytes, signed, size, has_size)
}
unsafe extern "C" fn cb_ptr(ctx: *mut c_void, target: u32, size: u64, has_size: u32) -> u32 {
    unsafe { builder(&ctx) }.ptr(target, size, has_size)
}
unsafe extern "C" fn cb_array(
    ctx: *mut c_void,
    elem: u32,
    nelems: u64,
    size: u64,
    has_size: u32,
) -> u32 {
    unsafe { builder(&ctx) }.array(elem, nelems, size, has_size)
}
unsafe extern "C" fn cb_func(
    ctx: *mut c_void,
    ret: u32,
    params: *const u32,
    n: usize,
    vararg: u32,
) -> u32 {
    let params = unsafe { slice(&params, n) };
    unsafe { builder(&ctx) }.func(ret, params, vararg)
}
unsafe extern "C" fn cb_named_ref(ctx: *mut c_void, name: *const c_char, name_len: usize) -> u32 {
    let name = unsafe { lossy(name, name_len) }.unwrap_or_default();
    unsafe { builder(&ctx) }.named_ref(name)
}
unsafe extern "C" fn cb_anon(ctx: *mut c_void) -> u32 {
    unsafe { builder(&ctx) }.anon()
}
unsafe extern "C" fn cb_fill_struct(
    ctx: *mut c_void,
    id: u32,
    is_union: u32,
    members: *const MemberDesc,
    n: usize,
    size: u64,
    has_size: u32,
) {
    let members = unsafe { slice(&members, n) }
        .iter()
        .map(|m| TypeMember {
            name: unsafe { lossy(m.name, m.name_len) }.unwrap_or_default(),
            bit_offset: m.bit_offset,
            ty: tid(m.ty),
            bitfield_width: (m.bitfield_width != 0).then_some(m.bitfield_width),
        })
        .collect();
    unsafe { builder(&ctx) }.fill_struct(id, is_union != 0, members, size, has_size);
}
unsafe extern "C" fn cb_fill_enum(
    ctx: *mut c_void,
    id: u32,
    underlying: u32,
    consts: *const EnumConstDesc,
    n: usize,
    size: u64,
    has_size: u32,
) {
    let members = unsafe { slice(&consts, n) }
        .iter()
        .map(|c| EnumMember {
            name: unsafe { lossy(c.name, c.name_len) }.unwrap_or_default(),
            value: c.value,
        })
        .collect();
    unsafe { builder(&ctx) }.fill_enum(id, underlying, members, size, has_size);
}
unsafe extern "C" fn cb_fill_typedef(ctx: *mut c_void, id: u32, underlying: u32) {
    unsafe { builder(&ctx) }.fill_typedef(id, underlying);
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
    loc_kind: u32,
    loc_val: i64,
) {
    let location = match loc_kind {
        1 => LvarLocation::Register(loc_val as u32),
        2 => LvarLocation::Stack(loc_val),
        _ => LvarLocation::Other,
    };
    let lvar = Lvar {
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
    t_scalar: cb_scalar,
    t_ptr: cb_ptr,
    t_array: cb_array,
    t_func: cb_func,
    t_named_ref: cb_named_ref,
    t_anon: cb_anon,
    t_fill_struct: cb_fill_struct,
    t_fill_enum: cb_fill_enum,
    t_fill_typedef: cb_fill_typedef,
    l_lvar: cb_lvar,
};

/// Walk a decompiled function's ctree into an owned [`Ctree`]. `cfunc` is a live
/// `idakit_decompile` handle (see [`Cfunc`](crate::Cfunc)); the walk runs on this (kernel)
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

        assert!(matches!(tree.stmt(tree.root()).kind, Cinsn::Block(_)));
        let kinds: Vec<&Cexpr> = tree.exprs().map(|(_, e)| &e.kind).collect();
        assert!(matches!(kinds[2], Cexpr::Binary { op: BinOp::Add, .. }));
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
        let s0 = cb.expr_stmt(0, asg);
        let s1 = cb.expr_stmt(0, bin);
        let s2 = cb.expr_stmt(0, un);
        let blk = cb.block(0, &[s0, s1, s2]);
        let tree = cb.finish(blk).expect("well-formed");

        let kinds: Vec<&Cexpr> = tree.exprs().map(|(_, e)| &e.kind).collect();
        assert!(matches!(
            kinds[eid(asg).index()],
            Cexpr::Assign {
                op: AssignOp::AddAssign,
                ..
            }
        ));
        assert!(matches!(
            kinds[eid(bin).index()],
            Cexpr::Binary { op: BinOp::Sub, .. }
        ));
        assert!(matches!(
            kinds[eid(un).index()],
            Cexpr::Unary { op: UnOp::Neg, .. }
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
        let s = cb.expr_stmt(0, call);
        let blk = cb.block(0, &[s]);
        let tree = cb.finish(blk).expect("well-formed");

        assert!(let Cexpr::Call { callee, args } = &tree.expr(eid(call)).kind);
        assert!(matches!(tree.expr(*callee).kind, Cexpr::Helper(ref h) if h == "printf"));
        assert!(args.len() == 2);
        assert!(matches!(tree.expr(args[0]).kind, Cexpr::Str(ref s) if s == "%d"));
        assert!(matches!(tree.expr(args[1]).kind, Cexpr::Num(42)));
    }

    /// `if` with and without an `else` -- exercises the optional-child sentinel.
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

        let stmts: Vec<&Cinsn> = tree.stmts().map(|(_, s)| &s.kind).collect();
        assert!(matches!(
            stmts[sid(if_with).index()],
            Cinsn::If { else_: Some(_), .. }
        ));
        assert!(matches!(
            stmts[sid(if_without).index()],
            Cinsn::If { else_: None, .. }
        ));
    }

    /// `for`, `switch` (with the case-values pool), `try`/catches, and `asm` -- the
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

        let get = |s: u32| tree.stmt(sid(s)).kind.clone();
        assert!(matches!(
            get(for_s),
            Cinsn::For {
                init: None,
                cond: Some(_),
                step: None,
                ..
            }
        ));
        assert!(let Cinsn::Switch { cases, .. } = get(switch_s));
        assert!(cases.len() == 2);
        assert!(cases[0].values == vec![1, 2]);
        assert!(cases[1].values.is_empty());
        assert!(let Cinsn::Try { catches, .. } = get(try_s));
        assert!(catches.len() == 1);
        assert!(let Cinsn::Asm(addrs) = get(asm_s));
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
        let s = cb.expr_stmt(0, v);
        let blk = cb.block(0, &[s]);
        let tree = cb.finish(blk).expect("well-formed");

        assert!(let TypeKind::Struct { name, members } = &tree.type_of(tid(node)).kind);
        assert!(name.as_deref() == Some("Node"));
        assert!(members.len() == 1);
        assert!(members[0].name == "next");
        // the member pointer resolves back to the struct itself
        assert!(matches!(tree.type_of(members[0].ty).kind, TypeKind::Ptr(t) if t == tid(node)));
    }

    /// A typedef keeps its alias name and points at the (separately interned) underlying.
    #[test]
    fn typedef_wraps_its_underlying() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        let alias = cb.named_ref("size_t".into());
        cb.fill_typedef(alias, it);

        let v = cb.var(0, 0, alias);
        let s = cb.expr_stmt(0, v);
        let blk = cb.block(0, &[s]);
        let tree = cb.finish(blk).expect("well-formed");

        let alias_ty = tree.type_of(tid(alias));
        assert!(let TypeKind::Typedef { name, underlying } = &alias_ty.kind);
        assert!(name == "size_t");
        assert!(matches!(
            tree.type_of(*underlying).kind,
            TypeKind::Int { bytes: 4, .. }
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

    /// An unmodeled ctype is a loud error (the `Internal` fallback is reserved for
    /// `cot_insn`), surfaced at `finish`.
    #[test]
    fn rejects_unknown_ctype() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        let v = cb.var(0, 0, it);
        let bad = cb.op(0, 999, v, IDAKIT_NONE, IDAKIT_NONE, it);
        let s = cb.expr_stmt(0, bad);
        let blk = cb.block(0, &[s]);
        assert!(cb.finish(blk).err() == Some(ExtractError::UnknownExprTag { tag: 999 }));
    }

    /// `cot_insn` (a statement in expression position) collapses to `Internal`, not an
    /// error -- the one allowance, since a finalized tree never contains it.
    #[test]
    fn cot_insn_collapses_to_internal() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        let insn = cb.op(0, ct::INSN, IDAKIT_NONE, IDAKIT_NONE, IDAKIT_NONE, it);
        let s = cb.expr_stmt(0, insn);
        let blk = cb.block(0, &[s]);
        let tree = cb.finish(blk).expect("internal is not an error");
        assert!(matches!(tree.expr(eid(insn)).kind, Cexpr::Internal));
    }

    /// A float literal now carries its real value (the old extractor always emitted 0.0).
    #[test]
    fn float_literal_round_trips() {
        let mut cb = CallbackBuilder::new();
        let ft = cb.scalar(4, 8, 0, 8, 1);
        let f = cb.fnum(0, 3.5, ft);
        let s = cb.expr_stmt(0, f);
        let blk = cb.block(0, &[s]);
        let tree = cb.finish(blk).expect("well-formed");
        assert!(matches!(tree.expr(eid(f)).kind, Cexpr::Fnum(v) if v == 3.5));
    }

    /// Lvars land in the table in push order and `Var` resolves to them.
    #[test]
    fn lvars_resolve_through_the_table() {
        let mut cb = CallbackBuilder::new();
        let it = int_ty(&mut cb);
        cb.push_lvar(Lvar {
            name: "argc".into(),
            ty: tid(it),
            is_arg: true,
            is_result: false,
            is_byref: false,
            width: 4,
            comment: None,
            location: LvarLocation::Stack(-4),
        });
        let v = cb.var(0, 0, it);
        let s = cb.expr_stmt(0, v);
        let blk = cb.block(0, &[s]);
        let tree = cb.finish(blk).expect("well-formed");

        assert!(let Cexpr::Var(id) = &tree.expr(eid(v)).kind);
        let lv = tree.lvar(*id);
        assert!(lv.name == "argc");
        assert!(lv.is_arg);
        assert!(lv.location == LvarLocation::Stack(-4));
    }
}
