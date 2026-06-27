//! Building a [`Ctree`] from the facade's flat record image ([`idakit_sys::ExprRec`] et
//! al.). The facade emits one DFS — types, then expressions, then statements, each in
//! post-order so a node's children and its type precede it — and [`build`] turns those
//! records back into owned arenas via [`CtreeBuilder`].
//!
//! The expression `tag` is a raw `ctype_t`: operators map straight through
//! [`BinOp::from_raw`]/[`AssignOp::from_raw`]/[`UnOp::from_raw`] (the enum discriminants
//! *are* the ctype values), and the handful of structural kinds match the named
//! constants in [`ct`]. There is exactly one shared contract with the C++ side — the
//! per-tag meaning of `a`/`b`/`c`/`aux` and the side pools — and it lives in this file.

use idakit_sys::{CaseRec, ExprRec, StmtRec, TypeRec};
use snafu::Snafu;

use super::arena::Idx;
use super::node::{Case, Cexpr, Cinsn, ExprId, LvarId, StmtId};
use super::ops::{AssignOp, BinOp, UnOp};
use super::tree::{Ctree, CtreeBuilder};
use super::types::{TypeData, TypeId, TypeKind};
use crate::Ea;

/// Sentinel in an optional child slot: the edge is absent.
const NONE: u32 = u32::MAX;

/// Structural `ctype_t` values matched by name (operators go through `from_raw`).
mod ct {
    pub const EMPTY: u32 = 0;
    pub const TERN: u32 = 16;
    pub const CAST: u32 = 48;
    pub const PTR: u32 = 51;
    pub const CALL: u32 = 57;
    pub const IDX: u32 = 58;
    pub const MEMREF: u32 = 59;
    pub const MEMPTR: u32 = 60;
    pub const NUM: u32 = 61;
    pub const FNUM: u32 = 62;
    pub const STR: u32 = 63;
    pub const OBJ: u32 = 64;
    pub const VAR: u32 = 65;
    // 66 = cot_insn (a statement in expression position) is not matched by name; it and
    // any unmodeled ctype collapse to `Cexpr::Internal`.
    pub const SIZEOF: u32 = 67;
    pub const HELPER: u32 = 68;
    pub const TYPE: u32 = 69;

    pub const CIT_EMPTY: u32 = 70;
    pub const BLOCK: u32 = 71;
    pub const EXPR: u32 = 72;
    pub const IF: u32 = 73;
    pub const FOR: u32 = 74;
    pub const WHILE: u32 = 75;
    pub const DO: u32 = 76;
    pub const SWITCH: u32 = 77;
    pub const BREAK: u32 = 78;
    pub const CONTINUE: u32 = 79;
    pub const RETURN: u32 = 80;
    pub const GOTO: u32 = 81;
    pub const ASM: u32 = 82;
    pub const TRY: u32 = 83;
    pub const THROW: u32 = 84;
}

/// Type-kind codes for [`TypeRec::tag`]. Types are not `ctype_t`, so this is a small
/// private contract with the facade — only the kinds it currently emits.
mod tk {
    pub const UNKNOWN: u32 = 0;
    pub const VOID: u32 = 1;
    pub const BOOL: u32 = 2;
    pub const INT: u32 = 3;
    pub const FLOAT: u32 = 4;
    pub const PTR: u32 = 5;
    pub const ARRAY: u32 = 6;
    pub const NAMED: u32 = 7;
}

/// Borrowed view of the facade's record image: the three node/type arrays plus the side
/// pools their variadic edges point into. [`build`] reads only these slices.
pub(crate) struct Records<'a> {
    pub types: &'a [TypeRec],
    pub exprs: &'a [ExprRec],
    pub stmts: &'a [StmtRec],
    /// Homogeneous index lists: block bodies, call args, try catches.
    pub nodes: &'a [u32],
    /// String bytes for `cot_str` / `cot_helper` / named types.
    pub bytes: &'a [u8],
    /// Wide values: `cit_asm` addresses and `switch` case values.
    pub longs: &'a [u64],
    pub cases: &'a [CaseRec],
    /// Statement index of the root block.
    pub root: u32,
}

/// Why a record image could not be turned into a [`Ctree`].
#[derive(Debug, Snafu, PartialEq, Eq)]
pub enum ExtractError {
    #[snafu(display("unknown statement ctype {tag}"))]
    UnknownStmtTag { tag: u32 },

    #[snafu(display("unknown type kind {tag}"))]
    UnknownTypeTag { tag: u32 },

    #[snafu(display("{kind} reference {index} is out of range"))]
    BadIndex { kind: &'static str, index: u32 },

    #[snafu(display("{kind} pool slice {off}..{off}+{len} is out of range"))]
    BadPool {
        kind: &'static str,
        off: u32,
        len: u32,
    },

    #[snafu(display("a node carries the BADADDR sentinel as its address"))]
    BadEa,
}

/// Turn a facade record image into an owned [`Ctree`]. Validates every tag, reference,
/// and pool slice; assumes the records come from a trusted emitter (it does not guard
/// against a hand-crafted image with unreachable nodes — `finish` debug-asserts that).
pub(crate) fn build(r: &Records) -> Result<Ctree, ExtractError> {
    let mut b = CtreeBuilder::new();
    // The records arrive in post-order, so a child/type reference always resolves
    // against an earlier (already-pushed) entry of these maps.
    let mut type_map: Vec<TypeId> = Vec::with_capacity(r.types.len());
    let mut expr_map: Vec<ExprId> = Vec::with_capacity(r.exprs.len());
    let mut stmt_map: Vec<StmtId> = Vec::with_capacity(r.stmts.len());

    for rec in r.types {
        let data = build_type(rec, &type_map, r.bytes)?;
        type_map.push(b.intern_type(data));
    }
    for rec in r.exprs {
        let ty = resolve(&type_map, rec.ty, "type")?;
        let kind = build_expr(rec, &expr_map, r)?;
        expr_map.push(b.expr(node_ea(rec.ea), ty, kind));
    }
    for rec in r.stmts {
        let kind = build_stmt(rec, &expr_map, &stmt_map, r)?;
        stmt_map.push(b.stmt(node_ea(rec.ea), kind));
    }

    let root = resolve(&stmt_map, r.root, "stmt")?;
    Ok(b.finish(root))
}

/// A node's source address: `None` for a synthetic node (the BADADDR sentinel).
fn node_ea(raw: u64) -> Option<Ea> {
    Ea::try_new(raw)
}

/// A referenced address that must be real (a `cot_obj` target, a `cit_asm` instruction):
/// the BADADDR sentinel here is malformed input.
fn ea(raw: u64) -> Result<Ea, ExtractError> {
    Ea::try_new(raw).ok_or(ExtractError::BadEa)
}

/// Translate a record index into the handle allocated for it.
fn resolve<T>(map: &[Idx<T>], raw: u32, kind: &'static str) -> Result<Idx<T>, ExtractError> {
    map.get(raw as usize)
        .copied()
        .ok_or(ExtractError::BadIndex { kind, index: raw })
}

/// Like [`resolve`], but a [`NONE`] index yields `None`.
fn resolve_opt<T>(
    map: &[Idx<T>],
    raw: u32,
    kind: &'static str,
) -> Result<Option<Idx<T>>, ExtractError> {
    if raw == NONE {
        Ok(None)
    } else {
        resolve(map, raw, kind).map(Some)
    }
}

/// A `[off, off+len)` window into a side pool, bounds-checked.
fn sub<'a, T>(
    pool: &'a [T],
    off: u32,
    len: u32,
    kind: &'static str,
) -> Result<&'a [T], ExtractError> {
    let start = off as usize;
    let end = start
        .checked_add(len as usize)
        .filter(|&end| end <= pool.len())
        .ok_or(ExtractError::BadPool { kind, off, len })?;
    Ok(&pool[start..end])
}

/// Resolve a pool window of record indices to handles in one pass.
fn resolve_pool<T>(
    pool: &[u32],
    off: u32,
    len: u32,
    map: &[Idx<T>],
    kind: &'static str,
) -> Result<Vec<Idx<T>>, ExtractError> {
    sub(pool, off, len, kind)?
        .iter()
        .map(|&i| resolve(map, i, kind))
        .collect()
}

/// A pooled string, decoded lossily (IDA names and string literals are not guaranteed
/// UTF-8; see `ffi::cstr`).
fn string(bytes: &[u8], off: u32, len: u32) -> Result<String, ExtractError> {
    let slice = sub(bytes, off, len, "string")?;
    Ok(String::from_utf8_lossy(slice).into_owned())
}

fn build_type(rec: &TypeRec, type_map: &[TypeId], bytes: &[u8]) -> Result<TypeData, ExtractError> {
    let size = (rec.has_size != 0).then_some(rec.size);
    let kind = match rec.tag {
        tk::UNKNOWN => TypeKind::Unknown,
        tk::VOID => TypeKind::Void,
        tk::BOOL => TypeKind::Bool,
        tk::INT => TypeKind::Int {
            bytes: rec.bytes as u8,
            signed: rec.signed != 0,
        },
        tk::FLOAT => TypeKind::Float {
            bytes: rec.bytes as u8,
        },
        tk::PTR => TypeKind::Ptr(resolve(type_map, rec.a, "type")?),
        tk::ARRAY => TypeKind::Array {
            elem: resolve(type_map, rec.a, "type")?,
            len: rec.aux,
        },
        tk::NAMED => TypeKind::Named(string(bytes, rec.a, rec.b)?),
        tag => return Err(ExtractError::UnknownTypeTag { tag }),
    };
    Ok(TypeData { kind, size })
}

fn build_expr(rec: &ExprRec, em: &[ExprId], r: &Records) -> Result<Cexpr, ExtractError> {
    // An operator's kind is its ctype value: probe assignments first (their range
    // overlaps the numeric binary range), then plain binary, then unary.
    let op = u16::try_from(rec.tag).ok();
    if let Some(op) = op.and_then(AssignOp::from_raw) {
        return Ok(Cexpr::Assign {
            op,
            x: resolve(em, rec.a, "expr")?,
            y: resolve(em, rec.b, "expr")?,
        });
    }
    if let Some(op) = op.and_then(BinOp::from_raw) {
        return Ok(Cexpr::Binary {
            op,
            x: resolve(em, rec.a, "expr")?,
            y: resolve(em, rec.b, "expr")?,
        });
    }
    if let Some(op) = op.and_then(UnOp::from_raw) {
        return Ok(Cexpr::Unary {
            op,
            x: resolve(em, rec.a, "expr")?,
        });
    }

    Ok(match rec.tag {
        ct::TERN => Cexpr::Ternary {
            cond: resolve(em, rec.a, "expr")?,
            then_: resolve(em, rec.b, "expr")?,
            else_: resolve(em, rec.c, "expr")?,
        },
        ct::CAST => Cexpr::Cast {
            x: resolve(em, rec.a, "expr")?,
        },
        ct::PTR => Cexpr::Deref {
            x: resolve(em, rec.a, "expr")?,
            size: rec.b,
        },
        ct::CALL => Cexpr::Call {
            callee: resolve(em, rec.a, "expr")?,
            args: resolve_pool(r.nodes, rec.b, rec.c, em, "expr")?,
        },
        ct::IDX => Cexpr::Index {
            array: resolve(em, rec.a, "expr")?,
            index: resolve(em, rec.b, "expr")?,
        },
        ct::MEMREF => Cexpr::MemberRef {
            obj: resolve(em, rec.a, "expr")?,
            offset: rec.b,
        },
        ct::MEMPTR => Cexpr::MemberPtr {
            obj: resolve(em, rec.a, "expr")?,
            offset: rec.b,
        },
        ct::NUM => Cexpr::Num(rec.aux),
        ct::FNUM => Cexpr::Fnum(f64::from_bits(rec.aux)),
        ct::STR => Cexpr::Str(string(r.bytes, rec.a, rec.b)?),
        ct::OBJ => Cexpr::Obj(ea(rec.aux)?),
        ct::VAR => Cexpr::Var(LvarId(rec.a)),
        ct::SIZEOF => Cexpr::Sizeof(resolve(em, rec.a, "expr")?),
        ct::HELPER => Cexpr::Helper(string(r.bytes, rec.a, rec.b)?),
        ct::TYPE => Cexpr::TypeExpr,
        ct::EMPTY => Cexpr::Empty,
        // cot_insn (a statement in expression position) and any ctype this build doesn't
        // model collapse to the one documented marker, not a catch-all variant per kind.
        _ => Cexpr::Internal,
    })
}

fn build_stmt(
    rec: &StmtRec,
    em: &[ExprId],
    sm: &[StmtId],
    r: &Records,
) -> Result<Cinsn, ExtractError> {
    Ok(match rec.tag {
        ct::BLOCK => Cinsn::Block(resolve_pool(r.nodes, rec.a, rec.b, sm, "block")?),
        ct::EXPR => Cinsn::Expr(resolve(em, rec.a, "expr")?),
        ct::IF => Cinsn::If {
            cond: resolve(em, rec.a, "expr")?,
            then_: resolve(sm, rec.b, "stmt")?,
            else_: resolve_opt(sm, rec.c, "stmt")?,
        },
        ct::FOR => Cinsn::For {
            init: resolve_opt(em, rec.a, "expr")?,
            cond: resolve_opt(em, rec.b, "expr")?,
            step: resolve_opt(em, rec.c, "expr")?,
            body: resolve(sm, rec.aux as u32, "stmt")?,
        },
        ct::WHILE => Cinsn::While {
            cond: resolve(em, rec.a, "expr")?,
            body: resolve(sm, rec.b, "stmt")?,
        },
        ct::DO => Cinsn::Do {
            body: resolve(sm, rec.a, "stmt")?,
            cond: resolve(em, rec.b, "expr")?,
        },
        ct::SWITCH => Cinsn::Switch {
            expr: resolve(em, rec.a, "expr")?,
            cases: sub(r.cases, rec.b, rec.c, "switch")?
                .iter()
                .map(|cr| build_case(cr, sm, r))
                .collect::<Result<Vec<_>, _>>()?,
        },
        ct::BREAK => Cinsn::Break,
        ct::CONTINUE => Cinsn::Continue,
        ct::RETURN => Cinsn::Return(resolve_opt(em, rec.a, "expr")?),
        ct::GOTO => Cinsn::Goto {
            label: rec.a as i32,
        },
        ct::ASM => Cinsn::Asm(
            sub(r.longs, rec.a, rec.b, "asm")?
                .iter()
                .map(|&v| ea(v))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        ct::TRY => Cinsn::Try {
            body: resolve(sm, rec.a, "stmt")?,
            catches: resolve_pool(r.nodes, rec.b, rec.c, sm, "stmt")?,
        },
        ct::THROW => Cinsn::Throw(resolve_opt(em, rec.a, "expr")?),
        ct::CIT_EMPTY => Cinsn::Empty,
        tag => return Err(ExtractError::UnknownStmtTag { tag }),
    })
}

fn build_case(cr: &CaseRec, sm: &[StmtId], r: &Records) -> Result<Case, ExtractError> {
    Ok(Case {
        values: sub(r.longs, cr.values_off, cr.values_len, "case")?.to_vec(),
        body: resolve(sm, cr.body, "stmt")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctree::types::TypeData as Td;

    fn int_rec() -> TypeRec {
        TypeRec {
            tag: tk::INT,
            bytes: 4,
            signed: 1,
            has_size: 1,
            size: 4,
            ..Default::default()
        }
    }

    fn int_ty() -> Td {
        Td {
            kind: TypeKind::Int {
                bytes: 4,
                signed: true,
            },
            size: Some(4),
        }
    }

    fn var(idx: u32) -> ExprRec {
        ExprRec {
            tag: ct::VAR,
            ty: 0,
            a: idx,
            ..Default::default()
        }
    }

    fn ea0() -> Option<Ea> {
        Ea::try_new(0)
    }

    /// Assert two trees are node-for-node, type-for-type, root-for-root identical.
    fn assert_same(a: &Ctree, b: &Ctree) {
        assert_eq!(a.types().collect::<Vec<_>>(), b.types().collect::<Vec<_>>(),);
        assert_eq!(a.exprs().collect::<Vec<_>>(), b.exprs().collect::<Vec<_>>());
        assert_eq!(a.stmts().collect::<Vec<_>>(), b.stmts().collect::<Vec<_>>());
        assert_eq!(a.root(), b.root());
    }

    /// `{ return a + b; }` as records → the same tree a hand-driven `CtreeBuilder` makes.
    #[test]
    fn builds_return_of_a_binary() {
        // a(0), b(1), a+b(2) ; return(0), block(1)
        let add = ExprRec {
            tag: 35, // cot_add
            ty: 0,
            a: 0,
            b: 1,
            ..Default::default()
        };
        let ret = StmtRec {
            tag: ct::RETURN,
            a: 2,
            ..Default::default()
        };
        let block = StmtRec {
            tag: ct::BLOCK,
            a: 0,
            b: 1,
            ..Default::default()
        };
        let records = Records {
            types: &[int_rec()],
            exprs: &[var(0), var(1), add],
            stmts: &[ret, block],
            nodes: &[0],
            bytes: &[],
            longs: &[],
            cases: &[],
            root: 1,
        };
        let got = build(&records).expect("well-formed records");

        let mut eb = CtreeBuilder::new();
        let it = eb.intern_type(int_ty());
        let a = eb.expr(ea0(), it, Cexpr::Var(LvarId(0)));
        let b = eb.expr(ea0(), it, Cexpr::Var(LvarId(1)));
        let sum = eb.expr(
            ea0(),
            it,
            Cexpr::Binary {
                op: BinOp::Add,
                x: a,
                y: b,
            },
        );
        let r = eb.stmt(ea0(), Cinsn::Return(Some(sum)));
        let blk = eb.stmt(ea0(), Cinsn::Block(vec![r]));
        let expected = eb.finish(blk);

        assert_same(&got, &expected);
    }

    /// Operator family dispatch: an assignment, a binary, and a unary ctype each land on
    /// the right variant. (assignment ctypes overlap the binary numeric range, so the
    /// order of the `from_raw` probes matters — this pins it.)
    #[test]
    fn dispatches_operator_families() {
        // Each operator gets its own operands (every node has exactly one parent).
        let asg = ExprRec {
            tag: 6, // cot_asgadd
            a: 0,
            b: 1,
            ..Default::default()
        };
        let bin = ExprRec {
            tag: 36, // cot_sub
            a: 3,
            b: 4,
            ..Default::default()
        };
        let un = ExprRec {
            tag: 47, // cot_neg
            a: 6,
            ..Default::default()
        };
        let stmt = |e: u32| StmtRec {
            tag: ct::EXPR,
            a: e,
            ..Default::default()
        };
        let block = StmtRec {
            tag: ct::BLOCK,
            a: 0,
            b: 3,
            ..Default::default()
        };
        let records = Records {
            types: &[int_rec()],
            exprs: &[var(0), var(1), asg, var(2), var(3), bin, var(4), un],
            stmts: &[stmt(2), stmt(5), stmt(7), block],
            nodes: &[0, 1, 2], // block children: the three expr-statements
            bytes: &[],
            longs: &[],
            cases: &[],
            root: 3,
        };
        let t = build(&records).expect("well-formed");
        let kinds: Vec<&Cexpr> = t.exprs().map(|(_, e)| &e.kind).collect();
        assert!(matches!(
            kinds[2],
            Cexpr::Assign {
                op: AssignOp::AddAssign,
                ..
            }
        ));
        assert!(matches!(kinds[5], Cexpr::Binary { op: BinOp::Sub, .. }));
        assert!(matches!(kinds[7], Cexpr::Unary { op: UnOp::Neg, .. }));
    }

    /// A call with two args (the `nodes` pool), a helper callee and a string literal (the
    /// `bytes` pool), and an integer literal (`aux`).
    #[test]
    fn builds_call_with_pooled_args() {
        let callee = ExprRec {
            tag: ct::HELPER,
            a: 0, // bytes[0..6] = "printf"
            b: 6,
            ..Default::default()
        };
        let fmt = ExprRec {
            tag: ct::STR,
            a: 6, // bytes[6..8] = "%d"
            b: 2,
            ..Default::default()
        };
        let n = ExprRec {
            tag: ct::NUM,
            aux: 42,
            ..Default::default()
        };
        let call = ExprRec {
            tag: ct::CALL,
            a: 0, // callee
            b: 0, // nodes[0..2] = args
            c: 2,
            ..Default::default()
        };
        let stmt = StmtRec {
            tag: ct::EXPR,
            a: 3,
            ..Default::default()
        };
        let block = StmtRec {
            tag: ct::BLOCK,
            a: 2, // nodes[2..3] = the one stmt
            b: 1,
            ..Default::default()
        };
        let records = Records {
            types: &[int_rec()],
            exprs: &[callee, fmt, n, call],
            stmts: &[stmt, block],
            nodes: &[1, 2, 0], // args = expr 1,2 ; block child = stmt 0
            bytes: b"printf%d",
            longs: &[],
            cases: &[],
            root: 1,
        };
        let t = build(&records).expect("well-formed");
        let Cexpr::Call { callee, args } = &t.exprs().nth(3).unwrap().1.kind else {
            panic!("expected a call");
        };
        assert!(matches!(t.expr(*callee).kind, Cexpr::Helper(ref h) if h == "printf"));
        assert_eq!(args.len(), 2);
        assert!(matches!(t.expr(args[0]).kind, Cexpr::Str(ref s) if s == "%d"));
        assert!(matches!(t.expr(args[1]).kind, Cexpr::Num(42)));
    }

    /// `if` with and without an `else` — exercises the optional-child sentinel.
    #[test]
    fn builds_if_with_optional_else() {
        let cond1 = var(0);
        let cond2 = var(1);
        let then1 = StmtRec {
            tag: ct::BREAK,
            ..Default::default()
        };
        let then2 = StmtRec {
            tag: ct::CONTINUE,
            ..Default::default()
        };
        let els = StmtRec {
            tag: ct::BREAK,
            ..Default::default()
        };
        let if_with = StmtRec {
            tag: ct::IF,
            a: 0, // cond expr 0
            b: 0, // then stmt 0 (break)
            c: 2, // else stmt 2
            ..Default::default()
        };
        let if_without = StmtRec {
            tag: ct::IF,
            a: 1,
            b: 1,    // then stmt 1 (continue)
            c: NONE, // no else
            ..Default::default()
        };
        let block = StmtRec {
            tag: ct::BLOCK,
            a: 0,
            b: 2,
            ..Default::default()
        };
        let records = Records {
            types: &[int_rec()],
            exprs: &[cond1, cond2],
            stmts: &[then1, then2, els, if_with, if_without, block],
            nodes: &[3, 4], // block children: the two ifs
            bytes: &[],
            longs: &[],
            cases: &[],
            root: 5,
        };
        let t = build(&records).expect("well-formed");
        let stmts: Vec<&Cinsn> = t.stmts().map(|(_, s)| &s.kind).collect();
        assert!(matches!(stmts[3], Cinsn::If { else_: Some(_), .. }));
        assert!(matches!(stmts[4], Cinsn::If { else_: None, .. }));
    }

    /// Every scalar/pointer/named type kind the facade can emit round-trips through the
    /// type records, including a `Ptr` that references an earlier type by index.
    #[test]
    fn builds_simple_type_kinds() {
        let types = [
            TypeRec {
                tag: tk::INT,
                bytes: 4,
                signed: 1,
                has_size: 1,
                size: 4,
                ..Default::default()
            },
            TypeRec {
                tag: tk::PTR,
                a: 0, // -> int
                has_size: 1,
                size: 8,
                ..Default::default()
            },
            TypeRec {
                tag: tk::NAMED,
                a: 0, // bytes[0..4] = "Node"
                b: 4,
                ..Default::default()
            },
            TypeRec {
                tag: tk::VOID,
                ..Default::default()
            },
        ];
        let e = ExprRec {
            tag: ct::VAR,
            ty: 1, // typed as the pointer
            a: 0,
            ..Default::default()
        };
        let stmt = StmtRec {
            tag: ct::EXPR,
            a: 0,
            ..Default::default()
        };
        let block = StmtRec {
            tag: ct::BLOCK,
            a: 0,
            b: 1,
            ..Default::default()
        };
        let records = Records {
            types: &types,
            exprs: &[e],
            stmts: &[stmt, block],
            nodes: &[0],
            bytes: b"Node",
            longs: &[],
            cases: &[],
            root: 1,
        };
        let t = build(&records).expect("well-formed");
        let kinds: Vec<&TypeKind> = t.types().map(|(_, d)| &d.kind).collect();
        assert!(matches!(kinds[1], TypeKind::Ptr(_)));
        assert!(matches!(kinds[2], TypeKind::Named(n) if n == "Node"));
        assert!(matches!(kinds[3], TypeKind::Void));
        // the sole expression's type resolves to the pointer it was tagged with
        let (_, e) = t.exprs().next().expect("one expression");
        assert!(matches!(t.type_of(e.ty).kind, TypeKind::Ptr(_)));
    }

    fn block_of(stmt_tag: u32) -> (Vec<ExprRec>, Vec<StmtRec>, Vec<u32>) {
        let s = StmtRec {
            tag: stmt_tag,
            a: 0,
            ..Default::default()
        };
        let block = StmtRec {
            tag: ct::BLOCK,
            a: 0,
            b: 1,
            ..Default::default()
        };
        (vec![var(0)], vec![s, block], vec![0])
    }

    #[test]
    fn rejects_unknown_statement_tag() {
        let (exprs, mut stmts, nodes) = block_of(200);
        stmts[0] = StmtRec {
            tag: 200,
            ..Default::default()
        };
        let records = Records {
            types: &[int_rec()],
            exprs: &exprs,
            stmts: &stmts,
            nodes: &nodes,
            bytes: &[],
            longs: &[],
            cases: &[],
            root: 1,
        };
        assert_eq!(
            build(&records).err(),
            Some(ExtractError::UnknownStmtTag { tag: 200 }),
        );
    }

    #[test]
    fn rejects_out_of_range_child() {
        let bad = ExprRec {
            tag: 35, // cot_add referencing a missing operand
            a: 0,
            b: 9, // out of range
            ..Default::default()
        };
        let stmt = StmtRec {
            tag: ct::EXPR,
            a: 1,
            ..Default::default()
        };
        let block = StmtRec {
            tag: ct::BLOCK,
            a: 0,
            b: 1,
            ..Default::default()
        };
        let records = Records {
            types: &[int_rec()],
            exprs: &[var(0), bad],
            stmts: &[stmt, block],
            nodes: &[0],
            bytes: &[],
            longs: &[],
            cases: &[],
            root: 1,
        };
        assert_eq!(
            build(&records).err(),
            Some(ExtractError::BadIndex {
                kind: "expr",
                index: 9,
            }),
        );
    }

    #[test]
    fn rejects_out_of_range_pool() {
        let block = StmtRec {
            tag: ct::BLOCK,
            a: 0,
            b: 5, // claims 5 children but nodes has 0
            ..Default::default()
        };
        let records = Records {
            types: &[int_rec()],
            exprs: &[],
            stmts: &[block],
            nodes: &[],
            bytes: &[],
            longs: &[],
            cases: &[],
            root: 0,
        };
        assert_eq!(
            build(&records).err(),
            Some(ExtractError::BadPool {
                kind: "block",
                off: 0,
                len: 5,
            }),
        );
    }
}
