//! Render an owned [`Ctree`] back to C-like pseudocode.
//!
//! This is a *fidelity* tool, not a faithful reproduction of IDA's printer: it proves
//! the extracted tree is structurally sound (operators mapped right, operands not
//! dropped, precedence preserved) by turning it back into readable source. It uses only
//! [`Ctree`]'s public navigation, so it stays a pure consumer of the ADT.
//!
//! Exact output is not expected to byte-match IDA's `pseudocode()` — IDA has its own
//! declaration block, cast style, and spacing. The invariants worth holding are the
//! structural ones, which the unit tests below pin against synthetic trees.

use std::fmt::Write;

use super::node::{Case, Cexpr, Cinsn, ExprId, LvarId, StmtId};
use super::ops::{AssignOp, BinOp, UnOp};
use super::tree::Ctree;
use super::types::{TypeId, TypeKind};

// C operator precedence, higher binds tighter. A child is parenthesized when its own
// precedence is below the minimum its position requires (see `Printer::expr`).
const P_COMMA: u8 = 1;
const P_ASSIGN: u8 = 2;
const P_TERNARY: u8 = 3;
const P_LOGOR: u8 = 4;
const P_LOGAND: u8 = 5;
const P_BITOR: u8 = 6;
const P_BITXOR: u8 = 7;
const P_BITAND: u8 = 8;
const P_EQ: u8 = 9;
const P_REL: u8 = 10;
const P_SHIFT: u8 = 11;
const P_ADD: u8 = 12;
const P_MUL: u8 = 13;
const P_UNARY: u8 = 14;
const P_POSTFIX: u8 = 15;
const P_PRIMARY: u8 = 16;

impl Ctree {
    /// Render this function's body as C-like pseudocode.
    #[must_use]
    pub fn to_pseudocode(&self) -> String {
        let mut p = Printer {
            tree: self,
            out: String::new(),
            indent: 0,
        };
        p.stmt(self.root());
        p.out
    }
}

struct Printer<'a> {
    tree: &'a Ctree,
    out: String,
    indent: usize,
}

impl Printer<'_> {
    fn push_indent(&mut self) {
        for _ in 0..self.indent {
            self.out.push_str("  ");
        }
    }

    /// An indented single-line statement.
    fn line(&mut self, s: &str) {
        self.push_indent();
        self.out.push_str(s);
        self.out.push('\n');
    }

    fn stmt(&mut self, id: StmtId) {
        let tree = self.tree;
        match &tree.stmt(id).kind {
            Cinsn::Block(stmts) => {
                let stmts = stmts.clone();
                self.line("{");
                self.indent += 1;
                for s in stmts {
                    self.stmt(s);
                }
                self.indent -= 1;
                self.line("}");
            }
            Cinsn::Expr(e) => {
                let e = *e;
                self.push_indent();
                self.expr(e, 0);
                self.out.push_str(";\n");
            }
            Cinsn::If { cond, then_, else_ } => {
                let (cond, then_, else_) = (*cond, *then_, *else_);
                self.push_indent();
                self.out.push_str("if ( ");
                self.expr(cond, 0);
                self.out.push_str(" )\n");
                self.stmt(then_);
                if let Some(e) = else_ {
                    self.line("else");
                    self.stmt(e);
                }
            }
            Cinsn::For {
                init,
                cond,
                step,
                body,
            } => {
                let (init, cond, step, body) = (*init, *cond, *step, *body);
                self.push_indent();
                self.out.push_str("for ( ");
                if let Some(e) = init {
                    self.expr(e, 0);
                }
                self.out.push_str("; ");
                if let Some(e) = cond {
                    self.expr(e, 0);
                }
                self.out.push_str("; ");
                if let Some(e) = step {
                    self.expr(e, 0);
                }
                self.out.push_str(" )\n");
                self.stmt(body);
            }
            Cinsn::While { cond, body } => {
                let (cond, body) = (*cond, *body);
                self.push_indent();
                self.out.push_str("while ( ");
                self.expr(cond, 0);
                self.out.push_str(" )\n");
                self.stmt(body);
            }
            Cinsn::Do { body, cond } => {
                let (body, cond) = (*body, *cond);
                self.line("do");
                self.stmt(body);
                self.push_indent();
                self.out.push_str("while ( ");
                self.expr(cond, 0);
                self.out.push_str(" );\n");
            }
            Cinsn::Switch { expr, cases } => {
                let expr = *expr;
                let cases = cases.clone();
                self.push_indent();
                self.out.push_str("switch ( ");
                self.expr(expr, 0);
                self.out.push_str(" )\n");
                self.line("{");
                for case in &cases {
                    self.case(case);
                }
                self.line("}");
            }
            Cinsn::Break => self.line("break;"),
            Cinsn::Continue => self.line("continue;"),
            Cinsn::Return(e) => {
                let e = *e;
                self.push_indent();
                self.out.push_str("return");
                if let Some(e) = e {
                    self.out.push(' ');
                    self.expr(e, 0);
                }
                self.out.push_str(";\n");
            }
            Cinsn::Goto { label } => {
                let label = *label;
                self.push_indent();
                writeln!(self.out, "goto LABEL_{label};").unwrap();
            }
            Cinsn::Asm(eas) => {
                let n = eas.len();
                self.push_indent();
                writeln!(self.out, "__asm {{ /* {n} insns */ }}").unwrap();
            }
            Cinsn::Try { body, catches } => {
                let (body, catches) = (*body, catches.clone());
                self.line("try");
                self.stmt(body);
                for c in catches {
                    self.line("catch");
                    self.stmt(c);
                }
            }
            Cinsn::Throw(e) => {
                let e = *e;
                self.push_indent();
                self.out.push_str("throw");
                if let Some(e) = e {
                    self.out.push(' ');
                    self.expr(e, 0);
                }
                self.out.push_str(";\n");
            }
            Cinsn::Empty => self.line(";"),
        }
    }

    fn case(&mut self, case: &Case) {
        if case.values.is_empty() {
            self.line("default:");
        } else {
            for v in &case.values {
                self.push_indent();
                writeln!(self.out, "case {v}:").unwrap();
            }
        }
        self.stmt(case.body);
    }

    /// Render `id`, parenthesizing it when its own precedence is below `min_prec` — the
    /// minimum the surrounding operator position requires.
    fn expr(&mut self, id: ExprId, min_prec: u8) {
        let paren = self.prec(id) < min_prec;
        if paren {
            self.out.push('(');
        }
        self.expr_inner(id);
        if paren {
            self.out.push(')');
        }
    }

    fn expr_inner(&mut self, id: ExprId) {
        let tree = self.tree;
        match &tree.expr(id).kind {
            Cexpr::Binary { op, x, y } => {
                let (op, x, y) = (*op, *x, *y);
                if op == BinOp::Comma {
                    self.expr(x, P_COMMA);
                    self.out.push_str(", ");
                    self.expr(y, P_COMMA + 1);
                } else {
                    let p = bin_prec(op);
                    self.expr(x, p);
                    write!(self.out, " {} ", bin_sym(op)).unwrap();
                    self.expr(y, p + 1);
                }
            }
            Cexpr::Assign { op, x, y } => {
                let (op, x, y) = (*op, *x, *y);
                self.expr(x, P_ASSIGN + 1);
                write!(self.out, " {} ", assign_sym(op)).unwrap();
                self.expr(y, P_ASSIGN);
            }
            Cexpr::Unary { op, x } => {
                let (op, x) = (*op, *x);
                match op {
                    UnOp::PostInc | UnOp::PostDec => {
                        self.expr(x, P_POSTFIX);
                        self.out.push_str(un_sym(op));
                    }
                    _ => {
                        self.out.push_str(un_sym(op));
                        self.expr(x, P_UNARY);
                    }
                }
            }
            Cexpr::Ternary { cond, then_, else_ } => {
                let (cond, then_, else_) = (*cond, *then_, *else_);
                self.expr(cond, P_TERNARY + 1);
                self.out.push_str(" ? ");
                self.expr(then_, 0);
                self.out.push_str(" : ");
                self.expr(else_, P_TERNARY);
            }
            Cexpr::Call { callee, args } => {
                let callee = *callee;
                let args = args.clone();
                self.expr(callee, P_POSTFIX);
                self.out.push('(');
                for (i, a) in args.into_iter().enumerate() {
                    if i > 0 {
                        self.out.push_str(", ");
                    }
                    self.expr(a, P_ASSIGN);
                }
                self.out.push(')');
            }
            Cexpr::Index { array, index } => {
                let (array, index) = (*array, *index);
                self.expr(array, P_POSTFIX);
                self.out.push('[');
                self.expr(index, 0);
                self.out.push(']');
            }
            Cexpr::MemberRef { obj, byte_offset } => {
                let (obj, offset) = (*obj, *byte_offset);
                let name = self.field_name(obj, offset, false);
                self.expr(obj, P_POSTFIX);
                self.out.push('.');
                self.out.push_str(&name);
            }
            Cexpr::MemberPtr { obj, byte_offset } => {
                let (obj, offset) = (*obj, *byte_offset);
                let name = self.field_name(obj, offset, true);
                self.expr(obj, P_POSTFIX);
                self.out.push_str("->");
                self.out.push_str(&name);
            }
            Cexpr::Cast { x } => {
                let x = *x;
                let ts = self.print_type(tree.expr(id).ty);
                write!(self.out, "({ts})").unwrap();
                self.expr(x, P_UNARY);
            }
            Cexpr::Deref { x, .. } => {
                let x = *x;
                self.out.push('*');
                self.expr(x, P_UNARY);
            }
            Cexpr::Sizeof(x) => {
                let x = *x;
                self.out.push_str("sizeof(");
                self.expr(x, 0);
                self.out.push(')');
            }
            Cexpr::Num(v) => {
                let v = *v;
                if v < 10 {
                    write!(self.out, "{v}").unwrap();
                } else {
                    write!(self.out, "{v:#x}").unwrap();
                }
            }
            Cexpr::Fnum(f) => write!(self.out, "{f}").unwrap(),
            Cexpr::Str(s) => write!(self.out, "{s:?}").unwrap(),
            Cexpr::Obj { ea, name } => match name {
                Some(n) => self.out.push_str(n),
                None => write!(self.out, "{ea:#x}").unwrap(),
            },
            Cexpr::Var(v) => {
                let name = self.lvar_name(*v);
                self.out.push_str(&name);
            }
            Cexpr::Helper(s) => self.out.push_str(s),
            Cexpr::TypeExpr => {
                let ts = self.print_type(tree.expr(id).ty);
                self.out.push_str(&ts);
            }
            Cexpr::Empty => {}
            Cexpr::Internal => self.out.push_str("/* internal */"),
        }
    }

    /// The precedence of the operator at the root of `id` (primary for leaves).
    fn prec(&self, id: ExprId) -> u8 {
        match &self.tree.expr(id).kind {
            Cexpr::Binary { op, .. } => bin_prec(*op),
            Cexpr::Assign { .. } => P_ASSIGN,
            Cexpr::Ternary { .. } => P_TERNARY,
            Cexpr::Unary { op, .. } => match op {
                UnOp::PostInc | UnOp::PostDec => P_POSTFIX,
                _ => P_UNARY,
            },
            Cexpr::Call { .. }
            | Cexpr::Index { .. }
            | Cexpr::MemberRef { .. }
            | Cexpr::MemberPtr { .. } => P_POSTFIX,
            Cexpr::Cast { .. } | Cexpr::Deref { .. } | Cexpr::Sizeof(_) => P_UNARY,
            _ => P_PRIMARY,
        }
    }

    /// A struct/union member name at `byte_off`, resolved through the object's type; falls
    /// back to a synthetic `field_<off>` when the type isn't an aggregate we can index.
    fn field_name(&self, obj: ExprId, byte_off: u32, through_ptr: bool) -> String {
        let mut ty = self.tree.type_of(self.tree.expr(obj).ty);
        if through_ptr && let TypeKind::Ptr(p) = &ty.kind {
            ty = self.tree.type_of(*p);
        }
        let members = match &ty.kind {
            TypeKind::Struct { members, .. } | TypeKind::Union { members, .. } => Some(members),
            _ => None,
        };
        if let Some(members) = members {
            let bit = u64::from(byte_off) * 8;
            if let Some(m) = members.iter().find(|m| m.bit_offset == bit) {
                if !m.name.is_empty() {
                    return m.name.clone();
                }
                // Base-class subobjects come through with an empty member name; show the
                // subobject's type name instead (IDA renders `this->Base`).
                if let Some(tag) = self.type_tag_name(m.ty) {
                    return tag;
                }
            }
        }
        format!("field_{byte_off:#x}")
    }

    /// The bare name of a named aggregate/typedef, used to label an unnamed base
    /// subobject member by its type.
    fn type_tag_name(&self, id: TypeId) -> Option<String> {
        match &self.tree.type_of(id).kind {
            TypeKind::Struct { name, .. }
            | TypeKind::Union { name, .. }
            | TypeKind::Enum { name, .. } => name.clone(),
            TypeKind::Typedef { name, .. } => Some(name.clone()),
            _ => None,
        }
    }

    fn lvar_name(&self, v: LvarId) -> String {
        self.tree
            .lvars()
            .nth(v.0 as usize)
            .map(|l| l.name.clone())
            .unwrap_or_else(|| format!("v{}", v.0))
    }

    fn print_type(&self, id: TypeId) -> String {
        let t = self.tree.type_of(id);
        match &t.kind {
            TypeKind::Void => "void".into(),
            TypeKind::Bool => "bool".into(),
            TypeKind::Int { bytes, signed } => {
                let bits = u32::from(*bytes) * 8;
                if *signed {
                    format!("__int{bits}")
                } else {
                    format!("unsigned __int{bits}")
                }
            }
            TypeKind::Float { bytes } => match bytes {
                4 => "float".into(),
                8 => "double".into(),
                _ => "long double".into(),
            },
            TypeKind::Ptr(p) => format!("{} *", self.print_type(*p)),
            TypeKind::Array { elem, len } => format!("{}[{}]", self.print_type(*elem), len),
            TypeKind::Struct { name, .. } => name.clone().unwrap_or_else(|| "struct".into()),
            TypeKind::Union { name, .. } => name.clone().unwrap_or_else(|| "union".into()),
            TypeKind::Enum { name, .. } => name.clone().unwrap_or_else(|| "enum".into()),
            TypeKind::Func {
                ret,
                params,
                varargs,
            } => {
                let mut parts: Vec<String> = params.iter().map(|p| self.print_type(*p)).collect();
                if *varargs {
                    parts.push("...".into());
                }
                format!("{} (*)({})", self.print_type(*ret), parts.join(", "))
            }
            TypeKind::Typedef { name, .. } => name.clone(),
            TypeKind::Unknown => "_UNKNOWN".into(),
        }
    }
}

fn bin_prec(op: BinOp) -> u8 {
    match op {
        BinOp::Comma => P_COMMA,
        BinOp::LogOr => P_LOGOR,
        BinOp::LogAnd => P_LOGAND,
        BinOp::BitOr => P_BITOR,
        BinOp::BitXor => P_BITXOR,
        BinOp::BitAnd => P_BITAND,
        BinOp::Eq | BinOp::Ne => P_EQ,
        BinOp::Sge
        | BinOp::Uge
        | BinOp::Sle
        | BinOp::Ule
        | BinOp::Sgt
        | BinOp::Ugt
        | BinOp::Slt
        | BinOp::Ult => P_REL,
        BinOp::Sshr | BinOp::Ushr | BinOp::Shl => P_SHIFT,
        BinOp::Add | BinOp::Sub | BinOp::Fadd | BinOp::Fsub => P_ADD,
        BinOp::Mul
        | BinOp::Sdiv
        | BinOp::Udiv
        | BinOp::Smod
        | BinOp::Umod
        | BinOp::Fmul
        | BinOp::Fdiv => P_MUL,
    }
}

fn bin_sym(op: BinOp) -> &'static str {
    match op {
        BinOp::Comma => ",",
        BinOp::LogOr => "||",
        BinOp::LogAnd => "&&",
        BinOp::BitOr => "|",
        BinOp::BitXor => "^",
        BinOp::BitAnd => "&",
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Sge | BinOp::Uge => ">=",
        BinOp::Sle | BinOp::Ule => "<=",
        BinOp::Sgt | BinOp::Ugt => ">",
        BinOp::Slt | BinOp::Ult => "<",
        BinOp::Sshr | BinOp::Ushr => ">>",
        BinOp::Shl => "<<",
        BinOp::Add | BinOp::Fadd => "+",
        BinOp::Sub | BinOp::Fsub => "-",
        BinOp::Mul | BinOp::Fmul => "*",
        BinOp::Sdiv | BinOp::Udiv | BinOp::Fdiv => "/",
        BinOp::Smod | BinOp::Umod => "%",
    }
}

fn assign_sym(op: AssignOp) -> &'static str {
    match op {
        AssignOp::Assign => "=",
        AssignOp::BitOrAssign => "|=",
        AssignOp::BitXorAssign => "^=",
        AssignOp::BitAndAssign => "&=",
        AssignOp::AddAssign => "+=",
        AssignOp::SubAssign => "-=",
        AssignOp::MulAssign => "*=",
        AssignOp::SshrAssign | AssignOp::UshrAssign => ">>=",
        AssignOp::ShlAssign => "<<=",
        AssignOp::SdivAssign | AssignOp::UdivAssign => "/=",
        AssignOp::SmodAssign | AssignOp::UmodAssign => "%=",
    }
}

fn un_sym(op: UnOp) -> &'static str {
    match op {
        UnOp::FNeg | UnOp::Neg => "-",
        UnOp::LogNot => "!",
        UnOp::BitNot => "~",
        UnOp::Ref => "&",
        UnOp::PreInc | UnOp::PostInc => "++",
        UnOp::PreDec | UnOp::PostDec => "--",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ea;
    use crate::ctree::node::{Lvar, LvarLocation};
    use crate::ctree::tree::CtreeBuilder;
    use crate::ctree::types::{TypeData, TypeKind, TypeMember};

    fn ea() -> Option<Ea> {
        Some(Ea::new_const(0x1000))
    }

    fn int32(b: &mut CtreeBuilder) -> TypeId {
        b.intern_type(TypeData {
            kind: TypeKind::Int {
                bytes: 4,
                signed: true,
            },
            size: Some(4),
        })
    }

    fn lvar(name: &str, ty: TypeId) -> Lvar {
        Lvar {
            name: name.into(),
            ty,
            is_arg: false,
            is_result: false,
            is_byref: false,
            width: 4,
            comment: None,
            location: LvarLocation::Other,
        }
    }

    /// A base-class subobject member arrives with an empty name; it should render as the
    /// subobject's type name (what IDA shows for `this->Base`), never blank.
    #[test]
    fn empty_member_name_falls_back_to_type_name() {
        let mut b = CtreeBuilder::new();
        let base = b.intern_type(TypeData {
            kind: TypeKind::Struct {
                name: Some("Base".into()),
                members: vec![],
            },
            size: Some(8),
        });
        let derived = b.intern_type(TypeData {
            kind: TypeKind::Struct {
                name: Some("Derived".into()),
                members: vec![TypeMember {
                    name: String::new(),
                    bit_offset: 0,
                    ty: base,
                    bitfield_width: None,
                }],
            },
            size: Some(8),
        });
        let pderived = b.intern_type(TypeData {
            kind: TypeKind::Ptr(derived),
            size: Some(8),
        });
        let this = b.push_lvar(lvar("this", pderived));
        let v = b.expr(ea(), pderived, Cexpr::Var(this));
        let mp = b.expr(
            ea(),
            base,
            Cexpr::MemberPtr {
                obj: v,
                byte_offset: 0,
            },
        );
        let st = b.stmt(ea(), Cinsn::Expr(mp));
        let block = b.stmt(ea(), Cinsn::Block(vec![st]));
        let tree = b.finish(block);
        let out = tree.to_pseudocode();
        assert!(out.contains("this->Base"), "got: {out}");
    }

    /// `{ return a + b; }` — the canonical small tree, rendered exactly.
    #[test]
    fn renders_return_of_binary() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let a = b.push_lvar(lvar("a", int));
        let bb = b.push_lvar(lvar("b", int));
        let va = b.expr(ea(), int, Cexpr::Var(a));
        let vb = b.expr(ea(), int, Cexpr::Var(bb));
        let add = b.expr(
            ea(),
            int,
            Cexpr::Binary {
                op: BinOp::Add,
                x: va,
                y: vb,
            },
        );
        let ret = b.stmt(ea(), Cinsn::Return(Some(add)));
        let block = b.stmt(ea(), Cinsn::Block(vec![ret]));
        let tree = b.finish(block);
        assert_eq!(tree.to_pseudocode(), "{\n  return a + b;\n}\n");
    }

    /// A lower-precedence right operand must be parenthesized.
    #[test]
    fn parenthesizes_lower_precedence_child() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let a = b.push_lvar(lvar("a", int));
        let c = b.push_lvar(lvar("b", int));
        let d = b.push_lvar(lvar("c", int));
        let va = b.expr(ea(), int, Cexpr::Var(a));
        let vb = b.expr(ea(), int, Cexpr::Var(c));
        let vc = b.expr(ea(), int, Cexpr::Var(d));
        let add = b.expr(
            ea(),
            int,
            Cexpr::Binary {
                op: BinOp::Add,
                x: vb,
                y: vc,
            },
        );
        let mul = b.expr(
            ea(),
            int,
            Cexpr::Binary {
                op: BinOp::Mul,
                x: va,
                y: add,
            },
        );
        let ret = b.stmt(ea(), Cinsn::Return(Some(mul)));
        let block = b.stmt(ea(), Cinsn::Block(vec![ret]));
        let tree = b.finish(block);
        assert!(
            tree.to_pseudocode().contains("a * (b + c)"),
            "got: {}",
            tree.to_pseudocode()
        );
    }

    /// Left-associative same-precedence chains need no parentheses.
    #[test]
    fn omits_parens_for_left_associative_chain() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let a = b.push_lvar(lvar("a", int));
        let c = b.push_lvar(lvar("b", int));
        let d = b.push_lvar(lvar("c", int));
        let va = b.expr(ea(), int, Cexpr::Var(a));
        let vb = b.expr(ea(), int, Cexpr::Var(c));
        let vc = b.expr(ea(), int, Cexpr::Var(d));
        let inner = b.expr(
            ea(),
            int,
            Cexpr::Binary {
                op: BinOp::Sub,
                x: va,
                y: vb,
            },
        );
        let outer = b.expr(
            ea(),
            int,
            Cexpr::Binary {
                op: BinOp::Sub,
                x: inner,
                y: vc,
            },
        );
        let ret = b.stmt(ea(), Cinsn::Return(Some(outer)));
        let block = b.stmt(ea(), Cinsn::Block(vec![ret]));
        let tree = b.finish(block);
        let s = tree.to_pseudocode();
        assert!(s.contains("a - b - c"), "got: {s}");
        assert!(!s.contains("("), "should not parenthesize: {s}");
    }

    /// A call renders its callee and comma-joined arguments.
    #[test]
    fn renders_call_with_args() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let a = b.push_lvar(lvar("a", int));
        let va = b.expr(ea(), int, Cexpr::Var(a));
        let callee = b.expr(
            ea(),
            int,
            Cexpr::Obj {
                ea: Ea::new_const(0x2000),
                name: Some("foo".into()),
            },
        );
        let n = b.expr(ea(), int, Cexpr::Num(3));
        let call = b.expr(
            ea(),
            int,
            Cexpr::Call {
                callee,
                args: vec![va, n],
            },
        );
        let st = b.stmt(ea(), Cinsn::Expr(call));
        let block = b.stmt(ea(), Cinsn::Block(vec![st]));
        let tree = b.finish(block);
        assert!(
            tree.to_pseudocode().contains("foo(a, 3)"),
            "got: {}",
            tree.to_pseudocode()
        );
    }

    /// Unary, cast, and string/number leaves.
    #[test]
    fn renders_unary_cast_and_literals() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let a = b.push_lvar(lvar("a", int));
        let va = b.expr(ea(), int, Cexpr::Var(a));
        let neg = b.expr(
            ea(),
            int,
            Cexpr::Unary {
                op: UnOp::Neg,
                x: va,
            },
        );
        let r = b.push_lvar(lvar("r", int));
        let asg = b.expr(ea(), int, Cexpr::Var(r));
        let assign = b.expr(
            ea(),
            int,
            Cexpr::Assign {
                op: AssignOp::Assign,
                x: asg,
                y: neg,
            },
        );
        let st = b.stmt(ea(), Cinsn::Expr(assign));
        let block = b.stmt(ea(), Cinsn::Block(vec![st]));
        let tree = b.finish(block);
        assert!(
            tree.to_pseudocode().contains("r = -a;"),
            "got: {}",
            tree.to_pseudocode()
        );
    }

    /// String and hex/decimal number formatting.
    #[test]
    fn renders_string_and_numbers() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let s = b.expr(ea(), int, Cexpr::Str("hi".into()));
        let big = b.expr(ea(), int, Cexpr::Num(255));
        let small = b.expr(ea(), int, Cexpr::Num(7));
        let st1 = b.stmt(ea(), Cinsn::Expr(s));
        let st2 = b.stmt(ea(), Cinsn::Expr(big));
        let st3 = b.stmt(ea(), Cinsn::Expr(small));
        let block = b.stmt(ea(), Cinsn::Block(vec![st1, st2, st3]));
        let tree = b.finish(block);
        let out = tree.to_pseudocode();
        assert!(out.contains("\"hi\";"), "got: {out}");
        assert!(out.contains("0xff;"), "got: {out}");
        assert!(out.contains("  7;"), "got: {out}");
    }

    /// `if/else` with block bodies, indented.
    #[test]
    fn renders_if_else() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let a = b.push_lvar(lvar("a", int));
        let cond = b.expr(ea(), int, Cexpr::Var(a));
        let r1 = b.stmt(ea(), Cinsn::Return(None));
        let then_ = b.stmt(ea(), Cinsn::Block(vec![r1]));
        let r2 = b.stmt(ea(), Cinsn::Break);
        let else_ = b.stmt(ea(), Cinsn::Block(vec![r2]));
        let iff = b.stmt(
            ea(),
            Cinsn::If {
                cond,
                then_,
                else_: Some(else_),
            },
        );
        let block = b.stmt(ea(), Cinsn::Block(vec![iff]));
        let tree = b.finish(block);
        let out = tree.to_pseudocode();
        assert!(out.contains("if ( a )\n"), "got: {out}");
        assert!(out.contains("  else\n"), "got: {out}");
        assert!(out.contains("    break;\n"), "got: {out}");
    }

    /// A `Var` whose lvar is missing falls back to a synthetic name rather than panicking.
    #[test]
    fn missing_lvar_does_not_panic() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let v = b.expr(ea(), int, Cexpr::Var(LvarId(7)));
        let st = b.stmt(ea(), Cinsn::Expr(v));
        let block = b.stmt(ea(), Cinsn::Block(vec![st]));
        let tree = b.finish(block);
        assert!(
            tree.to_pseudocode().contains("v7"),
            "got: {}",
            tree.to_pseudocode()
        );
    }
}
