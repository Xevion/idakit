//! Render an owned [`Ctree`] back to C-like pseudocode.
//!
//! This is a *fidelity* tool, not a faithful reproduction of IDA's printer: it proves
//! the extracted tree is structurally sound (operators mapped right, operands not
//! dropped, precedence preserved) by turning it back into readable source. It uses only
//! [`Ctree`]'s public navigation, so it stays a pure consumer of the ADT.
//!
//! Exact output is not expected to byte-match IDA's `pseudocode()` -- IDA has its own
//! declaration block, cast style, and spacing. The invariants worth holding are the
//! structural ones, which the unit tests below pin against synthetic trees.

use std::fmt::Write;

use super::node::{Case, ExpressionId, ExpressionKind, LocalId, StatementId, StatementKind};
use super::ops::{BinOp, UnOp};
use super::tree::Ctree;
use crate::types::{TypeId, TypeKind};

// C operator precedence, higher binds tighter. A child is parenthesized when its own
// precedence is below the minimum its position requires (see `Printer::expression`).
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
        p.statement(self.root());
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

    fn statement(&mut self, id: StatementId) {
        let tree = self.tree;
        match &tree.statement(id).kind {
            StatementKind::Block(statements) => {
                let statements = statements.clone();
                self.line("{");
                self.indent += 1;
                for s in statements {
                    self.statement(s);
                }
                self.indent -= 1;
                self.line("}");
            }
            StatementKind::Expression(e) => {
                let e = *e;
                self.push_indent();
                self.expression(e, 0);
                self.out.push_str(";\n");
            }
            StatementKind::If { cond, then_, else_ } => {
                let (cond, then_, else_) = (*cond, *then_, *else_);
                self.push_indent();
                self.out.push_str("if ( ");
                self.expression(cond, 0);
                self.out.push_str(" )\n");
                self.statement(then_);
                if let Some(e) = else_ {
                    self.line("else");
                    self.statement(e);
                }
            }
            StatementKind::For {
                init,
                cond,
                step,
                body,
            } => {
                let (init, cond, step, body) = (*init, *cond, *step, *body);
                self.push_indent();
                self.out.push_str("for ( ");
                if let Some(e) = init {
                    self.expression(e, 0);
                }
                self.out.push_str("; ");
                if let Some(e) = cond {
                    self.expression(e, 0);
                }
                self.out.push_str("; ");
                if let Some(e) = step {
                    self.expression(e, 0);
                }
                self.out.push_str(" )\n");
                self.statement(body);
            }
            StatementKind::While { cond, body } => {
                let (cond, body) = (*cond, *body);
                self.push_indent();
                self.out.push_str("while ( ");
                self.expression(cond, 0);
                self.out.push_str(" )\n");
                self.statement(body);
            }
            StatementKind::Do { body, cond } => {
                let (body, cond) = (*body, *cond);
                self.line("do");
                self.statement(body);
                self.push_indent();
                self.out.push_str("while ( ");
                self.expression(cond, 0);
                self.out.push_str(" );\n");
            }
            StatementKind::Switch { expression, cases } => {
                let expression = *expression;
                let cases = cases.clone();
                self.push_indent();
                self.out.push_str("switch ( ");
                self.expression(expression, 0);
                self.out.push_str(" )\n");
                self.line("{");
                for case in &cases {
                    self.case(case);
                }
                self.line("}");
            }
            StatementKind::Break => self.line("break;"),
            StatementKind::Continue => self.line("continue;"),
            StatementKind::Return(e) => {
                let e = *e;
                self.push_indent();
                self.out.push_str("return");
                if let Some(e) = e {
                    self.out.push(' ');
                    self.expression(e, 0);
                }
                self.out.push_str(";\n");
            }
            StatementKind::Goto { label } => {
                let label = *label;
                self.push_indent();
                writeln!(self.out, "goto LABEL_{label};").unwrap();
            }
            StatementKind::Asm(eas) => {
                let n = eas.len();
                self.push_indent();
                writeln!(self.out, "__asm {{ /* {n} insns */ }}").unwrap();
            }
            StatementKind::Try { body, catches } => {
                let (body, catches) = (*body, catches.clone());
                self.line("try");
                self.statement(body);
                for c in catches {
                    self.line("catch");
                    self.statement(c);
                }
            }
            StatementKind::Throw(e) => {
                let e = *e;
                self.push_indent();
                self.out.push_str("throw");
                if let Some(e) = e {
                    self.out.push(' ');
                    self.expression(e, 0);
                }
                self.out.push_str(";\n");
            }
            StatementKind::Empty => self.line(";"),
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
        self.statement(case.body);
    }

    /// Render `id`, parenthesizing it when its own precedence is below `min_prec` -- the
    /// minimum the surrounding operator position requires.
    fn expression(&mut self, id: ExpressionId, min_prec: u8) {
        let paren = self.prec(id) < min_prec;
        if paren {
            self.out.push('(');
        }
        self.expression_inner(id);
        if paren {
            self.out.push(')');
        }
    }

    fn expression_inner(&mut self, id: ExpressionId) {
        let tree = self.tree;
        match tree.kind(id) {
            ExpressionKind::Binary { op, x, y } => {
                let (op, x, y) = (*op, *x, *y);
                if op == BinOp::Comma {
                    self.expression(x, P_COMMA);
                    self.out.push_str(", ");
                    self.expression(y, P_COMMA + 1);
                } else {
                    let p = bin_prec(op);
                    self.expression(x, p);
                    write!(self.out, " {} ", op.symbol()).unwrap();
                    self.expression(y, p + 1);
                }
            }
            ExpressionKind::Assign { op, x, y } => {
                let (op, x, y) = (*op, *x, *y);
                self.expression(x, P_ASSIGN + 1);
                write!(self.out, " {} ", op.symbol()).unwrap();
                self.expression(y, P_ASSIGN);
            }
            ExpressionKind::Unary { op, x } => {
                let (op, x) = (*op, *x);
                match op {
                    UnOp::PostInc | UnOp::PostDec => {
                        self.expression(x, P_POSTFIX);
                        self.out.push_str(op.symbol());
                    }
                    _ => {
                        self.out.push_str(op.symbol());
                        self.expression(x, P_UNARY);
                    }
                }
            }
            ExpressionKind::Ternary { cond, then_, else_ } => {
                let (cond, then_, else_) = (*cond, *then_, *else_);
                self.expression(cond, P_TERNARY + 1);
                self.out.push_str(" ? ");
                self.expression(then_, 0);
                self.out.push_str(" : ");
                self.expression(else_, P_TERNARY);
            }
            ExpressionKind::Call { callee, args } => {
                let callee = *callee;
                let args = args.clone();
                self.expression(callee, P_POSTFIX);
                self.out.push('(');
                for (i, a) in args.into_iter().enumerate() {
                    if i > 0 {
                        self.out.push_str(", ");
                    }
                    self.expression(a, P_ASSIGN);
                }
                self.out.push(')');
            }
            ExpressionKind::Index { array, index } => {
                let (array, index) = (*array, *index);
                self.expression(array, P_POSTFIX);
                self.out.push('[');
                self.expression(index, 0);
                self.out.push(']');
            }
            ExpressionKind::MemberRef { obj, byte_offset } => {
                let (obj, offset) = (*obj, *byte_offset);
                let name = self.field_name(obj, offset, false);
                self.expression(obj, P_POSTFIX);
                self.out.push('.');
                self.out.push_str(&name);
            }
            ExpressionKind::MemberPtr { obj, byte_offset } => {
                let (obj, offset) = (*obj, *byte_offset);
                let name = self.field_name(obj, offset, true);
                self.expression(obj, P_POSTFIX);
                self.out.push_str("->");
                self.out.push_str(&name);
            }
            ExpressionKind::Cast { x } => {
                let x = *x;
                let ts = self.print_type(tree.expression(id).ty);
                write!(self.out, "({ts})").unwrap();
                self.expression(x, P_UNARY);
            }
            ExpressionKind::Deref { x, .. } => {
                let x = *x;
                self.out.push('*');
                self.expression(x, P_UNARY);
            }
            ExpressionKind::Sizeof(x) => {
                let x = *x;
                self.out.push_str("sizeof(");
                self.expression(x, 0);
                self.out.push(')');
            }
            ExpressionKind::Num(v) => {
                let v = *v;
                if v < 10 {
                    write!(self.out, "{v}").unwrap();
                } else {
                    write!(self.out, "{v:#x}").unwrap();
                }
            }
            ExpressionKind::Fnum(f) => write!(self.out, "{f}").unwrap(),
            ExpressionKind::Str(s) => write!(self.out, "{s:?}").unwrap(),
            ExpressionKind::Obj { address, name } => match name {
                Some(n) => self.out.push_str(n),
                None => write!(self.out, "{address:#x}").unwrap(),
            },
            ExpressionKind::Var(v) => {
                let name = self.lvar_name(*v);
                self.out.push_str(&name);
            }
            ExpressionKind::Helper(s) => self.out.push_str(s),
            ExpressionKind::TypeExpression => {
                let ts = self.print_type(tree.expression(id).ty);
                self.out.push_str(&ts);
            }
            ExpressionKind::Empty => {}
            ExpressionKind::Internal => self.out.push_str("/* internal */"),
        }
    }

    /// The precedence of the operator at the root of `id` (primary for leaves).
    fn prec(&self, id: ExpressionId) -> u8 {
        match self.tree.kind(id) {
            ExpressionKind::Binary { op, .. } => bin_prec(*op),
            ExpressionKind::Assign { .. } => P_ASSIGN,
            ExpressionKind::Ternary { .. } => P_TERNARY,
            ExpressionKind::Unary { op, .. } => match op {
                UnOp::PostInc | UnOp::PostDec => P_POSTFIX,
                _ => P_UNARY,
            },
            ExpressionKind::Call { .. }
            | ExpressionKind::Index { .. }
            | ExpressionKind::MemberRef { .. }
            | ExpressionKind::MemberPtr { .. } => P_POSTFIX,
            ExpressionKind::Cast { .. }
            | ExpressionKind::Deref { .. }
            | ExpressionKind::Sizeof(_) => P_UNARY,
            _ => P_PRIMARY,
        }
    }

    /// A struct/union member name at `byte_off`, resolved through the object's type; falls
    /// back to a synthetic `field_<off>` when the type isn't an aggregate we can index.
    fn field_name(&self, obj: ExpressionId, byte_off: u32, through_ptr: bool) -> String {
        let mut ty = self.tree.type_of(self.tree.expression(obj).ty);
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
            TypeKind::Opaque(name) => Some(name.clone()),
            _ => None,
        }
    }

    fn lvar_name(&self, v: LocalId) -> String {
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
            TypeKind::Function {
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
            TypeKind::Opaque(name) => name.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Address;
    use crate::ctree::node::{Local, LocalLocation};
    use crate::ctree::ops::AssignOp;
    use crate::ctree::tree::CtreeBuilder;
    use crate::types::{TypeData, TypeKind, TypeMember};
    use assert2::assert;
    use rstest::rstest;

    fn int32(b: &mut CtreeBuilder) -> TypeId {
        b.intern_type(TypeData {
            kind: TypeKind::Int {
                bytes: 4,
                signed: true,
            },
            size: Some(4),
        })
    }

    fn lvar(name: &str, ty: TypeId) -> Local {
        Local {
            name: name.into(),
            ty,
            is_arg: false,
            is_result: false,
            is_byref: false,
            width: 4,
            comment: None,
            location: LocalLocation::Register(0),
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
        let v = b.var(pderived, this);
        let mp = b.member_ptr(base, v, 0);
        let st = b.expression_statement(mp);
        let block = b.block(vec![st]);
        let tree = b.finish(block);
        let out = tree.to_pseudocode();
        assert!(out.contains("this->Base"), "got: {out}");
    }

    /// `{ return a + b; }` -- the canonical small tree, rendered exactly.
    #[test]
    fn renders_return_of_binary() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let a = b.push_lvar(lvar("a", int));
        let bb = b.push_lvar(lvar("b", int));
        let va = b.var(int, a);
        let vb = b.var(int, bb);
        let add = b.binary(int, BinOp::Add, va, vb);
        let ret = b.ret(Some(add));
        let block = b.block(vec![ret]);
        let tree = b.finish(block);
        assert!(tree.to_pseudocode() == "{\n  return a + b;\n}\n");
    }

    /// The printer spells each binary operator via [`BinOp::symbol`]; render `a OP b` and
    /// confirm the glyph lands. Guards the render->ops delegation across the table.
    #[rstest]
    #[case(BinOp::Add, "a + b")]
    #[case(BinOp::BitAnd, "a & b")]
    #[case(BinOp::Shl, "a << b")]
    #[case(BinOp::LogOr, "a || b")]
    #[case(BinOp::Eq, "a == b")]
    fn binary_operator_renders_with_its_symbol(#[case] op: BinOp, #[case] expect: &str) {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let a = b.push_lvar(lvar("a", int));
        let bb = b.push_lvar(lvar("b", int));
        let va = b.var(int, a);
        let vb = b.var(int, bb);
        let bin = b.binary(int, op, va, vb);
        let st = b.expression_statement(bin);
        let block = b.block(vec![st]);
        let tree = b.finish(block);
        let out = tree.to_pseudocode();
        assert!(out.contains(expect), "got: {out}");
    }

    /// A lower-precedence right operand must be parenthesized.
    #[test]
    fn parenthesizes_lower_precedence_child() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let a = b.push_lvar(lvar("a", int));
        let c = b.push_lvar(lvar("b", int));
        let d = b.push_lvar(lvar("c", int));
        let va = b.var(int, a);
        let vb = b.var(int, c);
        let vc = b.var(int, d);
        let add = b.binary(int, BinOp::Add, vb, vc);
        let mul = b.binary(int, BinOp::Mul, va, add);
        let ret = b.ret(Some(mul));
        let block = b.block(vec![ret]);
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
        let va = b.var(int, a);
        let vb = b.var(int, c);
        let vc = b.var(int, d);
        let inner = b.binary(int, BinOp::Sub, va, vb);
        let outer = b.binary(int, BinOp::Sub, inner, vc);
        let ret = b.ret(Some(outer));
        let block = b.block(vec![ret]);
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
        let va = b.var(int, a);
        let callee = b.obj(int, Address::new_const(0x2000), Some("foo"));
        let n = b.num(int, 3);
        let call = b.call_expression(int, callee, vec![va, n]);
        let st = b.expression_statement(call);
        let block = b.block(vec![st]);
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
        let va = b.var(int, a);
        let neg = b.unary(int, UnOp::Neg, va);
        let r = b.push_lvar(lvar("r", int));
        let asg = b.var(int, r);
        let assign = b.assign(int, AssignOp::Assign, asg, neg);
        let st = b.expression_statement(assign);
        let block = b.block(vec![st]);
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
        let s = b.string(int, "hi");
        let big = b.num(int, 255);
        let small = b.num(int, 7);
        let st1 = b.expression_statement(s);
        let st2 = b.expression_statement(big);
        let st3 = b.expression_statement(small);
        let block = b.block(vec![st1, st2, st3]);
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
        let cond = b.var(int, a);
        let r1 = b.ret(None);
        let then_ = b.block(vec![r1]);
        let r2 = b.statement(StatementKind::Break).call();
        let else_ = b.block(vec![r2]);
        let iff = b
            .statement(StatementKind::If {
                cond,
                then_,
                else_: Some(else_),
            })
            .call();
        let block = b.block(vec![iff]);
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
        let v = b.var(int, LocalId(7));
        let st = b.expression_statement(v);
        let block = b.block(vec![st]);
        let tree = b.finish(block);
        assert!(
            tree.to_pseudocode().contains("v7"),
            "got: {}",
            tree.to_pseudocode()
        );
    }
}
