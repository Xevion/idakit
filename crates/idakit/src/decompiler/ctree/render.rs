//! Render an owned [`Ctree`] back to C-like pseudocode.
//!
//! This is a *fidelity* tool, not a faithful reproduction of IDA's printer. It proves
//! the extracted tree is structurally sound (operators mapped right, operands not
//! dropped, precedence preserved) by turning it back into readable source. It uses only
//! [`Ctree`]'s public navigation, so it stays a pure consumer of the ADT.
//!
//! Exact output is not expected to byte-match IDA's `pseudocode()`, since IDA has its own
//! declaration block, cast style, and spacing. The invariants worth holding are the
//! structural ones, which the unit tests below pin against synthetic trees.

use std::fmt::Write;

use super::node::{Case, ExpressionId, ExpressionKind, LocalId, StatementId, StatementKind};
use super::ops::{BinaryOp, UnaryOp};
use super::tree::Ctree;
use crate::types::{TypeId, TypeShape};

/// A C operator precedence level, ordered so a higher level binds tighter.
///
/// A child expression is parenthesized when its own level is below the minimum its position
/// requires, which [`Printer::expression`] applies.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Prec(u8);

impl Prec {
    /// No minimum, so the position never parenthesizes its child. Used where the grammar
    /// already delimits a full expression, as between `?` and `:` or inside `[]`.
    const ANY: Self = Self(0);
    const COMMA: Self = Self(1);
    const ASSIGN: Self = Self(2);
    const TERNARY: Self = Self(3);
    const LOGOR: Self = Self(4);
    const LOGAND: Self = Self(5);
    const BITOR: Self = Self(6);
    const BITXOR: Self = Self(7);
    const BITAND: Self = Self(8);
    const EQ: Self = Self(9);
    const REL: Self = Self(10);
    const SHIFT: Self = Self(11);
    const ADD: Self = Self(12);
    const MUL: Self = Self(13);
    const UNARY: Self = Self(14);
    const POSTFIX: Self = Self(15);
    const PRIMARY: Self = Self(16);

    /// One level tighter, which is what an operand must bind to stay unparenthesized against
    /// its own operator. A left-associative operator asks this of its right operand, so
    /// `a - (b - c)` keeps its parentheses while `a - b - c` does not.
    const fn tighter(self) -> Self {
        Self(self.0 + 1)
    }
}

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
                self.expression(e, Prec::ANY);
                self.out.push_str(";\n");
            }
            StatementKind::If { cond, then_, else_ } => {
                let (cond, then_, else_) = (*cond, *then_, *else_);
                self.push_indent();
                self.out.push_str("if ( ");
                self.expression(cond, Prec::ANY);
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
                    self.expression(e, Prec::ANY);
                }
                self.out.push_str("; ");
                if let Some(e) = cond {
                    self.expression(e, Prec::ANY);
                }
                self.out.push_str("; ");
                if let Some(e) = step {
                    self.expression(e, Prec::ANY);
                }
                self.out.push_str(" )\n");
                self.statement(body);
            }
            StatementKind::While { cond, body } => {
                let (cond, body) = (*cond, *body);
                self.push_indent();
                self.out.push_str("while ( ");
                self.expression(cond, Prec::ANY);
                self.out.push_str(" )\n");
                self.statement(body);
            }
            StatementKind::Do { body, cond } => {
                let (body, cond) = (*body, *cond);
                self.line("do");
                self.statement(body);
                self.push_indent();
                self.out.push_str("while ( ");
                self.expression(cond, Prec::ANY);
                self.out.push_str(" );\n");
            }
            StatementKind::Switch { expression, cases } => {
                let expression = *expression;
                let cases = cases.clone();
                self.push_indent();
                self.out.push_str("switch ( ");
                self.expression(expression, Prec::ANY);
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
                    self.expression(e, Prec::ANY);
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
                    self.expression(e, Prec::ANY);
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

    /// Render `id`, parenthesizing it when its own precedence is below `min_prec`: the
    /// minimum the surrounding operator position requires.
    fn expression(&mut self, id: ExpressionId, min_prec: Prec) {
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
                if op == BinaryOp::Comma {
                    self.expression(x, Prec::COMMA);
                    self.out.push_str(", ");
                    self.expression(y, Prec::COMMA.tighter());
                } else {
                    let p = bin_prec(op);
                    self.expression(x, p);
                    write!(self.out, " {} ", op.symbol()).unwrap();
                    self.expression(y, p.tighter());
                }
            }
            ExpressionKind::Assign { op, x, y } => {
                let (op, x, y) = (*op, *x, *y);
                self.expression(x, Prec::ASSIGN.tighter());
                write!(self.out, " {} ", op.symbol()).unwrap();
                self.expression(y, Prec::ASSIGN);
            }
            ExpressionKind::Unary { op, x } => {
                let (op, x) = (*op, *x);
                match op {
                    UnaryOp::PostInc | UnaryOp::PostDec => {
                        self.expression(x, Prec::POSTFIX);
                        self.out.push_str(op.symbol());
                    }
                    _ => {
                        self.out.push_str(op.symbol());
                        self.expression(x, Prec::UNARY);
                    }
                }
            }
            ExpressionKind::Ternary { cond, then_, else_ } => {
                let (cond, then_, else_) = (*cond, *then_, *else_);
                self.expression(cond, Prec::TERNARY.tighter());
                self.out.push_str(" ? ");
                self.expression(then_, Prec::ANY);
                self.out.push_str(" : ");
                self.expression(else_, Prec::TERNARY);
            }
            ExpressionKind::Call { callee, args } => {
                let callee = *callee;
                let args = args.clone();
                self.expression(callee, Prec::POSTFIX);
                self.out.push('(');
                for (i, a) in args.into_iter().enumerate() {
                    if i > 0 {
                        self.out.push_str(", ");
                    }
                    self.expression(a, Prec::ASSIGN);
                }
                self.out.push(')');
            }
            ExpressionKind::Index { array, index } => {
                let (array, index) = (*array, *index);
                self.expression(array, Prec::POSTFIX);
                self.out.push('[');
                self.expression(index, Prec::ANY);
                self.out.push(']');
            }
            ExpressionKind::MemberRef { obj, byte_offset } => {
                let (obj, offset) = (*obj, *byte_offset);
                let name = self.field_name(obj, offset, false);
                self.expression(obj, Prec::POSTFIX);
                self.out.push('.');
                self.out.push_str(&name);
            }
            ExpressionKind::MemberPtr { obj, byte_offset } => {
                let (obj, offset) = (*obj, *byte_offset);
                let name = self.field_name(obj, offset, true);
                self.expression(obj, Prec::POSTFIX);
                self.out.push_str("->");
                self.out.push_str(&name);
            }
            ExpressionKind::Cast { x } => {
                let x = *x;
                let ts = self.print_type(tree.expression(id).ty);
                write!(self.out, "({ts})").unwrap();
                self.expression(x, Prec::UNARY);
            }
            ExpressionKind::Deref { x, .. } => {
                let x = *x;
                self.out.push('*');
                self.expression(x, Prec::UNARY);
            }
            ExpressionKind::Sizeof(x) => {
                let x = *x;
                self.out.push_str("sizeof(");
                self.expression(x, Prec::ANY);
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
                let name = self.local_name(*v);
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
    fn prec(&self, id: ExpressionId) -> Prec {
        match self.tree.kind(id) {
            ExpressionKind::Binary { op, .. } => bin_prec(*op),
            ExpressionKind::Assign { .. } => Prec::ASSIGN,
            ExpressionKind::Ternary { .. } => Prec::TERNARY,
            ExpressionKind::Unary { op, .. } => match op {
                UnaryOp::PostInc | UnaryOp::PostDec => Prec::POSTFIX,
                _ => Prec::UNARY,
            },
            ExpressionKind::Call { .. }
            | ExpressionKind::Index { .. }
            | ExpressionKind::MemberRef { .. }
            | ExpressionKind::MemberPtr { .. } => Prec::POSTFIX,
            ExpressionKind::Cast { .. }
            | ExpressionKind::Deref { .. }
            | ExpressionKind::Sizeof(_) => Prec::UNARY,
            _ => Prec::PRIMARY,
        }
    }

    /// A struct/union member name at `byte_off`, resolved through the object's type; falls
    /// back to a synthetic `field_<off>` when the type isn't an aggregate we can index.
    fn field_name(&self, obj: ExpressionId, byte_off: u32, through_ptr: bool) -> String {
        let mut ty = self.tree.type_of(self.tree.expression(obj).ty);
        if through_ptr && let TypeShape::Ptr(p) = &ty.shape {
            ty = self.tree.type_of(*p);
        }
        let members = match &ty.shape {
            TypeShape::Struct { members, .. } | TypeShape::Union { members, .. } => Some(members),
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
        match &self.tree.type_of(id).shape {
            TypeShape::Struct { name, .. }
            | TypeShape::Union { name, .. }
            | TypeShape::Enum { name, .. } => name.clone(),
            TypeShape::Typedef { name, .. } | TypeShape::Opaque(name) => Some(name.clone()),
            _ => None,
        }
    }

    fn local_name(&self, v: LocalId) -> String {
        self.tree
            .locals()
            .nth(v.0 as usize)
            .map_or_else(|| format!("v{}", v.0), |l| l.name.clone())
    }

    fn print_type(&self, id: TypeId) -> String {
        let t = self.tree.type_of(id);
        match &t.shape {
            TypeShape::Void => "void".into(),
            TypeShape::Bool => "bool".into(),
            TypeShape::Int { bytes, signed } => {
                let bits = u32::from(*bytes) * 8;
                if *signed {
                    format!("__int{bits}")
                } else {
                    format!("unsigned __int{bits}")
                }
            }
            TypeShape::Float { bytes } => match bytes {
                4 => "float".into(),
                8 => "double".into(),
                _ => "long double".into(),
            },
            TypeShape::Ptr(p) => format!("{} *", self.print_type(*p)),
            TypeShape::Array { elem, len } => format!("{}[{}]", self.print_type(*elem), len),
            TypeShape::Struct { name, .. } => name.clone().unwrap_or_else(|| "struct".into()),
            TypeShape::Union { name, .. } => name.clone().unwrap_or_else(|| "union".into()),
            TypeShape::Enum { name, .. } => name.clone().unwrap_or_else(|| "enum".into()),
            TypeShape::Function {
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
            TypeShape::Typedef { name, .. } | TypeShape::Opaque(name) => name.clone(),
            TypeShape::Unknown => "_UNKNOWN".into(),
        }
    }
}

fn bin_prec(op: BinaryOp) -> Prec {
    match op {
        BinaryOp::Comma => Prec::COMMA,
        BinaryOp::LogOr => Prec::LOGOR,
        BinaryOp::LogAnd => Prec::LOGAND,
        BinaryOp::BitOr => Prec::BITOR,
        BinaryOp::BitXor => Prec::BITXOR,
        BinaryOp::BitAnd => Prec::BITAND,
        BinaryOp::Eq | BinaryOp::Ne => Prec::EQ,
        BinaryOp::Sge
        | BinaryOp::Uge
        | BinaryOp::Sle
        | BinaryOp::Ule
        | BinaryOp::Sgt
        | BinaryOp::Ugt
        | BinaryOp::Slt
        | BinaryOp::Ult => Prec::REL,
        BinaryOp::Sshr | BinaryOp::Ushr | BinaryOp::Shl => Prec::SHIFT,
        BinaryOp::Add | BinaryOp::Sub | BinaryOp::Fadd | BinaryOp::Fsub => Prec::ADD,
        BinaryOp::Mul
        | BinaryOp::Sdiv
        | BinaryOp::Udiv
        | BinaryOp::Smod
        | BinaryOp::Umod
        | BinaryOp::Fmul
        | BinaryOp::Fdiv => Prec::MUL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::decompiler::ctree::node::{Local, LocalLocation};
    use crate::decompiler::ctree::ops::AssignmentOp;
    use crate::decompiler::ctree::tree::CtreeBuilder;
    use crate::types::{TypeMember, TypeShape, TypeValue};
    use assert2::assert;
    use rstest::rstest;

    fn int32(b: &mut CtreeBuilder) -> TypeId {
        b.intern_type(TypeValue {
            shape: TypeShape::Int {
                bytes: 4,
                signed: true,
            },
            size: Some(4),
        })
    }

    fn local(name: &str, ty: TypeId) -> Local {
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

    /// A fresh local of type `ty` plus a `Var` referencing it.
    fn var_named(b: &mut CtreeBuilder, name: &str, ty: TypeId) -> ExpressionId {
        let l = b.push_local(local(name, ty));
        b.var(ty, l)
    }

    /// Wrap `e` in a one-statement block and render it.
    fn render_expr(mut b: CtreeBuilder, e: ExpressionId) -> String {
        let st = b.expression_statement(e);
        let block = b.block(vec![st]);
        b.finish(block).to_pseudocode()
    }

    /// A struct with one empty-named base member at bit offset 0, of type `ty`.
    fn empty_base_member(b: &mut CtreeBuilder, ty: TypeId) -> TypeId {
        b.intern_type(TypeValue {
            shape: TypeShape::Struct {
                name: Some("Derived".into()),
                members: vec![TypeMember {
                    name: String::new(),
                    bit_offset: 0,
                    ty,
                    bitfield_width: None,
                    repr: None,
                }],
            },
            size: Some(8),
        })
    }

    fn base_struct_via_ptr(b: &mut CtreeBuilder) -> ExpressionId {
        let base = b.intern_type(TypeValue {
            shape: TypeShape::Struct {
                name: Some("Base".into()),
                members: vec![],
            },
            size: Some(8),
        });
        let derived = empty_base_member(b, base);
        let pderived = b.intern_type(TypeValue {
            shape: TypeShape::Ptr(derived),
            size: Some(8),
        });
        let v = var_named(b, "this", pderived);
        b.member_ptr(base, v, 0)
    }

    fn base_opaque_via_value(b: &mut CtreeBuilder) -> ExpressionId {
        let opaque = b.intern_type(TypeValue {
            shape: TypeShape::Opaque("Foo".into()),
            size: Some(8),
        });
        let derived = empty_base_member(b, opaque);
        let v = var_named(b, "s", derived);
        b.member_ref(opaque, v, 0)
    }

    /// A base-class subobject arrives with an empty member name and renders as the subobject's
    /// type name (what IDA shows for `this->Base`), never blank. Covers both `type_tag_name`
    /// arms: a named `Struct` base peeled through a pointer, and an `Opaque` base on a value.
    #[rstest]
    #[case(base_struct_via_ptr, "this->Base")]
    #[case(base_opaque_via_value, "s.Foo")]
    fn empty_member_renders_base_type_name(
        #[case] build: fn(&mut CtreeBuilder) -> ExpressionId,
        #[case] expect: &str,
    ) {
        let mut b = CtreeBuilder::new();
        let mr = build(&mut b);
        let out = render_expr(b, mr);
        assert!(out.contains(expect), "got: {out}");
    }

    /// `{ return a + b; }`: the canonical small tree, rendered exactly.
    #[test]
    fn renders_return_of_binary() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let a = b.push_local(local("a", int));
        let bb = b.push_local(local("b", int));
        let va = b.var(int, a);
        let vb = b.var(int, bb);
        let add = b.binary(int, BinaryOp::Add, va, vb);
        let ret = b.ret(Some(add));
        let block = b.block(vec![ret]);
        let tree = b.finish(block);
        assert!(tree.to_pseudocode() == "{\n  return a + b;\n}\n");
    }

    /// The printer spells each binary operator via [`BinaryOp::symbol`]; render `a OP b` and
    /// confirm the glyph lands. Guards the render->ops delegation across the table.
    #[rstest]
    #[case(BinaryOp::Add, "a + b")]
    #[case(BinaryOp::BitAnd, "a & b")]
    #[case(BinaryOp::Shl, "a << b")]
    #[case(BinaryOp::LogOr, "a || b")]
    #[case(BinaryOp::Eq, "a == b")]
    fn binary_operator_renders_with_its_symbol(#[case] op: BinaryOp, #[case] expect: &str) {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let a = b.push_local(local("a", int));
        let bb = b.push_local(local("b", int));
        let va = b.var(int, a);
        let vb = b.var(int, bb);
        let bin = b.binary(int, op, va, vb);
        let st = b.expression_statement(bin);
        let block = b.block(vec![st]);
        let tree = b.finish(block);
        let out = tree.to_pseudocode();
        assert!(out.contains(expect), "got: {out}");
    }

    /// Left-associative same-precedence chains need no parentheses.
    #[test]
    #[expect(
        clippy::many_single_char_names,
        reason = "single-letter locals mirror the a - b - c expression the test builds"
    )]
    fn omits_parens_for_left_associative_chain() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let a = b.push_local(local("a", int));
        let c = b.push_local(local("b", int));
        let d = b.push_local(local("c", int));
        let va = b.var(int, a);
        let vb = b.var(int, c);
        let vc = b.var(int, d);
        let inner = b.binary(int, BinaryOp::Sub, va, vb);
        let outer = b.binary(int, BinaryOp::Sub, inner, vc);
        let ret = b.ret(Some(outer));
        let block = b.block(vec![ret]);
        let tree = b.finish(block);
        let s = tree.to_pseudocode();
        assert!(s.contains("a - b - c"), "got: {s}");
        assert!(!s.contains('('), "should not parenthesize: {s}");
    }

    /// A call renders its callee and comma-joined arguments.
    #[test]
    fn renders_call_with_args() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let a = b.push_local(local("a", int));
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

    /// A prefix unary inside an assignment statement renders `r = -a;`.
    #[test]
    fn renders_negation_assignment() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let va = var_named(&mut b, "a", int);
        let neg = b.unary(int, UnaryOp::Neg, va);
        let asg = var_named(&mut b, "r", int);
        let assign = b.assign(int, AssignmentOp::Assign, asg, neg);
        let out = render_expr(b, assign);
        assert!(out.contains("r = -a;"), "got: {out}");
    }

    /// A string literal renders quoted; the real decompiler surfaces these rarely, so unit
    /// coverage stands in. Number formatting is pinned by `num_switches_to_hex_at_ten`.
    #[test]
    fn renders_string_literal() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let s = b.string(int, "hi");
        let out = render_expr(b, s);
        assert!(out.contains("\"hi\";"), "got: {out}");
    }

    /// `if/else` with block bodies, indented.
    #[test]
    fn renders_if_else() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let a = b.push_local(local("a", int));
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

    /// A `Var` whose local is missing falls back to a synthetic name rather than panicking.
    #[test]
    fn missing_local_does_not_panic() {
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

    fn mul_over_add(b: &mut CtreeBuilder, int: TypeId) -> ExpressionId {
        let va = var_named(b, "a", int);
        let vb = var_named(b, "b", int);
        let vc = var_named(b, "c", int);
        let add = b.binary(int, BinaryOp::Add, vb, vc);
        b.binary(int, BinaryOp::Mul, va, add)
    }

    fn sub_over_sub(b: &mut CtreeBuilder, int: TypeId) -> ExpressionId {
        let va = var_named(b, "a", int);
        let vb = var_named(b, "b", int);
        let vc = var_named(b, "c", int);
        let inner = b.binary(int, BinaryOp::Sub, vb, vc);
        b.binary(int, BinaryOp::Sub, va, inner)
    }

    fn add_over_assign(b: &mut CtreeBuilder, int: TypeId) -> ExpressionId {
        let va = var_named(b, "a", int);
        let vb = var_named(b, "b", int);
        let vc = var_named(b, "c", int);
        let child = b.assign(int, AssignmentOp::Assign, vb, vc);
        b.binary(int, BinaryOp::Add, va, child)
    }

    fn add_over_ternary(b: &mut CtreeBuilder, int: TypeId) -> ExpressionId {
        let va = var_named(b, "a", int);
        let vb = var_named(b, "b", int);
        let vc = var_named(b, "c", int);
        let vd = var_named(b, "d", int);
        let child = b.ternary(int, vb, vc, vd);
        b.binary(int, BinaryOp::Add, va, child)
    }

    /// A right operand at or below its operator's precedence is parenthesized: a strictly lower
    /// child because its own level trails, a same-level one because `Prec::tighter` raises its
    /// minimum by one (left-associativity). Covers the `Binary`/`Assign`/`Ternary` `prec` arms,
    /// since a wrong level drops or adds the parentheses.
    #[rstest]
    #[case(mul_over_add, "a * (b + c)")]
    #[case(sub_over_sub, "a - (b - c)")]
    #[case(add_over_assign, "a + (b = c)")]
    #[case(add_over_ternary, "a + (b ? c : d)")]
    fn child_parenthesized_by_precedence(
        #[case] build: fn(&mut CtreeBuilder, TypeId) -> ExpressionId,
        #[case] expect: &str,
    ) {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let e = build(&mut b, int);
        let out = render_expr(b, e);
        assert!(out.contains(expect), "got: {out}");
    }

    fn neg_child(b: &mut CtreeBuilder, int: TypeId) -> ExpressionId {
        let va = var_named(b, "a", int);
        b.unary(int, UnaryOp::Neg, va)
    }

    fn post_inc_child(b: &mut CtreeBuilder, int: TypeId) -> ExpressionId {
        let va = var_named(b, "a", int);
        b.unary(int, UnaryOp::PostInc, va)
    }

    fn deref_child(b: &mut CtreeBuilder, int: TypeId) -> ExpressionId {
        let ptr = b.intern_type(TypeValue {
            shape: TypeShape::Ptr(int),
            size: Some(8),
        });
        let vp = var_named(b, "p", ptr);
        b.deref(int, vp, 4)
    }

    /// At a postfix position (`child[0]`), a unary-precedence child is parenthesized while a
    /// postfix-precedence post-increment is not. Pins the `Unary`/`Cast|Deref|Sizeof` `prec` arms
    /// and the post-inc/dec case, since a wrong level flips the parentheses.
    #[rstest]
    #[case(neg_child, "(-a)[0]")]
    #[case(deref_child, "(*p)[0]")]
    #[case(post_inc_child, "a++[0]")]
    fn postfix_position_parenthesizes_by_precedence(
        #[case] build: fn(&mut CtreeBuilder, TypeId) -> ExpressionId,
        #[case] expect: &str,
    ) {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let child = build(&mut b, int);
        let zero = b.num(int, 0);
        let idx = b.index(int, child, zero);
        let out = render_expr(b, idx);
        assert!(out.contains(expect), "got: {out}");
    }

    /// Post-increment prints its operator suffixed, `a++`, not prefixed like an ordinary unary.
    #[test]
    fn post_increment_renders_suffixed() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let va = var_named(&mut b, "a", int);
        let pi = b.unary(int, UnaryOp::PostInc, va);
        let out = render_expr(b, pi);
        assert!(out.contains("a++;"), "got: {out}");
        assert!(!out.contains("++a"), "prefix, not suffix: {out}");
    }

    /// An integer literal renders decimal below ten and hexadecimal from ten up.
    #[rstest]
    #[case(9, "9;")]
    #[case(10, "0xa;")]
    #[case(16, "0x10;")]
    fn num_switches_to_hex_at_ten(#[case] value: u64, #[case] expect: &str) {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let n = b.num(int, value);
        let out = render_expr(b, n);
        assert!(out.contains(expect), "got: {out}");
    }

    /// A `switch` renders each `case N:` and the `default:` label.
    #[test]
    fn switch_renders_case_and_default_labels() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let sel = var_named(&mut b, "a", int);
        let matched = b.ret(None);
        let fallthrough = b.ret(None);
        let cases = vec![
            Case {
                values: vec![5],
                body: matched,
            },
            Case {
                values: vec![],
                body: fallthrough,
            },
        ];
        let switch = b
            .statement(StatementKind::Switch {
                expression: sel,
                cases,
            })
            .call();
        let block = b.block(vec![switch]);
        let out = b.finish(block).to_pseudocode();
        assert!(out.contains("case 5:"), "got: {out}");
        assert!(out.contains("default:"), "got: {out}");
    }

    /// A named member resolves through its byte offset (byte times eight into a bit offset), so
    /// an access at byte 4 finds the member declared at bit 32.
    #[test]
    fn member_resolves_by_byte_offset() {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let s_ty = b.intern_type(TypeValue {
            shape: TypeShape::Struct {
                name: Some("S".into()),
                members: vec![TypeMember {
                    name: "x".into(),
                    bit_offset: 32,
                    ty: int,
                    bitfield_width: None,
                    repr: None,
                }],
            },
            size: Some(8),
        });
        let s = b.push_local(local("s", s_ty));
        let v = b.var(s_ty, s);
        let mr = b.member_ref(int, v, 4);
        let out = render_expr(b, mr);
        assert!(out.contains("s.x"), "got: {out}");
    }

    /// A cast prints its target type's exact spelling, including each scalar width. Guards
    /// `print_type` against a stubbed body and against wrong bit-width arithmetic.
    #[rstest]
    #[case(TypeShape::Void, "(void)")]
    #[case(TypeShape::Bool, "(bool)")]
    #[case(TypeShape::Int { bytes: 4, signed: true }, "(__int32)")]
    #[case(TypeShape::Int { bytes: 8, signed: true }, "(__int64)")]
    #[case(TypeShape::Int { bytes: 4, signed: false }, "(unsigned __int32)")]
    #[case(TypeShape::Float { bytes: 4 }, "(float)")]
    #[case(TypeShape::Float { bytes: 8 }, "(double)")]
    #[case(TypeShape::Float { bytes: 16 }, "(long double)")]
    fn cast_renders_target_type_spelling(#[case] shape: TypeShape, #[case] expect: &str) {
        let mut b = CtreeBuilder::new();
        let int = int32(&mut b);
        let ty = b.intern_type(TypeValue { shape, size: None });
        let va = var_named(&mut b, "a", int);
        let cast = b.cast(ty, va);
        let out = render_expr(b, cast);
        assert!(out.contains(expect), "got: {out}");
    }
}
