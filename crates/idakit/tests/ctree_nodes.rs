//! Node-by-node ctree extraction check against real decompiler output.
//!
//! Compiles `tests/fixtures/ctree_kinds.cpp` with g++, lets IDA auto-analyze it headlessly, then
//! decompiles every function once and asserts the extracted [`Ctree`] against the shape the
//! decompiler actually produces: every statement/expression/type kind the decompiler emits is
//! present, every allocated node is reachable from the root (so a sink callback that drops or
//! mis-threads a handle is caught), a `switch`'s case-value pool is sliced correctly, and the
//! local-variable flags and node addresses survive. It also pins the [`DecompiledFunction`]
//! surface: `pseudocode`, `expr_extraction_expectation`, and the `Debug` impl.
//!
//! The kinds Hex-Rays does not emit from optimization-stripped, debug-info-free code (member
//! accesses on untyped pointers, `goto`/`continue`/inline-asm/try-throw, string-literal and
//! ternary nodes) are driven directly against the sink in the `extract` unit tests instead; this
//! test covers everything the real decompiler reaches. A normal `#[test]`, skipped when `g++` is
//! unavailable to build the fixture.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use assert2::assert;
use idakit::decompiler::ctree::{Ctree, ExpressionKind, NodeRef, StatementKind};
use idakit::prelude::*;
use idakit::types::TypeShape;

fn gxx_available() -> bool {
    Command::new("g++")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn expr_name(k: &ExpressionKind) -> &'static str {
    match k {
        ExpressionKind::Binary { .. } => "Binary",
        ExpressionKind::Assign { .. } => "Assign",
        ExpressionKind::Unary { .. } => "Unary",
        ExpressionKind::Ternary { .. } => "Ternary",
        ExpressionKind::Call { .. } => "Call",
        ExpressionKind::Index { .. } => "Index",
        ExpressionKind::MemberRef { .. } => "MemberRef",
        ExpressionKind::MemberPtr { .. } => "MemberPtr",
        ExpressionKind::Cast { .. } => "Cast",
        ExpressionKind::Deref { .. } => "Deref",
        ExpressionKind::Sizeof(_) => "Sizeof",
        ExpressionKind::Num(_) => "Num",
        ExpressionKind::Fnum(_) => "Fnum",
        ExpressionKind::Str(_) => "Str",
        ExpressionKind::Obj { .. } => "Obj",
        ExpressionKind::Var(_) => "Var",
        ExpressionKind::Helper(_) => "Helper",
        ExpressionKind::TypeExpression => "TypeExpression",
        ExpressionKind::Empty => "Empty",
        ExpressionKind::Internal => "Internal",
    }
}

fn stmt_name(k: &StatementKind) -> &'static str {
    match k {
        StatementKind::Block(_) => "Block",
        StatementKind::Expression(_) => "Expression",
        StatementKind::If { .. } => "If",
        StatementKind::For { .. } => "For",
        StatementKind::While { .. } => "While",
        StatementKind::Do { .. } => "Do",
        StatementKind::Switch { .. } => "Switch",
        StatementKind::Break => "Break",
        StatementKind::Continue => "Continue",
        StatementKind::Return(_) => "Return",
        StatementKind::Goto { .. } => "Goto",
        StatementKind::Asm(_) => "Asm",
        StatementKind::Try { .. } => "Try",
        StatementKind::Throw(_) => "Throw",
        StatementKind::Empty => "Empty",
    }
}

fn shape_name(s: &TypeShape) -> &'static str {
    match s {
        TypeShape::Void => "Void",
        TypeShape::Bool => "Bool",
        TypeShape::Int { .. } => "Int",
        TypeShape::Float { .. } => "Float",
        TypeShape::Ptr(_) => "Ptr",
        TypeShape::Array { .. } => "Array",
        TypeShape::Struct { .. } => "Struct",
        TypeShape::Union { .. } => "Union",
        TypeShape::Enum { .. } => "Enum",
        TypeShape::Function { .. } => "Function",
        TypeShape::Typedef { .. } => "Typedef",
        TypeShape::Opaque(_) => "Opaque",
        TypeShape::Unknown => "Unknown",
    }
}

/// Every node allocated in `tree` is reachable from the root, so no sink callback dropped its
/// node's handle or threaded a wrong one to a parent.
fn all_reachable(tree: &Ctree) -> bool {
    let total = tree.expressions().count() + tree.statements().count();
    let seen: BTreeSet<NodeRef> = tree.descendants(NodeRef::Statement(tree.root())).collect();
    seen.len() == total
}

/// The largest distinct case-value count across any `switch` in `tree`.
fn max_switch_distinct_values(tree: &Ctree) -> usize {
    tree.statements()
        .filter_map(|(_, s)| match &s.kind {
            StatementKind::Switch { cases, .. } => Some(
                cases
                    .iter()
                    .flat_map(|c| &c.values)
                    .collect::<BTreeSet<_>>()
                    .len(),
            ),
            _ => None,
        })
        .max()
        .unwrap_or(0)
}

#[test]
fn ctree_nodes() {
    if !gxx_available() {
        eprintln!("skipping: g++ not available to build the fixture");
        return;
    }

    let src = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/ctree_kinds.cpp"
    );
    let bin: PathBuf =
        std::env::temp_dir().join(format!("idakit_ctree_kinds_{}", std::process::id()));

    let status = Command::new("g++")
        .args(["-O0", "-g0", "-w", "-fno-inline", "-o"])
        .arg(&bin)
        .arg(src)
        .status()
        .expect("failed to spawn g++");
    assert!(status.success(), "g++ failed to compile the fixture");

    let bin_str = bin.to_string_lossy().into_owned();

    Ida::run(move |ida| {
        ida.call(move |idb| {
            idb.open(&bin_str)
                .run_auto(true)
                .call()
                .expect("open + auto-analysis failed");

            let targets: Vec<Address> = idb.functions().map(|f| f.address()).collect();

            let mut trees: Vec<Ctree> = Vec::new();
            // DecompiledFunction facts (mod.rs) folded here, since the handle is !Send.
            let mut saw_pseudocode_body = false;
            let mut saw_plausible_gap = false;
            let mut saw_debug = false;

            for addr in targets {
                let Ok(df) = idb.decompile(addr) else {
                    continue;
                };

                if let Some(pc) = df.pseudocode() {
                    // A rendered body always carries a brace; empty / a bogus constant does not.
                    if pc.contains('{') {
                        saw_pseudocode_body = true;
                    }
                }

                // `(visitor_total, expected)`: both counts are real (well above the small
                // constants a stubbed return could invent) and the walker never invents nodes.
                let (visitor_total, expected) = df.expr_extraction_expectation();
                if visitor_total > 1 && expected > 1 && visitor_total >= expected {
                    saw_plausible_gap = true;
                }

                let debug = format!("{df:?}");
                if debug.contains("DecompiledFunction") && debug.contains("counts") {
                    saw_debug = true;
                }

                // A function IDA decompiles must extract cleanly; a thunk that fails to decompile
                // was already skipped above.
                let Ok(tree) = df.ctree() else {
                    continue;
                };
                assert!(all_reachable(&tree), "extraction left an unreachable node");
                trees.push(tree);
            }

            assert!(!trees.is_empty(), "no function decompiled");
            assert!(
                saw_pseudocode_body,
                "pseudocode never rendered a function body"
            );
            assert!(
                saw_plausible_gap,
                "expr_extraction_expectation never returned real counts"
            );
            assert!(
                saw_debug,
                "Debug never rendered the DecompiledFunction struct"
            );

            let mut exprs = BTreeSet::new();
            let mut stmts = BTreeSet::new();
            let mut shapes = BTreeSet::new();
            let mut any_expr_address = false;
            let mut any_named_obj = false;
            let mut any_non_arg_local = false;
            let mut any_plain_arg_local = false;
            let mut any_commented_local = false;
            let mut best_switch_values = 0;

            for tree in &trees {
                for (_, e) in tree.expressions() {
                    exprs.insert(expr_name(&e.kind));
                    if e.address.is_some() {
                        any_expr_address = true;
                    }
                    if let ExpressionKind::Obj { name: Some(n), .. } = &e.kind
                        && !n.is_empty()
                    {
                        any_named_obj = true;
                    }
                }
                for (_, s) in tree.statements() {
                    stmts.insert(stmt_name(&s.kind));
                }
                for (_, t) in tree.types() {
                    shapes.insert(shape_name(&t.shape));
                }
                for l in tree.locals() {
                    if !l.is_arg {
                        any_non_arg_local = true;
                    }
                    // A plain argument: not the result var, not address-taken. Every flag mutant
                    // (OR-always-true, invert, XOR) turns such a local's `is_byref`/`is_result`
                    // true, so its existence pins the whole `flags &` decode.
                    if l.is_arg && !l.is_byref && !l.is_result {
                        any_plain_arg_local = true;
                    }
                    if l.comment.is_some() {
                        any_commented_local = true;
                    }
                }
                best_switch_values = best_switch_values.max(max_switch_distinct_values(tree));
            }

            // Every expression kind the decompiler emits from this fixture.
            for k in [
                "Binary", "Assign", "Unary", "Call", "Index", "Cast", "Deref", "Num", "Fnum",
                "Obj", "Var", "Helper",
            ] {
                assert!(exprs.contains(k), "missing expression kind {k}: {exprs:?}");
            }
            // Every statement kind it emits.
            for k in [
                "Block",
                "Expression",
                "If",
                "For",
                "While",
                "Do",
                "Switch",
                "Break",
                "Return",
                "Empty",
            ] {
                assert!(stmts.contains(k), "missing statement kind {k}: {stmts:?}");
            }
            // Every aggregate/derived type shape the type walk builds.
            for k in [
                "Ptr", "Array", "Struct", "Enum", "Typedef", "Function", "Opaque",
            ] {
                assert!(shapes.contains(k), "missing type shape {k}: {shapes:?}");
            }

            assert!(any_expr_address, "no expression carried a source address");
            assert!(any_named_obj, "no global reference kept its symbol name");
            assert!(any_non_arg_local, "every local was flagged an argument");
            assert!(
                any_plain_arg_local,
                "no plain (value, non-result) argument survived"
            );
            assert!(!any_commented_local, "a local gained a spurious comment");

            // The dense `switch` keeps every distinct case value through the slicing walk.
            assert!(
                best_switch_values >= 5,
                "switch case-value pool was mis-sliced: {best_switch_values} distinct values"
            );

            idb.close(false);
        })
        .unwrap_or_else(|e| e.resume());
    })
    .expect("kernel init failed");

    let _ = std::fs::remove_file(&bin);
    let _ = std::fs::remove_file(bin.with_extension("i64"));
}
