//! Node-by-node ctree extraction check against real decompiler output.
//!
//! Compiles `tests/fixtures/ctree_kinds.cpp` with g++, lets IDA auto-analyze it headlessly, then
//! decompiles every function once and checks the extracted [`Ctree`] against the decompiler's own
//! pseudocode for the same function: a float literal, loop, `switch` or `case` label the
//! pseudocode prints must exist in the extraction, whatever the host compiler lowered the source
//! to. Alongside that, every allocated node is reachable from the root (so a sink callback that
//! drops or mis-threads a handle is caught), and the local-variable flags and node addresses
//! survive. It also pins the [`DecompiledFunction`] surface: `pseudocode`,
//! `expr_extraction_expectation`, and the `Debug` impl.
//!
//! A divergence reports every problem at once, with the functions that failed to decompile and
//! the host toolchain, since the fixture's shape follows the machine that built it.
//!
//! The kinds Hex-Rays does not emit from optimization-stripped, debug-info-free code (member
//! accesses on untyped pointers, `goto`/`continue`/inline-asm/try-throw, string-literal and
//! ternary nodes) are driven directly against the sink in the `extract` unit tests instead; this
//! test covers everything the real decompiler reaches. A normal `#[test]`, skipped when `g++` is
//! unavailable to build the fixture.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use assert2::assert;
use idakit::decompiler::ctree::{Ctree, ExpressionKind, NodeRef, StatementKind};
use idakit::prelude::*;
use idakit::types::TypeShape;
use rstest::rstest;

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

/// One decompiled fixture function: its name, the Hex-Rays pseudocode, and the extracted tree.
///
/// The pseudocode is the independent oracle: Hex-Rays prints its own tree, so whatever kind it
/// shows must also be in the extraction, whatever the host compiler lowered the source to.
struct Observed {
    name: String,
    text: String,
    tree: Ctree,
}

/// Whether `text` holds a floating-point literal like `2.5` outside any string literal.
fn has_float_literal(text: &str) -> bool {
    let b = text.as_bytes();
    let mut in_string = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if in_string => i += 1,
            b'"' => in_string = !in_string,
            c if !in_string && c.is_ascii_digit() => {
                let starts_token =
                    i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
                let mut j = i;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                if starts_token
                    && b.get(j) == Some(&b'.')
                    && b.get(j + 1).is_some_and(u8::is_ascii_digit)
                {
                    return true;
                }
                i = j;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

fn any_line(text: &str, f: impl Fn(&str) -> bool) -> bool {
    text.lines().map(str::trim).any(f)
}

/// A node kind paired with a test for the pseudocode that proves it was printed.
type Oracle = (&'static str, fn(&str) -> bool);

/// Expression kinds whose presence the pseudocode proves, independent of how the host compiler
/// lowered the source.
const EXPR_ORACLES: &[Oracle] = &[("Fnum", has_float_literal)];

/// Statement kinds the pseudocode proves by their keyword, keyed so a `do { } while ( c );` tail
/// is not mistaken for a `while` statement.
const STMT_ORACLES: &[Oracle] = &[
    ("If", |t| t.contains("if (")),
    ("For", |t| any_line(t, |l| l.starts_with("for ("))),
    ("While", |t| {
        any_line(t, |l| l.starts_with("while (") && !l.ends_with(';'))
    }),
    ("Do", |t| any_line(t, |l| l == "do")),
    ("Switch", |t| t.contains("switch (")),
    ("Break", |t| any_line(t, |l| l == "break;")),
];

/// The case-value count of every `switch` in `tree`, one distinct-value tally per switch.
fn switch_distinct_values(tree: &Ctree) -> impl Iterator<Item = usize> + '_ {
    tree.statements().filter_map(|(_, s)| match &s.kind {
        StatementKind::Switch { cases, .. } => Some(
            cases
                .iter()
                .flat_map(|c| &c.values)
                .collect::<BTreeSet<_>>()
                .len(),
        ),
        _ => None,
    })
}

/// Oracle kinds no function's pseudocode showed; such an oracle checked nothing this run, so the
/// fixture stopped exercising that kind on this toolchain.
fn silent_oracles(observed: &[Observed]) -> Vec<&'static str> {
    EXPR_ORACLES
        .iter()
        .chain(STMT_ORACLES)
        .filter(|(_, shown)| !observed.iter().any(|o| shown(&o.text)))
        .map(|(kind, _)| *kind)
        .collect()
}

/// Every divergence between the extraction and what Hex-Rays printed for the same functions.
///
/// Collects instead of stopping at the first miss, so one failing run reports the whole picture.
fn extraction_problems(observed: &[Observed]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut exprs = BTreeSet::new();
    let mut stmts = BTreeSet::new();
    let mut shapes = BTreeSet::new();
    let mut any_expr_address = false;
    let mut any_named_obj = false;
    let mut any_non_arg_local = false;
    let mut any_plain_arg_local = false;
    let mut any_commented_local = false;

    for Observed { name, text, tree } in observed {
        let mut local_exprs = BTreeSet::new();
        let mut local_stmts = BTreeSet::new();
        for (_, e) in tree.expressions() {
            local_exprs.insert(expr_name(&e.kind));
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
            local_stmts.insert(stmt_name(&s.kind));
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

        for (kind, shown) in EXPR_ORACLES {
            if shown(text) && !local_exprs.contains(kind) {
                problems.push(format!(
                    "{name}: pseudocode shows {kind}, extraction has none"
                ));
            }
        }
        for (kind, shown) in STMT_ORACLES {
            if shown(text) && !local_stmts.contains(kind) {
                problems.push(format!(
                    "{name}: pseudocode shows {kind}, extraction has none"
                ));
            }
        }

        // The pool slicing keeps every case label: Hex-Rays prints one `case` line per value.
        let printed = text
            .lines()
            .filter(|l| l.trim().starts_with("case "))
            .count();
        let extracted: usize = switch_distinct_values(tree).sum();
        if printed != extracted {
            problems.push(format!(
                "{name}: pseudocode prints {printed} case labels, extraction holds {extracted}"
            ));
        }

        exprs.extend(local_exprs);
        stmts.extend(local_stmts);
    }

    // The kinds not covered by an oracle above: the fixture's source shapes them, so a toolchain
    // that stops producing one is reported here with the full list rather than aborting the run.
    for k in [
        "Binary", "Assign", "Unary", "Call", "Index", "Cast", "Deref", "Num", "Obj", "Var",
        "Helper",
    ] {
        if !exprs.contains(k) {
            problems.push(format!("missing expression kind {k}"));
        }
    }
    for k in ["Block", "Expression", "Return", "Empty"] {
        if !stmts.contains(k) {
            problems.push(format!("missing statement kind {k}"));
        }
    }
    // Every aggregate/derived type shape the type walk builds.
    for k in [
        "Ptr", "Array", "Struct", "Enum", "Typedef", "Function", "Opaque",
    ] {
        if !shapes.contains(k) {
            problems.push(format!("missing type shape {k}"));
        }
    }

    for (ok, what) in [
        (any_expr_address, "no expression carried a source address"),
        (any_named_obj, "no global reference kept its symbol name"),
        (any_non_arg_local, "every local was flagged an argument"),
        (
            any_plain_arg_local,
            "no plain (value, non-result) argument survived",
        ),
        (!any_commented_local, "a local gained a spurious comment"),
    ] {
        if !ok {
            problems.push(what.to_owned());
        }
    }

    eprintln!("observed expression kinds: {exprs:?}");
    eprintln!("observed statement kinds: {stmts:?}");
    eprintln!("observed type shapes: {shapes:?}");
    eprintln!("silent oracles: {:?}", silent_oracles(observed));
    problems
}

#[rstest]
#[case::literal("  v11 = expressions(argc, argc + 1, 2.5);", true)]
#[case::literal_after_paren("f(0.125)", true)]
#[case::format_string(r#"printf("val=%f 1.5\n", v);"#, false)]
#[case::member_of_numbered_local("v1.x = 1;", false)]
#[case::integer_only("return v10 + 12;", false)]
fn float_literal_oracle(#[case] text: &str, #[case] expected: bool) {
    assert!(has_float_literal(text) == expected);
}

#[rstest]
#[case::do_while_tail("do\n{\n}\nwhile ( v4 );", "While", false)]
#[case::while_stmt("while ( v4 )\n{\n}", "While", true)]
#[case::do_stmt("do\n{\n}\nwhile ( v4 );", "Do", true)]
#[case::for_stmt("for ( i = 0; i < 4; ++i )", "For", true)]
fn statement_oracles(#[case] text: &str, #[case] kind: &str, #[case] expected: bool) {
    let (_, shown) = STMT_ORACLES
        .iter()
        .find(|(k, _)| *k == kind)
        .expect("oracle exists");
    assert!(shown(text) == expected);
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
    // g++ appends `.exe` itself on Windows, so an extensionless `-o` leaves nothing to open.
    let name = format!(
        "idakit_ctree_kinds_{}{}",
        std::process::id(),
        std::env::consts::EXE_SUFFIX
    );
    let bin: PathBuf = std::env::temp_dir().join(&name);

    let mut cmd = Command::new("g++");
    cmd.args(["-O0", "-g0", "-w", "-fno-inline"]);
    // Apple clang's AArch64 backend lowers even this dense a switch to compare-chains, so pin
    // the fixture to x86_64 there to match every other platform's decompiler behavior.
    if cfg!(target_os = "macos") {
        cmd.args(["-arch", "x86_64"]);
    } else if cfg!(target_arch = "x86_64") {
        // Some hosts default to x86-64-v3, whose VEX encodings the decompiler leaves as inline asm.
        cmd.arg("-march=x86-64");
    }
    let status = cmd
        .arg("-o")
        .arg(&bin)
        .arg(src)
        .status()
        .expect("failed to spawn g++");
    assert!(status.success(), "g++ failed to compile the fixture");

    let bin_str = bin.to_string_lossy().into_owned();

    // Printed first so a failing run shows what the fixture was built by, since its decompiled
    // shape follows the host toolchain.
    eprintln!("{}", common::host_banner("g++"));

    Ida::run(move |ida| {
        ida.call(move |idb| {
            idb.open(&bin_str)
                .run_auto(true)
                .call()
                .expect("open + auto-analysis failed");

            let targets: Vec<(Address, String)> = idb
                .functions()
                .map(|f| (f.address(), f.name().as_str().to_owned()))
                .collect();

            let mut observed: Vec<Observed> = Vec::new();
            // Functions that did not decompile or extract, with why; a silent skip once hid the
            // fixture's `main` going missing behind an unrelated "missing kind" assertion.
            let mut skipped: Vec<String> = Vec::new();
            // DecompiledFunction facts (mod.rs) folded here, since the handle is !Send.
            let mut saw_pseudocode_body = false;
            let mut saw_plausible_gap = false;
            let mut saw_debug = false;

            for (addr, name) in targets {
                let df = match idb.decompile(addr) {
                    Ok(df) => df,
                    Err(e) => {
                        skipped.push(format!("{name} @ {addr:#x}: decompile failed: {e}"));
                        continue;
                    }
                };

                let text = df.pseudocode().unwrap_or_default();
                // A rendered body always carries a brace; empty / a bogus constant does not.
                if text.contains('{') {
                    saw_pseudocode_body = true;
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
                let tree = match df.ctree() {
                    Ok(tree) => tree,
                    Err(e) => {
                        skipped.push(format!("{name} @ {addr:#x}: extraction failed: {e}"));
                        continue;
                    }
                };
                assert!(
                    all_reachable(&tree),
                    "extraction left an unreachable node in {name}"
                );
                observed.push(Observed { name, text, tree });
            }

            assert!(!observed.is_empty(), "no function decompiled: {skipped:#?}");
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

            eprintln!(
                "decompiled: {:?}, skipped: {skipped:?}",
                observed.iter().map(|o| o.name.as_str()).collect::<Vec<_>>()
            );
            let mut problems = extraction_problems(&observed);
            // The fixture's entry point is where its float literal, calls and locals live; losing
            // it is the failure to explain, not a missing-kind symptom downstream of it.
            if !observed
                .iter()
                .any(|o| o.name.trim_start_matches('_') == "main")
            {
                problems.insert(
                    0,
                    "the fixture's `main` was not decompiled and extracted".into(),
                );
            }
            let silent = silent_oracles(&observed);
            if !silent.is_empty()
                && let Some(main) = observed
                    .iter()
                    .find(|o| o.name.trim_start_matches('_') == "main")
            {
                // `main` holds the fixture's float literal; its text says what replaced it.
                eprintln!("silent {silent:?}, main pseudocode:\n{}", main.text);
            }
            if !problems.is_empty() || !silent.is_empty() {
                let pseudocode = observed
                    .iter()
                    .map(|o| format!("// {}\n{}", o.name, o.text))
                    .collect::<Vec<_>>()
                    .join("\n\n");
                common::save_artifact("ctree_kinds.pseudocode.txt", pseudocode);
                common::save_artifact("ctree_kinds.problems.txt", problems.join("\n"));
                if let Ok(binary) = std::fs::read(&bin_str) {
                    common::save_artifact("ctree_kinds.bin", binary);
                }
            }
            assert!(
                problems.is_empty(),
                "{}\nskipped functions: {skipped:#?}\ndecompiled: {:?}",
                problems.join("\n"),
                observed.iter().map(|o| o.name.as_str()).collect::<Vec<_>>(),
            );

            idb.close(false);
        })
        .unwrap_or_else(|e| e.resume());
    })
    .expect("kernel init failed");

    // IDA appends `.i64` to the whole name, so `with_extension` would miss it next to a `.exe`.
    let _ = std::fs::remove_file(&bin);
    let _ = std::fs::remove_file(bin.with_file_name(format!("{name}.i64")));
}
