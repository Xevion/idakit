//! Reusable, read-only invariant checks over an already-open [`Idb`]. Each returns a one-line
//! summary and panics (via `assert!`) on a violation, so it works as a `#[test]` body and as a
//! `libtest-mimic` trial alike. The registry [`CHECKS`] is the corpus matrix's check axis.

use idakit::{CodeReference, Error, Idb, ReferenceKind, TypeKind};

/// One named invariant over an open database.
pub type Check = fn(&Idb) -> String;

/// The check axis of the corpus matrix. Add a row here and every corpus database runs it.
pub const CHECKS: &[(&str, Check)] = &[
    ("structure", structure),
    ("symbols", symbols),
    ("strings", strings),
    ("disasm", disasm),
    ("cfg", cfg),
    ("decompile", decompile),
    ("types", types),
];

/// The database has functions and segments, the first function is named, and its entry bytes
/// are readable -- the floor every real program clears.
pub fn structure(idb: &Idb) -> String {
    let funcs = idb.functions().count();
    let segs = idb.segments().count();
    assert!(funcs > 0, "no functions");
    assert!(segs > 0, "no segments");
    let first = idb.functions().next().expect("a function");
    let name = first.name();
    assert!(!name.is_empty(), "first function name is empty");
    let bytes = idb.bytes(first.address(), 16);
    assert!(!bytes.is_empty(), "entry bytes unreadable");
    format!("{funcs} funcs, {segs} segs")
}

/// Every export resolves to an address or a forwarder; every import carries a name or an
/// ordinal; a real program has at least one of the two.
pub fn symbols(idb: &Idb) -> String {
    let mut exports = 0usize;
    for export in idb.exports().take(20000) {
        exports += 1;
        assert!(
            export.address().is_some() || export.forwarder().is_some(),
            "export #{} resolves to neither address nor forwarder",
            export.index()
        );
    }
    let mut imports = 0usize;
    for import in idb.imports().take(20000) {
        imports += 1;
        assert!(
            import.name().is_some() || import.ordinal().is_some(),
            "import at {:#x} has neither name nor ordinal",
            import.address()
        );
    }
    assert!(exports > 0 || imports > 0, "neither exports nor imports");
    format!("{exports} exports, {imports} imports")
}

/// Every located string has a sane character width, and when the scan finds any, at least some
/// decode to text.
pub fn strings(idb: &Idb) -> String {
    let mut total = 0usize;
    let mut decoded = 0usize;
    for s in idb.strings().take(5000) {
        total += 1;
        assert!(
            matches!(s.char_width(), 1 | 2 | 4),
            "string at {:#x} has impossible char width {}",
            s.address(),
            s.char_width()
        );
        if s.text().is_some() {
            decoded += 1;
        }
    }
    if total > 0 {
        assert!(decoded > 0, "{total} strings but none decoded");
    }
    format!("{total} scanned, {decoded} decoded")
}

/// A bounded straight-line decode holds structural invariants, and at least one direct branch
/// target is mirrored in IDA's reference graph.
pub fn disasm(idb: &Idb) -> String {
    const BUDGET: usize = 4000;
    let mut total = 0usize;
    let mut with_ops = 0usize;
    let mut checked_target = false;

    'outer: for function in idb.functions() {
        let mut address = function.address();
        for _ in 0..256 {
            let Ok(instruction) = idb.decode(address) else {
                break;
            };
            assert!(instruction.len > 0, "zero-length insn at {address:#x}");
            assert!(
                instruction.address == address,
                "insn address disagrees at {address:#x}"
            );
            assert!(
                !instruction.mnemonic.is_empty(),
                "empty mnemonic at {address:#x}"
            );
            for op in &instruction.ops {
                assert!(
                    op.idx < 8,
                    "operand index {} out of range at {address:#x}",
                    op.idx
                );
            }
            if !instruction.ops.is_empty() {
                with_ops += 1;
            }
            if !checked_target
                && !instruction.flow.is_indirect
                && (instruction.flow.is_call || instruction.flow.is_jump)
                && let Some(target) = instruction.flow.target
            {
                checked_target = idb.references_from(address).any(|x| {
                    x.to == target
                        && matches!(
                            x.kind,
                            ReferenceKind::Code(
                                CodeReference::CallNear
                                    | CodeReference::CallFar
                                    | CodeReference::JumpNear
                                    | CodeReference::JumpFar
                            )
                        )
                });
            }
            total += 1;
            address = address + u64::from(instruction.len);
            if total >= BUDGET {
                break 'outer;
            }
        }
    }
    assert!(total > 0, "decoded no instructions");
    assert!(with_ops > 0, "no instruction had operands");
    assert!(
        checked_target,
        "no direct branch target matched the reference graph"
    );
    format!("{total} insns, {with_ops} with operands")
}

/// The first multi-block function builds a graph whose edges are in range and mirror as
/// predecessors, and whose entry resolves back to block 0.
pub fn cfg(idb: &Idb) -> String {
    let Some(cfg) = idb
        .functions()
        .take(4000)
        .find_map(|f| f.cfg().ok().filter(|c| c.len() >= 2))
    else {
        return "no multi-block function in prefix".to_string();
    };
    for (id, b) in cfg.blocks() {
        assert!(b.end() > b.start(), "empty block range");
        for &s in b.successors() {
            assert!(s.index() < cfg.len(), "successor out of range");
            assert!(
                cfg.block(s).predecessors().contains(&id),
                "edge not mirrored in predecessors"
            );
        }
    }
    let entry = cfg.entry();
    assert!(entry.index() == 0, "entry is not block 0");
    let start = cfg.block(entry).start();
    assert!(
        cfg.block_at(start) == Some(entry),
        "entry start does not resolve to entry"
    );
    format!("{} blocks", cfg.len())
}

/// Decompiling the first functions succeeds where Hex-Rays can, and the extracted ctree's node
/// counts agree with the independent visitor counts.
pub fn decompile(idb: &Idb) -> String {
    use idakit::ctree::{NodeRef, StatementKind};
    let mut decompiled = 0usize;
    let mut deep_checked = false;
    for f in idb.functions().take(50) {
        let Ok(cf) = f.decompile() else { continue };
        decompiled += 1;
        let Ok(tree) = cf.ctree() else { continue };

        // Extraction fidelity, per function: the materialized expression count must equal what a
        // faithful walk should emit -- the SDK visitor's total minus the cot_empty placeholders it
        // counts in optional operand slots (a `for(;;)` init/cond/step, a bare `return;`) that the
        // walker elides to `None`. A shortfall/surplus is a real dropped or invented node.
        let (visitor_total, expected) = cf.expr_extraction_expectation();
        let actual = tree.expressions().count() as i32;
        assert!(
            actual == expected,
            "ctree extraction emitted {actual} expression nodes; a faithful walk should emit \
             {expected} (SDK visits {visitor_total}, less {} elided empty operand slots) in {:?}",
            visitor_total - expected,
            f.name()
        );

        if deep_checked {
            continue;
        }
        let root = tree.root();
        assert!(
            matches!(tree.statement(root).kind, StatementKind::Block(_)),
            "ctree root should be a block"
        );
        // Statements are never elided (cit_empty materializes as StatementKind::Empty), so their
        // count matches the SDK visitor exactly -- unlike expressions, checked above.
        assert!(
            tree.statements().count() == cf.counts().insns as usize,
            "extracted statement count disagrees with the visitor"
        );
        let reachable = tree.descendants(NodeRef::Statement(root)).count();
        assert!(
            reachable == tree.expressions().count() + tree.statements().count(),
            "not every ctree node is reachable from the root"
        );
        deep_checked = true;
    }
    format!("{decompiled} decompiled")
}

/// A function with a stored prototype walks into a `Function`-rooted [`TypeImage`] whose child
/// handles resolve, and a named aggregate it references round-trips through `type_named` to a
/// resolvable root. Best-effort: a stripped database may carry no prototypes, and a referenced
/// name need not be a local type.
pub fn types(idb: &Idb) -> String {
    let mut typed = 0usize;
    let mut checked_proto = false;
    let mut named = 0usize;

    for f in idb.functions().take(2000) {
        let Ok(Some(image)) = f.prototype_type() else {
            continue;
        };
        typed += 1;

        if !checked_proto {
            let TypeKind::Function { ret, params, .. } = image.kind() else {
                panic!("prototype root at {:#x} is not a Function", f.address());
            };
            let _ = image.get(*ret);
            for p in params {
                let _ = image.get(*p);
            }
            checked_proto = true;
        }

        // Round-trip the first named aggregate this prototype references back through type_named.
        // A referenced name need not be a local type, so TypeNotFound is fine; only a malformed
        // walk (Extract) is a real failure.
        if named == 0
            && let Some(name) = image.types().iter().find_map(|(_, t)| t.kind.tag_name())
        {
            match idb.type_named(name) {
                Ok(resolved) => {
                    let _ = resolved.get(resolved.root());
                    named += 1;
                }
                Err(Error::TypeNotFound { .. }) => {}
                Err(e) => panic!("type_named({name:?}) failed unexpectedly: {e}"),
            }
        }

        if checked_proto && named > 0 {
            break;
        }
    }

    if typed == 0 {
        return "no typed prototypes in prefix".to_string();
    }
    format!("{typed} typed prototypes, {named} named round-trips")
}

// A non-function address is rejected -- kept out of the corpus battery (it needs a specific
// address) but exercised by the dedicated cfg test.
#[allow(dead_code)]
pub fn non_function_rejected(idb: &Idb) {
    if let Some(start) = idb
        .segments()
        .find(|s| !s.is_executable())
        .and_then(|s| s.start())
    {
        assert!(matches!(idb.cfg(start), Err(Error::NoFunction { .. })));
    }
}
