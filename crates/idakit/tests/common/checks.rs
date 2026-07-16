//! Reusable, read-only invariant checks over an already-open [`Database`]. Each returns a one-line
//! summary and panics (via `assert!`) on a violation, so it works as a `#[test]` body and as a
//! `libtest-mimic` trial alike. The registry [`CHECKS`] is the corpus matrix's check axis.

use idakit::prelude::*;

/// One named invariant over an open database.
pub type Check = fn(&Database) -> String;

/// The check axis of the corpus matrix. Add a row here and every corpus database runs it.
pub const CHECKS: &[(&str, Check)] = &[
    ("structure", structure),
    ("symbols", symbols),
    ("strings", strings),
    ("disasm", disasm),
    ("decode", decode),
    ("cfg", cfg),
    ("decompile", decompile),
    ("types", types),
    ("argloc", argloc),
    ("segment_attrs", segment_attrs),
    ("func_attrs", func_attrs),
];

// A regression that empties the check axis would otherwise still pass every corpus trial
// vacuously (zero checks run, zero failures); catch it at compile time instead.
const _: () = assert!(!CHECKS.is_empty());

/// The database has functions and segments, the first function is named, and its entry bytes
/// are readable, the floor every real program clears.
pub fn structure(idb: &Database) -> String {
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

/// Every export resolves to an address or a forwarder, and a resolved address falls inside a
/// real segment; every import carries a name or an ordinal, and its address falls inside a real
/// segment too. A real program has at least one export or import.
pub fn symbols(idb: &Database) -> String {
    let mut exports = 0usize;
    for export in idb.exports().take(20000) {
        exports += 1;
        assert!(
            export.address().is_some() || export.forwarder().is_some(),
            "export #{} resolves to neither address nor forwarder",
            export.index()
        );
        if let Some(address) = export.address() {
            assert!(
                idb.segment_at(address).is_some(),
                "export #{} at {address:#x} is not inside any segment",
                export.index()
            );
        }
    }
    let mut imports = 0usize;
    for import in idb.imports().take(20000) {
        imports += 1;
        assert!(
            import.name().is_some() || import.ordinal().is_some(),
            "import at {:#x} has neither name nor ordinal",
            import.address()
        );
        assert!(
            idb.segment_at(import.address()).is_some(),
            "import at {:#x} is not inside any segment",
            import.address()
        );
    }
    assert!(exports > 0 || imports > 0, "neither exports nor imports");
    format!("{exports} exports, {imports} imports")
}

/// Every located string has a sane character width, and when the scan finds any, at least some
/// decode to text.
pub fn strings(idb: &Database) -> String {
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
pub fn disasm(idb: &Database) -> String {
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
                checked_target = idb.xrefs_from(address).any(|x| {
                    x.to == target
                        && matches!(
                            x.kind,
                            XrefKind::Code(
                                CodeXref::CallNear
                                    | CodeXref::CallFar
                                    | CodeXref::JumpNear
                                    | CodeXref::JumpFar
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
pub fn cfg(idb: &Database) -> String {
    let Some(cfg) = idb
        .functions()
        .take(4000)
        .find_map(|f| f.flowchart().ok().filter(|c| c.len() >= 2))
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
///
/// Deliberately does not assert `decompiled > 0`: several real corpus fixtures (WASM, Dalvik,
/// .NET CLI, Java bytecode loaders) have no Hex-Rays module at all, and per the manifest's own
/// comment beside them they are not manifest-skipped for this check on purpose, since they
/// exist specifically to exercise the loader and processor module with zero decompiler
/// coverage. A hard failure here would need a manifest-level "no decompiler" signal distinct
/// from `skip_checks`, which does not exist today.
pub fn decompile(idb: &Database) -> String {
    use idakit::decompiler::ctree::{NodeRef, StatementKind};
    let mut decompiled = 0usize;
    let mut deep_checked = false;
    for f in idb.functions().take(50) {
        let Ok(cf) = f.decompile() else { continue };
        decompiled += 1;
        let Ok(tree) = cf.ctree() else { continue };

        // Extraction fidelity, per function: the materialized expression count must equal what a
        // faithful walk should emit, the SDK visitor's total minus the cot_empty placeholders it
        // counts in optional operand slots (a `for(;;)` init/cond/step, a bare `return;`) that the
        // walker elides to `None`. A shortfall/surplus is a real dropped or invented node.
        let (visitor_total, expected) = cf.expr_extraction_expectation();
        let actual = tree.expressions().count() as i32;
        assert!(
            actual == expected,
            "ctree extraction emitted {actual} expression nodes; a faithful walk should emit \
             {expected} (SDK visits {visitor_total}, less {} elided empty operand slots) in {}",
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
        // count matches the SDK visitor exactly, unlike expressions, checked above.
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

/// A function with a stored prototype walks into a `Function`-rooted [`Type`] whose child
/// handles resolve, and a named aggregate it references round-trips through `type_named` to a
/// resolvable root. Best-effort: a stripped database may carry no prototypes, and a referenced
/// name need not be a local type.
pub fn types(idb: &Database) -> String {
    let mut typed = 0usize;
    let mut checked_proto = false;
    let mut named = 0usize;

    for f in idb.functions().take(2000) {
        let Ok(Some(image)) = f.prototype_type() else {
            continue;
        };
        typed += 1;

        // Database::type_at(f.address()) reads the same tinfo_t as prototype_type, just keyed by
        // address instead of routed through the Function view; the two must agree.
        match idb.type_at(f.address()) {
            Ok(Some(via_address)) => assert!(
                via_address.key() == image.key(),
                "type_at({:#x}) disagrees with prototype_type",
                f.address()
            ),
            Ok(None) => panic!(
                "type_at({:#x}) found nothing, but prototype_type resolved one",
                f.address()
            ),
            Err(e) => panic!("type_at({:#x}) failed unexpectedly: {e}", f.address()),
        }

        if !checked_proto {
            let TypeShape::Function { ret, params, .. } = image.shape() else {
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
            && let Some(name) = image.types().iter().find_map(|(_, t)| t.shape.tag_name())
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

/// Every decompiled local's [`LocalLocation`] is one the model structures, tallied by variant so
/// the corpus matrix surfaces the per-architecture argloc spread. `Custom` (`ALOC_CUSTOM`) is a
/// tripwire: it means a processor module produced an argloc idakit doesn't model, which we want
/// to see rather than silently absorb. Every scattered fragment must itself be a register
/// or stack slot, never nested, mirroring `argpart_t`. A fixture Hex-Rays cannot decompile at
/// all (see [`decompile`]) yields no locals and passes vacuously, by the same design.
pub fn argloc(idb: &Database) -> String {
    use idakit::decompiler::ctree::LocalLocation;

    // Register / RegisterPair / Stack / RegisterRelative / Static / Scattered / Custom / Unallocated
    let mut n = [0usize; 8];
    let index = |loc: &LocalLocation| match loc {
        LocalLocation::Register(_) => 0,
        LocalLocation::RegisterPair { .. } => 1,
        LocalLocation::Stack(_) => 2,
        LocalLocation::RegisterRelative { .. } => 3,
        LocalLocation::Static(_) => 4,
        LocalLocation::Scattered(_) => 5,
        LocalLocation::Custom => 6,
        LocalLocation::Unallocated => 7,
    };

    let mut decompiled = 0usize;
    let mut lvars = 0usize;
    for f in idb.functions().take(200) {
        let Ok(cf) = f.decompile() else { continue };
        let Ok(tree) = cf.ctree() else { continue };
        decompiled += 1;
        for lv in tree.lvars() {
            lvars += 1;
            n[index(&lv.location)] += 1;
            if let LocalLocation::Scattered(pieces) = &lv.location {
                for p in pieces {
                    assert!(
                        matches!(
                            p.location,
                            LocalLocation::Register(_) | LocalLocation::Stack(_)
                        ),
                        "scattered fragment is neither register nor stack: {:?}",
                        p.location
                    );
                }
            }
        }
    }

    if lvars == 0 {
        return format!("{decompiled} decompiled, no locals");
    }
    assert!(
        n[6] == 0,
        "{} local(s) mapped to Custom (ALOC_CUSTOM) -- an unmodeled argloc surfaced",
        n[6]
    );
    format!(
        "{decompiled} fns, {lvars} lvars | reg={} pair={} stack={} rrel={} static={} scatter={} none={}",
        n[0], n[1], n[2], n[3], n[4], n[5], n[7]
    )
}

/// Every segment's start resolves back to its own index through [`Database::segment_at`], no
/// segment is inverted or overlaps the one before it, and the newer scalar accessors (`kind`,
/// `align`, `comb`, `sel`, `color`, `comment`) resolve without panicking. A database with no
/// segments skips cleanly rather than failing.
///
/// `is_visible`/`is_debugger`/`is_loader`/`is_type_hidden`/`is_header` are deliberately not
/// checked against [`Segment::flags`] here: per `segment.hpp`, the SDK defines each predicate
/// as that exact bit test (`is_visible_segm() { return (flags & SFL_HIDDEN) == 0; }`), so
/// re-deriving the same bit from the same flags and comparing is a tautology that can never
/// fail regardless of whether the predicate is wired to the right bit.
pub fn segment_attrs(idb: &Database) -> String {
    let mut checked = 0usize;
    let mut typed = 0usize;
    let mut aligned = 0usize;
    let mut combined = 0usize;
    let mut prev_end: Option<Address> = None;

    for seg in idb.segments() {
        checked += 1;

        if let (Some(start), Some(end)) = (seg.start(), seg.end()) {
            assert!(
                end > start,
                "segment {} has inverted or empty range [{start:#x}, {end:#x})",
                seg.index()
            );
            assert!(
                prev_end.is_none_or(|prev| start >= prev),
                "segment {} starts at {start:#x}, before the previous segment's end {:#x}",
                seg.index(),
                prev_end.unwrap()
            );
            prev_end = Some(end);

            let found = idb.segment_at(start);
            assert!(
                found.is_some_and(|f| f.index() == seg.index()),
                "segment_at(segment {}'s start {start:#x}) resolved to {:?}, not itself",
                seg.index(),
                found.map(|f| f.index())
            );
        }

        if seg.kind().is_some() {
            typed += 1;
        }
        if seg.align().is_some() {
            aligned += 1;
        }
        if seg.comb().is_some() {
            combined += 1;
        }
        // Neither accessor has an independent oracle here; calling them without panicking is
        // the invariant.
        let _ = seg.sel();
        let _ = seg.color();
        let _ = seg.comment(false);
        let _ = seg.comment(true);
    }

    if checked == 0 {
        return "no segments".to_string();
    }
    format!("{checked} segs, {typed} typed, {aligned} aligned, {combined} combined")
}

/// A bounded sample of functions reports a bitness, and every accessor new to this pass resolves
/// without panicking. `total_size` (summed across chunks) never undershoots `size` (the entry
/// chunk alone), since the entry chunk is one of the chunks being summed.
pub fn func_attrs(idb: &Database) -> String {
    const SAMPLE: usize = 200;

    let total = idb.functions().count();
    let mut checked = 0usize;
    let mut with_bitness = 0usize;

    for f in idb.functions().take(SAMPLE) {
        checked += 1;
        assert!(
            f.bitness().is_some(),
            "function {:#x} reports no bitness",
            f.address().get()
        );
        with_bitness += 1;
        assert!(
            f.total_size() >= f.size(),
            "function {:#x} total_size {} is smaller than size {}",
            f.address().get(),
            f.total_size(),
            f.size()
        );
        let _ = f.does_return();
        let _ = f.comment(false);
        let _ = f.comment(true);
    }

    assert!(checked > 0, "no functions");

    if total > SAMPLE {
        format!("{checked}/{total} funcs sampled (capped), {with_bitness} with bitness")
    } else {
        format!("{checked} funcs, {with_bitness} with bitness")
    }
}

/// Strict decode over a bounded prefix of real code: every code head decodes with no silent
/// fallback, and every register operand's resolved name agrees with its [`RegisterClass`] in
/// both directions. Unlike [`disasm`], a decode *rejection* is a failure here, not a silent
/// stop. This is the axis that actually exercises operand classification and register naming
/// (`st`/`cr`/`dr`/`tr` and the SIMD widths) across the corpus. x86-only: our register model is
/// x86 `RegNo`-based, so a non-x86 fixture opts out of this check in the manifest.
pub fn decode(idb: &Database) -> String {
    const BUDGET: usize = 20000;
    let mut insns = 0usize;
    let mut regs = 0usize;

    let functions: Vec<_> = idb.functions().map(|f| f.address()).collect();
    'outer: for fea in functions {
        let function = idb.function(fea);
        let chunks: Vec<_> = function.chunks().collect();
        for chunk in chunks {
            let mut address = chunk.start;
            while address < chunk.end {
                if idb.is_code(address) {
                    match idb.decode(address) {
                        Ok(insn) => {
                            for register in insn.registers() {
                                register.assert_name_matches_class(address.get());
                                regs += 1;
                            }
                            insns += 1;
                            if insns >= BUDGET {
                                break 'outer;
                            }
                        }
                        Err(DecodeError::NotCode { .. }) => {}
                        Err(other) => panic!(
                            "strict decode rejected a real instruction at {address:#x}: {other}"
                        ),
                    }
                }
                match idb.next_head(address, chunk.end) {
                    Some(next) if next > address => address = next,
                    _ => break,
                }
            }
        }
    }
    assert!(insns > 0, "decoded no instructions");
    assert!(regs > 0, "no register operands checked");
    format!("{insns} insns, {regs} regs")
}

/// The register-consistency oracle for the decode checks. Cross-checks decode's structural
/// classification against the name IDA independently resolved, both directions.
pub trait RegisterCheck {
    /// Assert this register's name and class agree: a regularly-spelled class produces that
    /// spelling (a `St` register named `rsp` is a bug), and a name that reads as a special
    /// register carries that class (a `bnd0` classed `GeneralPurpose` is a bug). `address` labels
    /// failures.
    fn assert_name_matches_class(&self, address: u64);
}

impl RegisterCheck for Register {
    fn assert_name_matches_class(&self, address: u64) {
        let name = self.name.as_ref();
        if let Some(prefix) = self.class.name_prefix() {
            assert!(
                name.starts_with(prefix),
                "register {name:?} at {address:#x} is class {:?} but not named {prefix}*",
                self.class,
            );
        }
        if let Some(implied) = RegisterClass::from_name(name) {
            assert!(
                self.class == implied,
                "register {name:?} at {address:#x} classed {:?}, name implies {implied:?}",
                self.class,
            );
        }
    }
}

// A non-function address is rejected, kept out of the corpus battery (it needs a specific
// address) but exercised by the dedicated cfg test.
#[allow(dead_code)]
pub fn non_function_rejected(idb: &Database) {
    if let Some(start) = idb
        .segments()
        .find(|s| !s.is_executable())
        .and_then(|s| s.start())
    {
        assert!(matches!(
            idb.flowchart(start),
            Err(Error::NoFunction { .. })
        ));
    }
}
