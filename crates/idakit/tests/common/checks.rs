//! Reusable, read-only invariant checks over an already-open [`Database`]. Each returns a one-line
//! summary and panics (via `assert!`) on a violation, so it works as a `#[test]` body and as a
//! harness case alike. The registry [`CHECKS`] is the corpus fan-out's check axis.

use std::fmt::Write as _;

use idakit::decompiler::ctree::LocalFlags;
use idakit::prelude::*;
use idakit::types::{FunctionTypeFlags, StorageLocation};

/// One named invariant over an open database.
pub type Check = fn(&Database) -> String;

/// Whether a check may share its fixture's open database with its neighbours.
///
/// Declared per check rather than assumed: decompilation writes (noreturn propagation deletes
/// code and its cross-references, and stack-pointer analysis rewrites frames), so a check that
/// decompiles must not be handed to a later reader.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Shares {
    /// Pure read; shares the database already open on the worker.
    Yes,
    /// Dirties the database; gets one reopened for it.
    No,
}

/// The check axis of the corpus matrix. Add a row here and every corpus database runs it.
pub const CHECKS: &[(&str, Check, Shares)] = &[
    ("structure", structure, Shares::Yes),
    ("symbols", symbols, Shares::Yes),
    ("strings", strings, Shares::Yes),
    ("disasm", disasm, Shares::Yes),
    ("decode", decode, Shares::Yes),
    ("cfg", cfg, Shares::Yes),
    ("decompile", decompile, Shares::No),
    ("types", types, Shares::Yes),
    ("argloc", argloc, Shares::No),
    ("prototypes", prototypes, Shares::Yes),
    ("segment_attrs", segment_attrs, Shares::Yes),
    ("func_attrs", func_attrs, Shares::Yes),
    ("type_attrs", type_attrs, Shares::Yes),
    ("frame_attrs", frame_attrs, Shares::Yes),
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

/// A bounded straight-line decode holds structural invariants, and every direct branch target IDA
/// resolved is mirrored in its reference graph.
///
/// The per-function cap is deliberately far below the budget: a depth-first walk of 256 spends the
/// whole budget on ~16 functions, and in a stripped shared object the lowest addresses are PLT
/// thunks whose jumps are all indirect, so the sample can hold no direct branch at all.
pub fn disasm(idb: &Database) -> String {
    const BUDGET: usize = 4000;
    const PER_FUNCTION: usize = 32;
    let mut total = 0usize;
    let mut with_ops = 0usize;
    let mut direct = 0usize;
    let mut matched = 0usize;
    let mut unresolved = 0usize;
    let mut unmatched: Vec<Unmatched> = Vec::new();

    'outer: for function in idb.functions() {
        let mut address = function.address();
        for _ in 0..PER_FUNCTION {
            // A cross-reference only exists at a real code head, so decoding off the tail of a
            // function into data and then faulting the missing xref would prove nothing.
            if !idb.is_code(address) {
                break;
            }
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
                    op.slot < 8,
                    "operand slot {} out of range at {address:#x}",
                    op.slot
                );
            }
            if !instruction.ops.is_empty() {
                with_ops += 1;
            }
            if !instruction.flow.is_indirect
                && (instruction.flow.is_call || instruction.flow.is_jump)
                && let Some(target) = instruction.flow.target
            {
                // A branch IDA never resolved carries no cref at all (a `call $+5` PC idiom, a jump
                // into unmapped memory), so it is unverifiable rather than wrong.
                if branch_targets(idb, address).next().is_none() {
                    unresolved += 1;
                } else if branch_targets(idb, address).any(|to| to == target) {
                    direct += 1;
                    matched += 1;
                } else {
                    direct += 1;
                    if unmatched.len() < UNMATCHED_SAMPLE {
                        unmatched.push(Unmatched {
                            address,
                            target,
                            mnemonic: instruction.mnemonic.to_string(),
                            len: instruction.len,
                        });
                    }
                }
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
    // Split from the match assert below: "the sample held no direct branch" and "it held some and
    // none agreed with the graph" are different defects, and one message cannot name both.
    assert!(
        direct > 0,
        "{total} instructions decoded, none a direct call or jump"
    );
    assert!(
        matched == direct,
        "{}",
        unmatched_report(idb, direct, matched, &unmatched)
    );
    format!(
        "{total} insns, {with_ops} with operands, {matched}/{direct} branches matched \
         ({unresolved} unresolved)"
    )
}

/// The addresses IDA's reference graph records as branch targets of the instruction at `address`.
fn branch_targets(idb: &Database, address: Address) -> impl Iterator<Item = Address> + '_ {
    idb.xrefs_from(address)
        .filter(|x| {
            matches!(
                x.kind,
                XrefKind::Code(
                    CodeXref::CallNear | CodeXref::CallFar | CodeXref::JumpNear | CodeXref::JumpFar
                )
            )
        })
        .map(|x| x.to)
}

/// How many disagreeing branches [`unmatched_report`] names before it stops collecting.
const UNMATCHED_SAMPLE: usize = 5;

/// A direct branch whose decoded target the reference graph does not carry.
struct Unmatched {
    address: Address,
    target: Address,
    mnemonic: String,
    len: u8,
}

/// Why the disagreeing branches disagreed, naming several sites rather than one.
///
/// Whether every target is off by the same delta or each is wrong independently points at
/// different defects, and one sample cannot tell them apart.
fn unmatched_report(
    idb: &Database,
    direct: usize,
    matched: usize,
    unmatched: &[Unmatched],
) -> String {
    let mut report = format!(
        "{matched}/{direct} direct branches matched the reference graph; \
         first {} that did not:",
        unmatched.len()
    );
    for u in unmatched {
        let kinds: Vec<String> = idb
            .xrefs_from(u.address)
            .map(|x| format!("{:?}->{:#x}", x.kind, x.to))
            .collect();
        let _ = write!(
            report,
            "\n  {:#x} {} (len {}) targets {:#x}, xrefs there: [{}]",
            u.address.get(),
            u.mnemonic,
            u.len,
            u.target.get(),
            kinds.join(", ")
        );
    }
    report
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

/// Decompiling the first functions succeeds, and the extracted ctree's node counts agree with
/// the independent visitor counts.
///
/// A fixture whose architecture has no Hex-Rays module declares `decompiler = false` in the
/// manifest, which skips this check at the trial level rather than letting it pass vacuously;
/// every fixture that reaches this function is expected to decompile at least one.
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
            tree.statements().count() == cf.counts().statements as usize,
            "extracted statement count disagrees with the visitor"
        );
        let reachable = tree.descendants(NodeRef::Statement(root)).count();
        assert!(
            reachable == tree.expressions().count() + tree.statements().count(),
            "not every ctree node is reachable from the root"
        );
        deep_checked = true;
    }
    assert!(decompiled > 0, "no functions decompiled");
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
                let _ = image.get(p.ty);
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

/// Every decompiled local's [`StorageLocation`] is one the model structures, tallied by variant so
/// the corpus matrix surfaces the per-architecture argloc spread. `Custom` (`ALOC_CUSTOM`) is a
/// tripwire: it means a processor module produced an argloc idakit doesn't model, which we want
/// to see rather than silently absorb. Every scattered fragment must itself be a register
/// or stack slot, never nested, mirroring `argpart_t`. Like [`decompile`], a fixture reaching
/// this check is expected to decompile: one with no Hex-Rays module declares
/// `decompiler = false` and is skipped at the trial level.
pub fn argloc(idb: &Database) -> String {
    let mut n = [0usize; 8];

    let mut decompiled = 0usize;
    let mut lvars = 0usize;
    let mut user_named = 0usize;
    for f in idb.functions().take(200) {
        let Ok(cf) = f.decompile() else { continue };
        let Ok(tree) = cf.ctree() else { continue };
        decompiled += 1;
        for lv in tree.locals() {
            lvars += 1;
            n[location_index(&lv.location)] += 1;
            assert_fragments_flat(&lv.location);
            // The SDK's setters keep these: clearing the argument bit clears `this` too, and
            // marking a variable not-an-argument clears the argument bit.
            assert!(
                !lv.is_this_argument() || lv.is_argument(),
                "local {} is `this` but not an argument",
                lv.name
            );
            assert!(
                !(lv.is_argument() && lv.flags.contains(LocalFlags::NOT_ARGUMENT)),
                "local {} is both an argument and not one",
                lv.name
            );
            assert!(
                LocalFlags::all().contains(lv.flags),
                "local {} carries unnamed CVAR bits {:#x}",
                lv.name,
                lv.flags.bits()
            );
            user_named += usize::from(lv.is_user_named());
            // A decompiler local's register is the whole register, never an offset into one.
            assert!(
                !matches!(lv.location, StorageLocation::Register { offset, .. } if offset != 0),
                "local {} carries a register offset: {:?}",
                lv.name,
                lv.location
            );
        }
    }

    assert!(decompiled > 0, "no functions decompiled");
    assert!(lvars > 0, "no locals collected in decompiled functions");
    assert!(
        n[6] == 0,
        "{} local(s) mapped to Custom (ALOC_CUSTOM) -- an unmodeled argloc surfaced",
        n[6]
    );
    format!(
        "{decompiled} fns, {lvars} lvars ({user_named} user-named) | reg={} pair={} stack={} \
         rrel={} static={} scatter={} none={}",
        n[0], n[1], n[2], n[3], n[4], n[5], n[7]
    )
}

/// A location's slot in the per-variant tally: Register / RegisterPair / Stack /
/// RegisterRelative / Static / Scattered / Custom / Unallocated.
fn location_index(loc: &StorageLocation) -> usize {
    match loc {
        StorageLocation::Register { .. } => 0,
        StorageLocation::RegisterPair { .. } => 1,
        StorageLocation::Stack(_) => 2,
        StorageLocation::RegisterRelative { .. } => 3,
        StorageLocation::Static(_) => 4,
        StorageLocation::Scattered(_) => 5,
        StorageLocation::Custom(_) => 6,
        StorageLocation::Unallocated => 7,
    }
}

/// Every fragment of a scattered location is a register or stack slot, never itself scattered,
/// mirroring `argpart_t`.
fn assert_fragments_flat(loc: &StorageLocation) {
    if let StorageLocation::Scattered(pieces) = loc {
        for p in pieces {
            assert!(
                matches!(
                    p.location,
                    StorageLocation::Register { .. } | StorageLocation::Stack(_)
                ),
                "scattered fragment is neither register nor stack: {:?}",
                p.location
            );
        }
    }
}

/// Every stored prototype walks without an extraction error, and, once any typedef is followed to
/// its function body, its function-level facts hold together: a prototype whose locations were computed names a calling convention, every
/// parameter and the return value sit in a location the model structures (no `Custom`, flat
/// fragments), and a declared spoiled list is non-empty only under `FunctionTypeFlags::SPOILED`.
/// Tallies conventions, hidden parameters, and named parameters, so the matrix shows the spread.
pub fn prototypes(idb: &Database) -> String {
    use std::collections::BTreeMap;

    let mut typed = 0usize;
    let mut params_seen = 0usize;
    let mut named = 0usize;
    let mut hidden = 0usize;
    let mut unresolved = 0usize;
    let mut conventions: BTreeMap<String, usize> = BTreeMap::new();
    for f in idb.functions().take(2000) {
        let image = match f.prototype_type() {
            Ok(Some(image)) => image,
            Ok(None) => continue,
            Err(e) => panic!("prototype at {:#x} failed to walk: {e}", f.address()),
        };
        // A prototype may be stored as a typedef naming a function type; follow it to the body.
        let mut shape = image.shape();
        while let TypeShape::Typedef { underlying, .. } = shape {
            shape = &image.get(*underlying).shape;
        }
        let TypeShape::Function {
            params,
            calling_convention,
            flags,
            return_location,
            spoiled,
            ..
        } = shape
        else {
            unresolved += 1;
            continue;
        };
        typed += 1;
        if flags.contains(FunctionTypeFlags::LOCATIONS) {
            assert!(
                calling_convention.is_some(),
                "prototype at {:#x} computed locations but names no calling convention",
                f.address()
            );
        }
        if !spoiled.is_empty() {
            assert!(
                flags.contains(FunctionTypeFlags::SPOILED),
                "prototype at {:#x} lists spoiled registers without FTI_SPOILED",
                f.address()
            );
        }
        *conventions
            .entry(format!("{calling_convention:?}"))
            .or_default() += 1;
        for loc in std::iter::once(return_location).chain(params.iter().map(|p| &p.location)) {
            assert!(
                !matches!(loc, StorageLocation::Custom(_)),
                "prototype at {:#x} has an unmodeled custom location: {loc:?}",
                f.address()
            );
            assert_fragments_flat(loc);
        }
        params_seen += params.len();
        named += params.iter().filter(|p| p.name.is_some()).count();
        hidden += params.iter().filter(|p| p.is_hidden()).count();
    }
    if typed == 0 {
        return "no typed prototypes in prefix".to_string();
    }
    format!(
        "{typed} prototypes ({unresolved} unresolved), {params_seen} params ({named} named, \
         {hidden} hidden) | cc {conventions:?}"
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
        if seg.alignment().is_some() {
            aligned += 1;
        }
        if seg.combination().is_some() {
            combined += 1;
        }
        // Neither accessor has an independent oracle here; calling them without panicking is
        // the invariant.
        let _ = seg.selector();
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

/// Every type attribute word read off the local types holds only its own context's named bits,
/// frame-slot bits never mark an ordinary struct member, and each struct layout is internally
/// consistent. A census over the whole corpus found no other bit in any of the four words, so a
/// stray one means the walker read the wrong field.
pub fn type_attrs(idb: &Database) -> String {
    use idakit::types::{
        EnumAttributes, MemberAttributes, PointerAttributes, Signedness, StructAttributes,
    };

    let (mut aggregates, mut cpp, mut vftables, mut bases, mut comments, mut modified) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    let (mut enums, mut grouped, mut declared) = (0usize, 0usize, 0usize);
    let frame_bits = MemberAttributes::RETURN_ADDRESS | MemberAttributes::SAVED_REGISTERS;
    let mut problems = Vec::new();

    for named in idb.named_types().take(3000) {
        let Ok(ty) = named.resolve() else { continue };
        for (_, value) in ty.types().iter() {
            match &value.shape {
                TypeShape::Struct {
                    name,
                    members,
                    attributes,
                    layout,
                }
                | TypeShape::Union {
                    name,
                    members,
                    attributes,
                    layout,
                } => {
                    aggregates += 1;
                    let label = name.as_deref().unwrap_or("<anon>");
                    if !StructAttributes::all().contains(*attributes) {
                        problems.push(format!("{label}: struct word {:#x}", attributes.bits()));
                    }
                    cpp += usize::from(attributes.contains(StructAttributes::CPP_OBJECT));
                    if let Some(size) = value.size
                        && layout.unpadded_size > size
                    {
                        problems.push(format!(
                            "{label}: unpadded {} > size {size}",
                            layout.unpadded_size
                        ));
                    }
                    let aligned = |a: u32| a == 0 || a.is_power_of_two();
                    if !aligned(layout.effective_alignment)
                        || !layout.declared_alignment.is_none_or(u32::is_power_of_two)
                    {
                        problems.push(format!("{label}: alignment {layout:?}"));
                    }
                    for m in members {
                        let bits = m.attributes;
                        if !MemberAttributes::all().contains(bits) || bits.intersects(frame_bits) {
                            problems.push(format!(
                                "{label}.{}: member word {:#x}",
                                m.name,
                                bits.bits()
                            ));
                        }
                        vftables += usize::from(bits.contains(MemberAttributes::VFTABLE));
                        bases += usize::from(bits.contains(MemberAttributes::BASE_CLASS));
                        comments += usize::from(m.comment.is_some());
                    }
                }
                TypeShape::Ptr {
                    attributes,
                    modifier,
                    ..
                } => {
                    let named_or_field =
                        PointerAttributes::all().bits() | idakit::sys::POINTER_MODIFIER_MASK;
                    if attributes.bits() & !named_or_field != 0 {
                        problems.push(format!("pointer word {:#x}", attributes.bits()));
                    }
                    modified += usize::from(modifier.is_some());
                }
                TypeShape::Enum {
                    name,
                    underlying,
                    members,
                    is_bitmask,
                    signedness,
                    groups,
                    attributes,
                    ..
                } => {
                    enums += 1;
                    let label = name.as_deref().unwrap_or("<anon>");
                    if !EnumAttributes::all().contains(*attributes) {
                        problems.push(format!("{label}: enum word {:#x}", attributes.bits()));
                    }
                    if let Some(groups) = groups {
                        grouped += 1;
                        // Groups tile the member list: each starts where the last ended.
                        let mut next = 0;
                        for g in groups {
                            let start = g.mask.unwrap_or(g.members.start);
                            if !*is_bitmask
                                || start != next
                                || g.mask.is_some_and(|m| m + 1 != g.members.start)
                            {
                                problems.push(format!("{label}: group {g:?} after {next}"));
                            }
                            next = g.members.end;
                        }
                        if next != members.len() {
                            problems.push(format!(
                                "{label}: groups end at {next} of {}",
                                members.len()
                            ));
                        }
                    }
                    if let Some(s) = signedness {
                        declared += 1;
                        if let TypeShape::Int { signed, .. } = ty.get(*underlying).shape
                            && signed != (*s == Signedness::Signed)
                        {
                            problems.push(format!(
                                "{label}: declared {s:?}, underlying signed={signed}"
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    format!(
        "{aggregates} aggregates ({cpp} C++), {vftables} vftable / {bases} base members, \
         {comments} member comments, {modified} modified pointers, {enums} enums ({grouped} \
         grouped, {declared} declared signedness)"
    )
}

/// Each stack slot's kind agrees with the frame bits in its raw attribute word, and the word holds
/// no bit outside [`MemberAttributes`]. Everything else in it (type-library provenance in
/// practice) leaves the slot a variable.
pub fn frame_attrs(idb: &Database) -> String {
    use idakit::types::MemberAttributes;

    let (mut frames, mut slots, mut from_til, mut commented) = (0usize, 0usize, 0usize, 0usize);
    let mut problems = Vec::new();
    for f in idb.functions().take(2000) {
        let Ok(Some(frame)) = f.frame() else { continue };
        frames += 1;
        for slot in frame.slots() {
            slots += 1;
            let bits = slot.attributes();
            let expect_special = bits
                .intersects(MemberAttributes::RETURN_ADDRESS | MemberAttributes::SAVED_REGISTERS);
            if !MemberAttributes::all().contains(bits) || slot.is_special() != expect_special {
                problems.push(format!(
                    "{:#x} slot at {}: word {:#x}, kind {:?}",
                    f.address(),
                    slot.offset(),
                    bits.bits(),
                    slot.kind()
                ));
            }
            from_til += usize::from(bits.contains(MemberAttributes::FROM_TYPE_SYSTEM));
            commented += usize::from(slot.comment().is_some());
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    format!("{frames} frames, {slots} slots ({from_til} type-system, {commented} commented)")
}
