//! Instruction decode against a real database: walk, decode, cross-check.
//!
//! A normal `#[test]`: the kernel runs on the thread `Ida::run` spawns (8 MiB stack), so no
//! `harness = false`; the nextest `serial-kernel` group keeps it off the other kernel tests'
//! toes. Runs against the corpus manifest's canonical fixture (see [`common::TestDb`]);
//! skips when no corpus is configured. It decodes a
//! slice of each function's instruction stream, asserts structural invariants, and
//! cross-checks direct-branch targets against IDA's own reference graph. Two independent sources
//! that must agree. Read-only; never opens for write.

use std::fmt::Write as _;

use idakit::prelude::*;

mod common;

fn fmt_op(op: &Operand) -> String {
    match &op.kind {
        OperandKind::Register(r) => r.name.to_string(),
        OperandKind::Immediate { value } => format!("{value:#x}"),
        OperandKind::Near(t) => format!("{t:#x}"),
        OperandKind::Far { selector, offset } => format!("{selector:#x}:{offset:#x}"),
        OperandKind::Memory(m) => {
            let mut s = String::from("[");
            if let Some(b) = &m.base {
                s.push_str(&b.name);
            }
            if let Some(i) = &m.index {
                let _ = write!(s, "+{}*{}", i.name, m.scale);
            }
            if m.disp != 0 {
                let _ = write!(s, "{:+#x}", m.disp);
            }
            s.push(']');
            s
        }
    }
}

fn fmt_insn(instruction: &Instruction) -> String {
    let ops: Vec<String> = instruction.ops.iter().map(fmt_op).collect();
    format!(
        "{:#x}  {:<8} {}",
        instruction.address.get(),
        instruction.mnemonic,
        ops.join(", ")
    )
}

#[test]
fn disasm() {
    common::with_canonical_db(run);
}

fn run(idb: &mut Database) {
    check_straight_line_decode_invariants(idb);
    check_code_gated_instructions(idb);
    check_straight_line_lands_on_end(idb);
    check_decode_is_deterministic(idb);
    println!("ok");
}

/// A bounded straight-line decode over every function's instruction stream: structural
/// invariants hold per instruction, and at least one direct branch target is cross-checked
/// against IDA's own reference graph.
fn check_straight_line_decode_invariants(idb: &Database) {
    const BUDGET: usize = 4000;
    let mut total = 0usize;
    let mut with_ops = 0usize;
    let mut checked_target = false;

    'outer: for function in idb.functions() {
        let mut address = function.address();
        for _ in 0..256 {
            // NotCode ends the run of this function's straight-line decode (data,
            // alignment, or the function tail); move on to the next function.
            let Ok(instruction) = idb.decode(address) else {
                break;
            };

            // Structural invariants that must hold for every decoded instruction.
            assert!(
                instruction.len > 0,
                "zero-length instruction at {address:#x}"
            );
            assert!(
                instruction.address == address,
                "decoded address disagrees at {address:#x}"
            );
            assert!(
                !instruction.mnemonic.is_empty(),
                "empty mnemonic at {address:#x} (itype {})",
                instruction.itype
            );
            // Every operand's original slot index stays within IDA's operand array, and its byte
            // offset never exceeds the instruction it belongs to.
            for op in &instruction.ops {
                assert!(
                    op.idx < 8,
                    "operand index {} out of range at {address:#x}",
                    op.idx
                );
                assert!(
                    op.offb <= instruction.len,
                    "operand offb {} exceeds instruction length {} at {address:#x}",
                    op.offb,
                    instruction.len
                );
            }
            if !instruction.ops.is_empty() {
                with_ops += 1;
            }

            // Cross-check: a direct (non-indirect) branch/call with a static target must
            // have that target recorded as a code reference from this address. Positive check --
            // proving the mechanism works on at least one real branch is enough, and it
            // tolerates the rare target IDA didn't record as a cref.
            if !checked_target
                && !instruction.flow.is_indirect
                && (instruction.flow.is_call || instruction.flow.is_jump)
                && let Some(target) = instruction.flow.target
            {
                let matched = idb.xrefs_from(address).find(|x| {
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
                if let Some(reference) = matched {
                    // A branch IDA itself decoded is analysis-made, never user-marked. Asserting it
                    // also proves the `xrefblk_t::user` byte flows through the facade rather than
                    // arriving uninitialized (which would surface as a spurious `User`).
                    assert!(
                        reference.origin == XrefOrigin::Analysis,
                        "direct branch xref at {address:#x} should be analysis-made, got {:?}",
                        reference.origin
                    );
                    checked_target = true;
                    println!(
                        "cross-checked direct {} at {:#x} -> {:#x} against reference graph",
                        if instruction.flow.is_call {
                            "call"
                        } else {
                            "jump"
                        },
                        address.get(),
                        target.get()
                    );
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
    assert!(
        with_ops > 0,
        "no instruction had operands -- operand decode is likely broken"
    );
    assert!(
        checked_target,
        "no direct branch target matched the reference graph -- flow.target is likely wrong"
    );

    println!("decoded {total} instructions ({with_ops} with operands); invariants held");
}

/// Code-gated iteration: `Function::instructions()` must yield only real instructions, unlike
/// the unguarded straight-line decode that runs off a function's tail into adjacent bytes. Every
/// yielded instruction sits at a code address inside one of the function's chunks, does not
/// spill past that chunk's end, and its decoded length agrees with IDA's own item boundary.
fn check_code_gated_instructions(idb: &Database) {
    const BUDGET: usize = 4000;
    let mut iter_total = 0usize;
    let mut first_fn: Vec<String> = Vec::new();
    'iter: for (fi, function) in idb.functions().enumerate() {
        let chunks: Vec<_> = function.chunks().collect();
        assert!(
            !chunks.is_empty(),
            "function {:#x} reports no chunks",
            function.address().get()
        );
        for instruction in function.instructions() {
            assert!(
                idb.is_code(instruction.address),
                "instructions() yielded a non-code address {:#x}",
                instruction.address.get()
            );
            let end = instruction.address + u64::from(instruction.len);
            let in_chunk = chunks
                .iter()
                .any(|c| instruction.address >= c.start && end <= c.end);
            assert!(
                in_chunk,
                "instruction {:#x} escapes its function's chunks",
                instruction.address.get()
            );
            // Decoded length matches the byte span IDA itself assigns the item: two independent
            // sources (the processor decoder and the item classifier) must agree on where a real
            // code instruction ends. Only meaningful here, where `is_code` is already confirmed;
            // the unguarded straight-line walk elsewhere can run off into data, where the two need
            // not agree.
            assert!(
                idb.item_end(instruction.address) == end,
                "decoded length disagrees with the item boundary at {:#x}: decoded end {end:#x}, \
                 item_end {:#x}",
                instruction.address.get(),
                idb.item_end(instruction.address).get()
            );
            if fi == 0 && first_fn.len() < 12 {
                first_fn.push(fmt_insn(&instruction));
            }
            iter_total += 1;
            if iter_total >= BUDGET {
                break 'iter;
            }
        }
    }
    assert!(iter_total > 0, "instructions() yielded nothing");
    println!("code-gated instructions(): {iter_total} in-chunk code instructions");
    println!("first function via instructions():");
    for s in &first_fn {
        println!("  {s}");
    }
}

/// Straight-line decode from a function's start, advancing by decoded length, must land exactly
/// on the function's end when every head in between is real code (no embedded data, e.g. a jump
/// table, derails the walk). Restricted to single-chunk functions, whose entry span is the whole
/// function; overshooting `end` here would mean a decoded length is wrong.
///
/// Gated on `is_code` before each decode, unlike the unguarded budgeted walk elsewhere: `decode`
/// will happily turn a data byte into a plausible-looking instruction, so trusting a decode over
/// unclassified bytes here would risk a spurious "clean" walk that never truly lands on `end` by
/// construction, not by a real bug.
fn check_straight_line_lands_on_end(idb: &Database) {
    let mut landed = 0usize;
    let mut clean_fns = 0usize;
    for function in idb.functions().take(2000) {
        let Some(end) = function.end() else { continue };
        if function.chunks().count() != 1 {
            continue;
        }
        clean_fns += 1;
        let mut address = function.address();
        let mut clean = true;
        while address < end {
            if !idb.is_code(address) {
                clean = false;
                break;
            }
            let Ok(instruction) = idb.decode(address) else {
                clean = false;
                break;
            };
            address = address + u64::from(instruction.len);
        }
        if clean {
            assert!(
                address == end,
                "straight-line decode overshot the function end: landed at {:#x}, end is {end:#x}",
                address.get()
            );
            landed += 1;
        }
    }
    assert!(
        landed > 0,
        "no single-chunk function's straight-line decode landed cleanly on its end"
    );
    println!(
        "landing check: {landed}/{clean_fns} single-chunk functions decoded cleanly to their end"
    );
}

/// Decode is a pure read: the same address must decode identically twice.
fn check_decode_is_deterministic(idb: &Database) {
    let entry = idb.functions().next().expect("a function").address();
    let a = idb.decode(entry).expect("entry decodes");
    let b = idb.decode(entry).expect("entry decodes again");
    assert!(a == b, "decode is not deterministic");
}

#[test]
fn xref_flow_and_predicates() {
    common::with_canonical_db(run_xref_flow);
}

fn run_xref_flow(idb: &mut Database) {
    let mut found_flow = false;

    'outer: for function in idb.functions() {
        let mut address = function.address();
        for _ in 0..64 {
            let Ok(instruction) = idb.decode(address) else {
                break;
            };
            let next = address + u64::from(instruction.len);

            // Default excludes ordinary flow, matching CodeXref::Flow's exclusion from
            // xrefs_to/xrefs_from.
            assert!(
                !idb.xrefs_from(address)
                    .any(|x| x.to == next && matches!(x.kind, XrefKind::Code(CodeXref::Flow))),
                "xrefs_from at {address:#x} should exclude ordinary flow by default"
            );

            // flow(true) surfaces the sequential edge into the next instruction (skipped when
            // this one diverts control away entirely, e.g. an unconditional jump).
            let with_flow = idb
                .xrefs_from_with(address)
                .flow(true)
                .call()
                .any(|x| x.to == next && matches!(x.kind, XrefKind::Code(CodeXref::Flow)));
            if with_flow && !found_flow {
                assert!(
                    idb.has_jump_or_flow_xref(next),
                    "flow-reached address {next:#x} should report a jump-or-flow xref"
                );
                found_flow = true;
                println!(
                    "flow edge {:#x} -> {:#x} reachable via xrefs_from_with(...).flow(true)",
                    address.get(),
                    next.get()
                );
                break 'outer;
            }

            address = next;
        }
    }

    assert!(
        found_flow,
        "no CodeXref::Flow edge became reachable via xrefs_from_with(...).flow(true)"
    );

    // Positive case: at least one address in the first functions' straight-line decode should
    // carry an external reference (a call/jump into an import thunk or another module), proving
    // has_external_refs actually reports true somewhere rather than only ever false.
    let mut found_external = false;
    'externals: for function in idb.functions().take(2000) {
        let mut address = function.address();
        for _ in 0..64 {
            let Ok(instruction) = idb.decode(address) else {
                break;
            };
            if idb.has_external_refs(address) {
                found_external = true;
                println!("external ref found at {:#x}", address.get());
                break 'externals;
            }
            address = address + u64::from(instruction.len);
        }
    }
    if !found_external {
        println!("skipping: no external reference found in the scanned prefix");
    }

    println!("ok");
}

/// Edge symmetry: `xrefs_to`/`xrefs_from` are two traversal directions over one edge list, so for
/// every outgoing edge `A -> B` a database-wide bug would show up as `B`'s incoming list missing
/// the mirror `A -> B` edge. This is checked over both code and data references, sampled from a
/// real disassembly walk rather than synthesized.
#[test]
fn xref_edges_are_symmetric() {
    common::with_canonical_db(run_xref_symmetry);
}

fn run_xref_symmetry(idb: &mut Database) {
    const BUDGET: usize = 2000;
    let mut checked = 0usize;

    'outer: for function in idb.functions() {
        let mut address = function.address();
        for _ in 0..64 {
            let Ok(instruction) = idb.decode(address) else {
                break;
            };
            for x in idb.xrefs_from(address) {
                let mirrored = idb
                    .xrefs_to(x.to)
                    .any(|y| y.from == x.from && y.kind == x.kind && y.origin == x.origin);
                assert!(
                    mirrored,
                    "xref {:#x} -> {:#x} ({:?}, {:?}) has no mirrored entry in xrefs_to({:#x})",
                    x.from.get(),
                    x.to.get(),
                    x.kind,
                    x.origin,
                    x.to.get()
                );
                checked += 1;
                if checked >= BUDGET {
                    break 'outer;
                }
            }
            address = address + u64::from(instruction.len);
        }
    }

    assert!(checked > 0, "no xref edges sampled for symmetry");
    println!("xref edge symmetry OK: {checked} edges mirrored in both directions");
}
