//! Instruction decode against a real database: walk, decode, cross-check.
//!
//! A normal `#[test]`: the kernel runs on the thread `Ida::run` spawns (8 MiB stack), so no
//! `harness = false`; the nextest `serial-kernel` group keeps it off the other kernel tests'
//! toes. Runs against the corpus manifest's canonical fixture (see [`common::TestDb`]);
//! skips when no corpus is configured. It decodes a
//! slice of each function's instruction stream, asserts structural invariants, cross-checks
//! direct-branch targets against IDA's own reference graph (two independent sources that must
//! agree), and walks the byte accessors. Mostly read-only: one check round-trips a comment write
//! that is never persisted (`idb.close(false)`).

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
            if m.displacement != 0 {
                let _ = write!(s, "{:+#x}", m.displacement);
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
    check_instructions_in_boundaries(idb);
    check_xref_flow_and_predicates(idb);
    check_xref_edges_are_symmetric(idb);
    check_is_code_and_is_data(idb);
    check_next_and_prev_head(idb);
    check_read_into_matches_bytes(idb);
    // Last: the only check that writes, so nothing after it reads a mutated database.
    check_comment_round_trips(idb);
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
                "empty mnemonic at {address:#x} (canonical_code {})",
                instruction.canonical_code
            );
            // Every operand's original slot index stays within IDA's operand array, and its byte
            // offset never exceeds the instruction it belongs to.
            for op in &instruction.ops {
                assert!(
                    op.slot < 8,
                    "operand slot {} out of range at {address:#x}",
                    op.slot
                );
                assert!(
                    op.byte_offset <= instruction.len,
                    "operand byte_offset {} exceeds instruction length {} at {address:#x}",
                    op.byte_offset,
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
    // A walk that yields more than one instruction proves the cursor advances past each decoded
    // item rather than jumping straight to the chunk end.
    let mut multi_insn_function = false;
    'iter: for (fi, function) in idb.functions().enumerate() {
        let chunks: Vec<_> = function.chunks().collect();
        assert!(
            !chunks.is_empty(),
            "function {:#x} reports no chunks",
            function.address().get()
        );
        let mut this_fn_count = 0usize;
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
            // Pins the premise behind Instructions::next's `>` guard: item_end must strictly
            // advance at every code address a real walk visits, never echo the input back.
            assert!(
                idb.item_end(instruction.address) > instruction.address,
                "item_end should strictly advance past {:#x}",
                instruction.address.get()
            );
            if fi == 0 && first_fn.len() < 12 {
                first_fn.push(fmt_insn(&instruction));
            }
            this_fn_count += 1;
            iter_total += 1;
            if iter_total >= BUDGET {
                break 'iter;
            }
        }
        // Single-chunk only: a multi-chunk function yields one instruction per chunk even if the
        // cursor never advances within a chunk.
        if chunks.len() == 1 && this_fn_count > 1 {
            multi_insn_function = true;
        }
    }
    assert!(iter_total > 0, "instructions() yielded nothing");
    assert!(
        multi_insn_function,
        "no function yielded more than one instruction; Instructions::next never advances"
    );
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

/// A chunk's range yields more than one instruction (the cursor advances), and an unmapped range
/// terminates: [`Database::item_end`] falls back to `address` itself there, which must end the
/// walk rather than loop forever re-examining that address.
fn check_instructions_in_boundaries(idb: &Database) {
    let mut multi_insn_range = false;
    'outer: for function in idb.functions().take(500) {
        for chunk in function.chunks() {
            if idb.instructions_in(chunk.start..chunk.end).take(3).count() > 1 {
                multi_insn_range = true;
                break 'outer;
            }
        }
    }
    assert!(
        multi_insn_range,
        "no chunk yielded more than one instruction; InstructionsIn::next never advances"
    );

    let Some(unmapped) = (1u64..0x1000)
        .filter_map(Address::try_new)
        .find(|&a| idb.segment_at(a).is_none())
    else {
        println!("skipping: no unmapped low address found to probe the zero-width guard");
        return;
    };
    // Pins the other half of Instructions::next's `>` guard premise: even outside every
    // segment, item_end still advances rather than echoing the input back as BADADDR would.
    assert!(
        idb.item_end(unmapped) > unmapped,
        "item_end should advance past the unmapped address {unmapped:#x} too"
    );
    let mut probe = idb.instructions_in(unmapped..unmapped + 0x10);
    assert!(
        probe.next().is_none(),
        "an unmapped range at {unmapped:#x} should decode nothing"
    );
    println!("instructions_in boundary checks OK (probed unmapped {unmapped:#x})");
}

/// `CodeXref::Flow` is excluded by default and surfaced by `flow(true)`, and the
/// `has_external_refs`/`has_jump_or_flow_xref` predicates report both true and false.
fn check_xref_flow_and_predicates(idb: &Database) {
    let mut found_flow = false;
    let mut mid_function_addr = None;

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
                mid_function_addr = Some(next);
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

    // A direct call into a different function's entry is a reference from outside the callee, so
    // has_external_refs must report true there.
    let function_starts: std::collections::HashSet<Address> =
        idb.functions().map(|f| f.address()).collect();
    let mut found_external = false;
    'externals: for function in idb.functions() {
        let mut address = function.address();
        for _ in 0..64 {
            let Ok(instruction) = idb.decode(address) else {
                break;
            };
            if !instruction.flow.is_indirect
                && instruction.flow.is_call
                && let Some(target) = instruction.flow.target
                && target != function.address()
                && function_starts.contains(&target)
            {
                assert!(
                    idb.has_external_refs(target),
                    "call target {target:#x} from a different function should report external refs"
                );
                found_external = true;
                println!(
                    "external ref confirmed: {:#x} calls {target:#x}",
                    address.get()
                );
                break 'externals;
            }
            address = address + u64::from(instruction.len);
        }
    }
    assert!(
        found_external,
        "no direct call into a different function's entry found to verify has_external_refs"
    );

    // Negative case for has_external_refs: nothing calls into the middle of a straight-line
    // function body, so the second instruction the flow walk above landed on has no external
    // refs, catching a predicate hardcoded to `true`.
    let mid = mid_function_addr.expect("found_flow implies a mid-function address was recorded");
    assert!(
        !idb.has_external_refs(mid),
        "mid-function instruction {mid:#x} should report no external refs"
    );

    // Negative case for has_jump_or_flow_xref: a function entry reached only by direct calls
    // (fl_CN/fl_CF, xref.hpp) carries no incoming jump (fl_JN/fl_JF) or flow (fl_F) cref.
    let call_only_entry = idb
        .functions()
        .take(5000)
        .map(|f| f.address())
        .find(|&entry| {
            !idb.xrefs_to_with(entry).flow(true).call().any(|x| {
                matches!(
                    x.kind,
                    XrefKind::Code(CodeXref::JumpNear | CodeXref::JumpFar | CodeXref::Flow)
                )
            })
        });
    if let Some(entry) = call_only_entry {
        assert!(
            !idb.has_jump_or_flow_xref(entry),
            "call-only function entry {entry:#x} should report no jump/flow xref"
        );
    } else {
        println!("skipping: no function entry found with only call-kind incoming xrefs");
    }
}

/// `xrefs_to`/`xrefs_from` are two traversal directions over one edge list, so every outgoing
/// edge `A -> B` must appear in `B`'s incoming list. Sampled over code and data references from
/// a real disassembly walk rather than synthesized.
fn check_xref_edges_are_symmetric(idb: &Database) {
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

/// A function entry classifies as code, never data; the first entry in IDA's own string list
/// classifies as data, never code. Derived from the database's structure rather than a fixed
/// address, so it needs no per-fixture constant.
fn check_is_code_and_is_data(idb: &Database) {
    let code_addr = idb.functions().next().expect("a function").address();
    assert!(
        idb.is_code(code_addr),
        "function entry should classify as code"
    );
    assert!(
        !idb.is_data(code_addr),
        "function entry should not classify as data"
    );

    let data_addr = idb.strings().next().expect("a string literal").address();
    assert!(
        idb.is_data(data_addr),
        "known string address should classify as data"
    );
    assert!(
        !idb.is_code(data_addr),
        "known string address should not classify as code"
    );
}

/// `next_head`/`prev_head` land on the real neighboring head, not `None`: from a function entry
/// to the instruction right after it, and back.
fn check_next_and_prev_head(idb: &Database) {
    let bounds = idb
        .address_range()
        .expect("open database has an address range");
    let mut checked = false;
    for function in idb.functions() {
        let entry = function.address();
        let Ok(insn) = idb.decode(entry) else {
            continue;
        };
        let next_addr = entry + u64::from(insn.len);
        if !idb.is_code(next_addr) {
            continue;
        }
        assert!(
            idb.next_head(entry, bounds.end) == Some(next_addr),
            "next_head from {entry:#x} should land on the following head {next_addr:#x}"
        );
        assert!(
            idb.prev_head(next_addr, bounds.start) == Some(entry),
            "prev_head from {next_addr:#x} should land back on {entry:#x}"
        );
        checked = true;
        break;
    }
    assert!(
        checked,
        "no function found with two consecutive code heads to check next_head/prev_head"
    );
}

/// `read_into` fills the caller's buffer with the same bytes the owning [`Database::bytes`]
/// shortcut returns, and reports the real count supplied.
fn check_read_into_matches_bytes(idb: &Database) {
    let address = idb.functions().next().expect("a function").address();
    let owned = idb.bytes(address, 8);
    assert!(owned.len() == 8, "need 8 readable bytes at the entry");

    let mut buf = [0u8; 8];
    let got = idb.read_into(address, &mut buf);
    assert!(got == 8, "read_into should report all 8 bytes supplied");
    assert!(
        buf.as_slice() == owned.as_slice(),
        "read_into should match the owned read"
    );
}

/// A comment set through the write cursor reads back verbatim through [`Database::comment`].
/// Never saved: `with_canonical_db` closes `save = false`.
fn check_comment_round_trips(idb: &mut Database) {
    let address = idb.functions().next().expect("a function").address();
    idb.at_mut(address)
        .set_comment("idakit probe", false)
        .expect("set_comment failed");
    assert!(
        idb.comment(address, false).as_deref() == Some("idakit probe"),
        "comment should read back the text just set"
    );
}
