//! Instruction decode against a real database: walk, decode, cross-check.
//!
//! A normal `#[test]`: the kernel runs on the thread `Ida::run` spawns (8 MiB stack), so no
//! `harness = false`; the nextest `serial-kernel` group keeps it off the other kernel tests'
//! toes. Runs against `IDAKIT_TEST_DB` or `$IDADIR/libida.so.i64` (see [`common::test_db`]);
//! skips when neither is present. It decodes a
//! slice of each function's instruction stream, asserts structural invariants, and
//! cross-checks direct-branch targets against IDA's own reference graph -- two independent sources
//! that must agree. Read-only; never opens for write.

use idakit::{CodeReference, Ida, Idb, Offset, Operand, OperandKind, ReferenceKind};

mod common;

fn fmt_op(op: &Operand) -> String {
    match &op.kind {
        OperandKind::Register(r) => r.name.to_string(),
        OperandKind::Imm { value } => format!("{value:#x}"),
        OperandKind::Near(t) => format!("{t:#x}"),
        OperandKind::Far { selector, offset } => format!("{selector:#x}:{offset:#x}"),
        OperandKind::Mem(m) => {
            let mut s = String::from("[");
            if let Some(b) = &m.base {
                s.push_str(&b.name);
            }
            if let Some(i) = &m.index {
                s.push_str(&format!("+{}*{}", i.name, m.scale));
            }
            if m.disp != 0 {
                s.push_str(&format!("{:+#x}", m.disp));
            }
            s.push(']');
            s
        }
        // `OperandKind` is `#[non_exhaustive]`; a future kind renders as a placeholder.
        _ => String::from("?"),
    }
}

fn fmt_insn(instruction: &idakit::Instruction) -> String {
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
    let Some(db) = common::TestDb::acquire() else {
        eprintln!("skipping: no test database (set IDAKIT_TEST_DB or install IDA at $IDADIR)");
        return;
    };
    let path = db.path().to_owned();
    Ida::run(move |ida| {
        ida.call(move |idb| run(idb, &path))
            .unwrap_or_else(|e| e.resume())
    })
    .expect("kernel init failed");
}

fn run(idb: &mut Idb, db: &str) {
    idb.open(db).call().expect("open failed");

    const BUDGET: usize = 4000;
    let mut total = 0usize;
    let mut with_ops = 0usize;
    let mut checked_target = false;

    'outer: for function in idb.functions() {
        let mut address = function.address();
        for _ in 0..256 {
            let instruction = match idb.decode(address) {
                Ok(i) => i,
                // NotCode ends the run of this function's straight-line decode (data,
                // alignment, or the function tail); move on to the next function.
                Err(_) => break,
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
            // Every operand's original slot index stays within IDA's operand array.
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

            // Cross-check: a direct (non-indirect) branch/call with a static target must
            // have that target recorded as a code reference from this address. Positive check --
            // proving the mechanism works on at least one real branch is enough, and it
            // tolerates the rare target IDA didn't record as a cref.
            if !checked_target
                && !instruction.flow.is_indirect
                && (instruction.flow.is_call || instruction.flow.is_jump)
                && let Some(target) = instruction.flow.target
            {
                let matched = idb.references_from(address).any(|x| {
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
                if matched {
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
            address = address + Offset::new(i64::from(instruction.len));
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

    // Code-gated iteration: `Function::instructions()` must yield only real instructions, unlike
    // the straight-line decode above that runs off a function's tail into adjacent bytes.
    // Every yielded instruction sits at a code address inside one of the function's chunks
    // and does not spill past that chunk's end.
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
            let end = instruction.address + Offset::new(i64::from(instruction.len));
            let in_chunk = chunks
                .iter()
                .any(|c| instruction.address >= c.start && end <= c.end);
            assert!(
                in_chunk,
                "instruction {:#x} escapes its function's chunks",
                instruction.address.get()
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

    // Decode is a pure read: the same address must decode identically twice.
    let entry = idb.functions().next().expect("a function").address();
    let a = idb.decode(entry).expect("entry decodes");
    let b = idb.decode(entry).expect("entry decodes again");
    assert!(a == b, "decode is not deterministic");

    idb.close(false);
    println!("ok");
}
