//! Instruction decode against a real database: walk, decode, cross-check.
//!
//! A normal `#[test]`: the kernel runs on the thread `Ida::run` spawns (8 MiB stack), so no
//! `harness = false`; the nextest `serial-kernel` group keeps it off the other kernel tests'
//! toes. Runs against `IDAKIT_TEST_DB` or `$IDADIR/libida.so.i64` (see [`common::test_db`]);
//! skips when neither is present. It decodes a
//! slice of each function's instruction stream, asserts structural invariants, and
//! cross-checks direct-branch targets against IDA's own xref graph -- two independent sources
//! that must agree. Read-only; never opens for write.

use idakit::{CodeRef, Ida, Idb, Offset, Operand, OperandKind, XrefKind};

mod common;

fn fmt_op(op: &Operand) -> String {
    match &op.kind {
        OperandKind::Reg(r) => r.name.to_string(),
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

fn fmt_insn(insn: &idakit::Insn) -> String {
    let ops: Vec<String> = insn.ops.iter().map(fmt_op).collect();
    format!(
        "{:#x}  {:<8} {}",
        insn.ea.get(),
        insn.mnemonic,
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

    'outer: for func in idb.functions() {
        let mut ea = func.ea();
        for _ in 0..256 {
            let insn = match idb.decode(ea) {
                Ok(i) => i,
                // NotCode ends the run of this function's straight-line decode (data,
                // alignment, or the function tail); move on to the next function.
                Err(_) => break,
            };

            // Structural invariants that must hold for every decoded instruction.
            assert!(insn.len > 0, "zero-length instruction at {ea:#x}");
            assert!(insn.ea == ea, "decoded ea disagrees at {ea:#x}");
            assert!(
                !insn.mnemonic.is_empty(),
                "empty mnemonic at {ea:#x} (itype {})",
                insn.itype
            );
            // Every operand's original slot index stays within IDA's operand array.
            for op in &insn.ops {
                assert!(
                    op.idx < 8,
                    "operand index {} out of range at {ea:#x}",
                    op.idx
                );
            }
            if !insn.ops.is_empty() {
                with_ops += 1;
            }

            // Cross-check: a direct (non-indirect) branch/call with a static target must
            // have that target recorded as a code xref from this address. Positive check --
            // proving the mechanism works on at least one real branch is enough, and it
            // tolerates the rare target IDA didn't record as a cref.
            if !checked_target
                && !insn.flow.is_indirect
                && (insn.flow.is_call || insn.flow.is_jump)
                && let Some(target) = insn.flow.target
            {
                let matched = idb.xrefs_from(ea).any(|x| {
                    x.to == target
                        && matches!(
                            x.kind,
                            XrefKind::Code(
                                CodeRef::CallNear
                                    | CodeRef::CallFar
                                    | CodeRef::JumpNear
                                    | CodeRef::JumpFar
                            )
                        )
                });
                if matched {
                    checked_target = true;
                    println!(
                        "cross-checked direct {} at {:#x} -> {:#x} against xref graph",
                        if insn.flow.is_call { "call" } else { "jump" },
                        ea.get(),
                        target.get()
                    );
                }
            }

            total += 1;
            ea = ea + Offset::new(i64::from(insn.len));
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
        "no direct branch target matched the xref graph -- flow.target is likely wrong"
    );

    println!("decoded {total} instructions ({with_ops} with operands); invariants held");

    // Code-gated iteration: `Func::instructions()` must yield only real instructions, unlike
    // the straight-line decode above that runs off a function's tail into adjacent bytes.
    // Every yielded instruction sits at a code address inside one of the function's chunks
    // and does not spill past that chunk's end.
    let mut iter_total = 0usize;
    let mut first_fn: Vec<String> = Vec::new();
    'iter: for (fi, func) in idb.functions().enumerate() {
        let chunks: Vec<_> = func.chunks().collect();
        assert!(
            !chunks.is_empty(),
            "function {:#x} reports no chunks",
            func.ea().get()
        );
        for insn in func.instructions() {
            assert!(
                idb.is_code(insn.ea),
                "instructions() yielded a non-code address {:#x}",
                insn.ea.get()
            );
            let end = insn.ea + Offset::new(i64::from(insn.len));
            let in_chunk = chunks.iter().any(|c| insn.ea >= c.start && end <= c.end);
            assert!(
                in_chunk,
                "instruction {:#x} escapes its function's chunks",
                insn.ea.get()
            );
            if fi == 0 && first_fn.len() < 12 {
                first_fn.push(fmt_insn(&insn));
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
    let entry = idb.functions().next().expect("a function").ea();
    let a = idb.decode(entry).expect("entry decodes");
    let b = idb.decode(entry).expect("entry decodes again");
    assert!(a == b, "decode is not deterministic");

    idb.close(false);
    println!("ok");
}
