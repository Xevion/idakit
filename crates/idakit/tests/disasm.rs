//! Instruction decode against a real database: walk, decode, cross-check.
//!
//! `harness = false` so the test owns `fn main()` -- `Ida::here` needs the OS main
//! thread's stack. Set `IDAKIT_TEST_DB` to an absolute `.i64` path; skips when unset. It
//! decodes a slice of each function's instruction stream, asserts structural invariants,
//! and cross-checks direct-branch targets against IDA's own xref graph -- two independent
//! sources that must agree. Read-only; never opens for write.

use idakit::{CodeRef, Offset, Operand, OperandKind, XrefKind};

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

fn main() {
    let Ok(db) = std::env::var("IDAKIT_TEST_DB") else {
        eprintln!("skipping: set IDAKIT_TEST_DB=<path to .i64> to run this test");
        return;
    };

    let mut idb = idakit::Ida::here().expect("kernel init failed");
    idb.open(&db).call().expect("open failed");

    const BUDGET: usize = 4000;
    let mut total = 0usize;
    let mut with_ops = 0usize;
    let mut checked_target = false;
    let mut samples: Vec<String> = Vec::new();

    'outer: for (fi, func) in idb.functions().enumerate() {
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

            if fi == 0 && samples.len() < 12 {
                samples.push(fmt_insn(&insn));
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
    println!("first function disassembly:");
    for s in &samples {
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
