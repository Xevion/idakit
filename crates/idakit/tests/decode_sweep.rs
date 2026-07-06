//! Decode every instruction in a real database and hold the strict-decode invariants: no
//! silent fallbacks, no panics, no misclassification.
//!
//! It walks every code head in every function's chunks, decodes it, and asserts the decode
//! *succeeds* -- a register or value type the model cannot represent exactly is a loud error,
//! never a `GeneralPurpose`/`Void` guess -- then cross-checks each register's resolved name against its
//! assigned [`RegisterClass`] with the shared `RegisterCheck` oracle. This is the exhaustive,
//! single-database counterpart to the budget-bounded `decode` check the corpus matrix fans out
//! across every fixture; both hold the same invariant through the same oracle. Read-only; opens
//! `save = false`. Skips when no test database is present.

mod common;

use common::checks::RegisterCheck;
use idakit::prelude::*;

#[test]
fn decode_is_strict_and_consistent() {
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

fn run(idb: &mut Database, db: &str) {
    idb.open(db).call().expect("open failed");

    let mut classes = [0usize; 13];
    let mut insns = 0usize;

    // Every code head in every function's chunks must decode faithfully. A `NotCode` head is
    // ordinary (embedded data such as a jump table); any *other* error means the strict decode
    // rejected a real instruction, which would be a regression, not a fallback silently hiding it.
    let functions: Vec<_> = idb.functions().map(|f| f.address()).collect();
    for fea in functions {
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
                                classes[u8::from(register.class) as usize] += 1;
                            }
                            insns += 1;
                        }
                        Err(DecodeError::NotCode { .. }) => {}
                        Err(other) => {
                            panic!(
                                "strict decode rejected a real instruction at {address:#x}: {other}"
                            )
                        }
                    }
                }
                match idb.next_head(address, chunk.end) {
                    Some(next) if next > address => address = next,
                    _ => break,
                }
            }
        }
    }

    let regs: usize = classes.iter().sum();
    assert!(insns > 0, "decoded no instructions");
    assert!(
        regs > 0,
        "no register operands seen -- operand decode is likely broken"
    );

    idb.close(false);
    let named = |c: RegisterClass| classes[u8::from(c) as usize];
    println!(
        "decode sweep OK: {insns} instructions, {regs} register operands -- \
         gpr {} seg {} xmm {} ymm {} zmm {} mask {} st {} mmx {} ctrl {} dbg {} test {} ip {} bnd {}",
        named(RegisterClass::GeneralPurpose),
        named(RegisterClass::Segment),
        named(RegisterClass::Xmm),
        named(RegisterClass::Ymm),
        named(RegisterClass::Zmm),
        named(RegisterClass::Mask),
        named(RegisterClass::St),
        named(RegisterClass::Mmx),
        named(RegisterClass::Control),
        named(RegisterClass::Debug),
        named(RegisterClass::Test),
        named(RegisterClass::Ip),
        named(RegisterClass::Bnd),
    );
}
