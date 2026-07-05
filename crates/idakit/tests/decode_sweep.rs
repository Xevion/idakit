//! Decode every instruction in a real database and hold the strict-decode invariants: no
//! silent fallbacks, no panics, no misclassification.
//!
//! It walks every code head in every function's chunks, decodes it, and asserts the decode
//! *succeeds* -- a register or value type the model cannot represent exactly is a loud error,
//! never a `Gpr`/`Void` guess -- then cross-checks each register's resolved name against its
//! assigned [`RegisterClass`]. That name <-> class check is the tripwire for a misclassified
//! register: `bnd0` classed as anything but [`RegisterClass::Bnd`] fails here. Read-only; opens
//! `save = false`. Skips when no test database is present.

mod common;

use idakit::{DecodeError, Idb, Instruction, OperandKind, Register, RegisterClass};

#[test]
fn decode_is_strict_and_consistent() {
    let Some(db) = common::TestDb::acquire() else {
        eprintln!("skipping: no test database (set IDAKIT_TEST_DB or install IDA at $IDADIR)");
        return;
    };
    let path = db.path().to_owned();
    idakit::Ida::run(move |ida| {
        ida.call(move |idb| run(idb, &path))
            .unwrap_or_else(|e| e.resume())
    })
    .expect("kernel init failed");
}

/// The register classes whose resolved name has a fixed prefix, so name and class must agree.
/// GPR/segment names are irregular, and st/control/debug/test names are a known, separate gap
/// (the optype-register path still mis-names them), so those classes are tallied but not
/// name-checked here.
fn expected_class(name: &str) -> Option<RegisterClass> {
    // Order matters: xmm/ymm/zmm are checked before the bare `mm` prefix.
    if name.starts_with("xmm") {
        Some(RegisterClass::Xmm)
    } else if name.starts_with("ymm") {
        Some(RegisterClass::Ymm)
    } else if name.starts_with("zmm") {
        Some(RegisterClass::Zmm)
    } else if name.starts_with("bnd") {
        Some(RegisterClass::Bnd)
    } else if name.starts_with("mm") {
        Some(RegisterClass::Mmx)
    } else if name.len() == 2 && name.starts_with('k') && name.as_bytes()[1].is_ascii_digit() {
        Some(RegisterClass::Mask)
    } else {
        None
    }
}

fn check_register(reg: &Register, address: u64, classes: &mut [usize; 13]) {
    classes[reg.class.raw() as usize] += 1;
    if let Some(expected) = expected_class(&reg.name) {
        assert!(
            reg.class == expected,
            "register {:?} at {address:#x} classed {:?}, name implies {expected:?}",
            reg.name.as_ref(),
            reg.class,
        );
    }
}

fn check_instruction(insn: &Instruction, classes: &mut [usize; 13]) {
    let at = insn.address.get();
    for op in &insn.ops {
        match &op.kind {
            OperandKind::Register(r) => check_register(r, at, classes),
            OperandKind::Mem(m) => {
                if let Some(b) = &m.base {
                    check_register(b, at, classes);
                }
                if let Some(i) = &m.index {
                    check_register(i, at, classes);
                }
            }
            _ => {}
        }
    }
}

fn run(idb: &mut Idb, db: &str) {
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
                            check_instruction(&insn, &mut classes);
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
    let named = |c: RegisterClass| classes[c.raw() as usize];
    println!(
        "decode sweep OK: {insns} instructions, {regs} register operands -- \
         gpr {} seg {} xmm {} ymm {} zmm {} mask {} st {} mmx {} ctrl {} dbg {} test {} ip {} bnd {}",
        named(RegisterClass::Gpr),
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
