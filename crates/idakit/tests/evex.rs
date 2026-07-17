//! AVX-512 EVEX-modifier decode check against real IDA output.
//!
//! Assembles `tests/fixtures/avx512.asm` with nasm + ld, lets IDA auto-analyze it headlessly, and
//! pins the decoder's handling of the four EVEX modifiers: write-masking (merge and zeroing),
//! embedded broadcast, static rounding-control, and suppress-all-exceptions. The corpus contains
//! no AVX-512 rounding/broadcast forms (integer crypto never emits them), so this hand-assembled
//! fixture is the only coverage. Skips when nasm or ld is unavailable to build it.
//!
//! The regression this guards: IDA stores the opmask in a slot shaped like a sixth operand, so a
//! naive decode surfaced it as a phantom fourth operand carrying slot 5. Every decoded operand
//! here must have a slot below the processor's real operand count.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use assert2::assert;
use idakit::prelude::*;

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn evex_modifiers() {
    if !tool_available("nasm") || !tool_available("ld") {
        eprintln!("skipping: nasm or ld not available to build the fixture");
        return;
    }

    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/avx512.asm");
    let base: PathBuf = std::env::temp_dir().join(format!("idakit_evex_{}", std::process::id()));
    let obj = base.with_extension("o");
    let bin = base;

    let asm = Command::new("nasm")
        .args(["-f", "elf64", src, "-o"])
        .arg(&obj)
        .status()
        .expect("failed to spawn nasm");
    assert!(asm.success(), "nasm failed to assemble the fixture");
    let link = Command::new("ld")
        .arg("-o")
        .arg(&bin)
        .arg(&obj)
        .status()
        .expect("failed to spawn ld");
    assert!(link.success(), "ld failed to link the fixture");

    let bin_str = bin.to_string_lossy().into_owned();

    Ida::run(move |ida| {
        ida.call(move |idb| {
            idb.open(&bin_str)
                .run_auto(true)
                .call()
                .expect("open + auto-analysis failed");

            let mut insns: Vec<Instruction> = idb
                .functions()
                .flat_map(|f| f.instructions().collect::<Vec<_>>())
                .collect();
            // Sorted by address so the rounding-mode check below can rely on program order
            // regardless of how functions enumerate.
            insns.sort_by_key(|i| i.address);
            assert!(
                !insns.is_empty(),
                "no instructions decoded from the fixture"
            );

            // The phantom-operand regression: the opmask must never surface as an operand. x86 has
            // at most five real operand slots, so a slot of 5 is the leaked Op6.
            for insn in &insns {
                assert!(
                    insn.ops.iter().all(|o| o.slot < 5),
                    "operand slot >= 5 (leaked EVEX opmask) in {}: {:?}",
                    insn.mnemonic,
                    insn.ops
                );
            }

            // Write-masking: exactly the two masked forms, by (register name, zeroing).
            let masks: BTreeSet<(String, bool)> = insns
                .iter()
                .filter_map(|i| i.masking.as_ref())
                .map(|m| (m.register.name.to_string(), m.zeroing))
                .collect();
            assert!(
                masks == BTreeSet::from([("k1".to_string(), false), ("k2".to_string(), true)]),
                "unexpected write-masks: {masks:?}"
            );

            // Embedded broadcast, read off the memory operands: every {1toN} factor the fixture
            // encodes. 32 is the fp16 form the old EVEX.W heuristic mis-sized to 16; 2/4 exercise
            // the xmm/ymm widths.
            let broadcasts: Vec<u8> = insns
                .iter()
                .flat_map(|i| &i.ops)
                .filter_map(|o| match &o.kind {
                    OperandKind::Memory(m) => m.broadcast,
                    _ => None,
                })
                .collect();
            let factors: BTreeSet<u8> = broadcasts.iter().copied().collect();
            assert!(
                factors == BTreeSet::from([2, 4, 8, 16, 32]),
                "unexpected broadcast factors: {factors:?}"
            );
            // Every EVEX.b+mem form must parse a {1toN}: the fixture has seven, so a factor lost to a
            // failed read (None) would drop the count. This pins the "always Some on supported paths"
            // invariant the None fallback relies on.
            assert!(
                broadcasts.len() == 7,
                "expected 7 broadcast operands, got {}: {broadcasts:?}",
                broadcasts.len()
            );

            // Static rounding-control, in program order: the fixture's {rn,rd,ru,rz-sae} forms map
            // to exactly this sequence. Order matters here, since a swapped EVEX.L'L bit order would
            // still yield all four modes as a set while mislabelling rd as ru.
            let rounds: Vec<RoundMode> = insns
                .iter()
                .filter_map(|i| match i.fp_control {
                    Some(FpControl::Rounding { mode }) => Some(mode),
                    _ => None,
                })
                .collect();
            assert!(
                rounds
                    == [
                        RoundMode::Nearest,
                        RoundMode::Down,
                        RoundMode::Up,
                        RoundMode::Zero,
                    ],
                "rounding modes wrong or out of order (bit-order swap?): {rounds:?}"
            );

            // Suppress-all-exceptions only: the two non-rounding {sae} forms.
            let sae = insns
                .iter()
                .filter(|i| i.fp_control == Some(FpControl::SuppressExceptions))
                .count();
            assert!(sae == 2, "expected 2 suppress-exceptions forms, got {sae}");

            idb.close(false);
            println!(
                "evex fixture OK: 2 write-masks, broadcast {{2,4,8,16,32}}, 4 rounding modes, 2 sae; \
                 no phantom operand"
            );
        })
        .unwrap_or_else(|e| e.resume());
    })
    .expect("kernel init failed");

    let _ = std::fs::remove_file(&obj);
    let _ = std::fs::remove_file(&bin);
    let _ = std::fs::remove_file(bin.with_extension("i64"));
}
