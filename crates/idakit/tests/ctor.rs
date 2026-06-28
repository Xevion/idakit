//! Deterministic constructor-analysis check against real decompiler output.
//!
//! Compiles `tests/fixtures/vtbl.cpp` with g++, lets IDA auto-analyze it headlessly, then
//! asserts the ctree query matchers recover the multiple-inheritance constructor pattern:
//! the `Derived` ctor installs two vtables — the primary at offset 0 and the `Other`
//! subobject at a nonzero offset — and calls both base constructors with the matching
//! `this`-relative arguments. This pins `query::vtable_installs`/`query::this_arg_calls`
//! to ground truth, complementing the synthetic trees in the unit tests.
//!
//! `harness = false`: the test owns `fn main()` to control process lifetime around the
//! kernel thread `Ida::run` spawns. Skips (exit 0) when `g++` is unavailable.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use assert2::assert;
use idakit::ctree::query;

fn gxx_available() -> bool {
    Command::new("g++")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn main() {
    if !gxx_available() {
        eprintln!("skipping: g++ not available to build the fixture");
        return;
    }

    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vtbl.cpp");
    // No optimization: keep the constructors out-of-line so their vtable stores and base
    // ctor calls survive as distinct nodes in the decompiled ctree.
    let bin: PathBuf = std::env::temp_dir().join(format!("idakit_vtbl_{}", std::process::id()));

    let status = Command::new("g++")
        .args(["-O0", "-w", "-o"])
        .arg(&bin)
        .arg(src)
        .status()
        .expect("failed to spawn g++");
    assert!(status.success(), "g++ failed to compile the fixture");

    let bin_str = bin.to_string_lossy().into_owned();

    idakit::Ida::run(move |ida| {
        ida.call(move |idb| {
            idb.open(&bin_str)
                .run_auto(true)
                .call()
                .expect("open + auto-analysis failed");

            // Run the constructor matchers over every function's ctree. Decompilation can
            // fail for thunks/imports — skip those. Keep only functions that install at
            // least one vtable, with their this-arg calls, for the assertions below.
            let eas: Vec<_> = idb.functions().map(|f| (f.ea(), f.name())).collect();
            let mut analyzed = Vec::new();
            for (ea, name) in eas {
                let Ok(cf) = idb.decompile(ea) else { continue };
                let Ok(tree) = cf.ctree() else { continue };
                let installs = query::vtable_installs(&tree);
                if installs.is_empty() {
                    continue;
                }
                let calls = query::this_arg_calls(&tree);
                analyzed.push((name.unwrap_or_default(), installs, calls));
            }

            // The Derived ctor is the function installing two vtables: the primary at
            // offset 0 and the Other subobject at a nonzero offset.
            let mi_ctor = analyzed
                .iter()
                .find(|(_, installs, _)| {
                    installs.len() >= 2
                        && installs.iter().any(|i| i.this_offset == 0)
                        && installs.iter().any(|i| i.this_offset > 0)
                })
                .unwrap_or_else(|| {
                    panic!("no multiple-inheritance constructor found; analyzed: {analyzed:#?}")
                });

            let (name, installs, calls) = mi_ctor;

            // The nonzero subobject offset both matchers must agree on.
            let sub_off = installs
                .iter()
                .map(|i| i.this_offset)
                .find(|&o| o > 0)
                .expect("a nonzero subobject install offset");

            // Each base constructor is called with a this-relative argument: the primary
            // base at offset 0, the Other subobject at the same offset its vtable went.
            assert!(
                calls.iter().any(|c| c.this_offset == 0),
                "expected a base ctor call at this+0; calls: {calls:#?}"
            );
            assert!(
                calls.iter().any(|c| c.this_offset == sub_off),
                "expected a subobject ctor call at this+{sub_off}; calls: {calls:#?}"
            );

            idb.close(false);
            println!(
                "ctor fixture OK: `{name}` installs 2 vtables (offsets 0, {sub_off}) and \
                 calls both base ctors with matching this-relative args"
            );
        })
        .expect("kernel call panicked");
    })
    .expect("kernel init failed");

    // Best-effort cleanup: the temp binary and the database IDA wrote next to it.
    let _ = std::fs::remove_file(&bin);
    let _ = std::fs::remove_file(bin.with_extension("i64"));
}
