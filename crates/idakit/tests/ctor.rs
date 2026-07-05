//! Deterministic constructor-analysis check against real decompiler output.
//!
//! The C++ constructor matchers (`vtable_installs` / `this_arg_calls`) live here as
//! test-local helpers composed from the public `idakit::ctree::query` primitives -- they
//! are specific to C++ reverse engineering, so they are not part of the crate's API. This
//! test pins them to ground truth: it compiles `tests/fixtures/vtbl.cpp` with g++, lets
//! IDA auto-analyze it headlessly, then asserts the multiple-inheritance constructor
//! pattern is recovered -- the `Derived` ctor installs two vtables (the primary at offset 0
//! and the `Other` subobject at a nonzero offset) and calls both base constructors with
//! the matching `this`-relative arguments.
//!
//! A normal `#[test]`; the kernel runs on the thread `Ida::run` spawns, so no
//! `harness = false`. The nextest `serial-kernel` group serializes it against the other
//! kernel tests. Skips when `g++` is unavailable to build the fixture.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use assert2::assert;
use idakit::ctree::Ctree;
use idakit::ctree::query::{base_var, global_target};
use idakit::{Address, AssignOp};

/// A store of a global's address into a `this`-relative slot -- a vtable install in a
/// constructor (`this->__vftable = &vtbl`). `this_offset` is the byte offset within the
/// object (0 = primary base, non-zero = a multiple-inheritance subobject).
#[derive(Clone, Debug, PartialEq, Eq)]
struct VtableInstall {
    this_offset: i64,
    vtable: Address,
    vtable_name: Option<String>,
}

/// A direct call whose first argument is `this`-relative -- a base or subobject
/// constructor call. `this_offset` is the byte offset of the subobject it applies to.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ThisCall {
    callee: Address,
    callee_name: Option<String>,
    this_offset: i64,
}

/// Every vtable install in the tree: a plain assignment of a global's address into a
/// `this`-relative slot. Composes the tolerant look-through primitives `base_var`
/// (resolve a place expression to `(lvar, byte-offset)`) and `global_target`.
fn vtable_installs(tree: &Ctree) -> Vec<VtableInstall> {
    let Some(this) = tree.this_lvar() else {
        return Vec::new();
    };
    tree.assigns()
        .filter_map(|(_, op, x, y)| {
            if op != AssignOp::Assign {
                return None;
            }
            let (v, off) = base_var(tree, x)?;
            if v != this {
                return None;
            }
            let g = global_target(tree, y)?;
            Some(VtableInstall {
                this_offset: off,
                vtable: g.address,
                vtable_name: g.name,
            })
        })
        .collect()
}

/// Every direct call whose first argument is `this`-relative -- base/subobject constructor
/// calls and other `this`-threading calls.
fn this_arg_calls(tree: &Ctree) -> Vec<ThisCall> {
    let Some(this) = tree.this_lvar() else {
        return Vec::new();
    };
    tree.calls()
        .filter_map(|(_, callee, args)| {
            let g = global_target(tree, callee)?;
            let (v, off) = base_var(tree, *args.first()?)?;
            if v != this {
                return None;
            }
            Some(ThisCall {
                callee: g.address,
                callee_name: g.name,
                this_offset: off,
            })
        })
        .collect()
}

fn gxx_available() -> bool {
    Command::new("g++")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn ctor() {
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
            // fail for thunks/imports -- skip those. Keep only functions that install at
            // least one vtable, with their this-arg calls, for the assertions below.
            let eas: Vec<_> = idb.functions().map(|f| (f.address(), f.name())).collect();
            let mut analyzed = Vec::new();
            for (address, name) in eas {
                // One-shot decompile + extract: this test only wants the owned tree.
                let Ok(tree) = idb.ctree(address) else {
                    continue;
                };
                let installs = vtable_installs(&tree);
                if installs.is_empty() {
                    continue;
                }
                let calls = this_arg_calls(&tree);
                analyzed.push((name.into_string(), installs, calls));
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
        .unwrap_or_else(|e| e.resume());
    })
    .expect("kernel init failed");

    // Best-effort cleanup: the temp binary and the database IDA wrote next to it.
    let _ = std::fs::remove_file(&bin);
    let _ = std::fs::remove_file(bin.with_extension("i64"));
}
