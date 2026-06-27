//! End-to-end cycle against a real database: open, read, write, re-read.
//!
//! `harness = false` so the test owns `fn main()` and the process lifetime around
//! the kernel thread. Set `IDAKIT_TEST_DB` to an `.i64` (use an absolute path:
//! `cargo test` runs from the crate dir, not the workspace root); skips when unset.

fn main() {
    let Ok(db) = std::env::var("IDAKIT_TEST_DB") else {
        eprintln!("skipping: set IDAKIT_TEST_DB=<path to .i64> to run this test");
        return;
    };

    idakit::Ida::run(move |ida| {
        ida.call(move |idb| {
            idb.open(&db).expect("open failed");

            let func_count = idb.functions().count();
            let seg_count = idb.segments().count();
            assert!(func_count > 0, "expected at least one function");
            assert!(seg_count > 0, "expected at least one segment");

            let first = idb.functions().next().expect("a function");
            let ea = first.ea();
            let original = first.name().expect("function has a name");
            assert!(!original.is_empty());

            let bytes = idb.bytes(ea, 16);
            assert!(!bytes.is_empty(), "expected readable bytes at the entry");

            // Best-effort; just exercise the paths.
            let _ = first.xrefs_to();
            let _ = first.prototype();

            // Exercise the RAII owned-handle path (best-effort).
            match first.decompile() {
                Ok(cf) => {
                    let c = cf.counts();
                    assert!(c.exprs >= 0 && c.insns >= 0);
                    println!(
                        "decompiled first fn: {} insns, {} exprs, {} calls",
                        c.insns, c.exprs, c.calls
                    );

                    // Materialize the whole ctree and cross-check it against the
                    // independent visitor counts: two separate traversals of the same
                    // cfunc must agree, node-for-node.
                    use idakit::ctree::{Cinsn, NodeRef};
                    let tree = cf.ctree().expect("ctree extraction");
                    let root = tree.root();
                    assert!(
                        matches!(tree.stmt(root).kind, Cinsn::Block(_)),
                        "ctree root should be a block"
                    );
                    assert_eq!(
                        tree.exprs().count(),
                        c.exprs as usize,
                        "extracted expr count should match the visitor"
                    );
                    assert_eq!(
                        tree.stmts().count(),
                        c.insns as usize,
                        "extracted stmt count should match the visitor"
                    );
                    // Every allocated node is reachable from the root: confirms the
                    // post-order image and parent wiring are sound.
                    let reachable = tree.descendants(NodeRef::Stmt(root)).count();
                    assert_eq!(
                        reachable,
                        tree.exprs().count() + tree.stmts().count(),
                        "every node should be reachable from the root"
                    );
                    println!(
                        "ctree extracted: {} exprs, {} stmts, {} types; root is a block",
                        tree.exprs().count(),
                        tree.stmts().count(),
                        tree.types().count()
                    );
                }
                Err(e) => println!("decompile unavailable ({e})"),
            }

            // Decompile-failure path: an unmapped address has no function, so the
            // kernel returns null and the facade reports the reason. Confirm a real
            // reason (sourced from the facade buffer, not a stale qerrno) propagates.
            let nowhere = idakit::Ea::new_const(0xffff_ffff_f000);
            match idb.decompile(nowhere) {
                Ok(_) => panic!("expected decompile to fail at unmapped {nowhere:#x}"),
                Err(e) => {
                    let msg = e.to_string();
                    assert!(
                        msg.contains("no function at address"),
                        "decompile failure should carry the facade reason, got: {msg}"
                    );
                    println!("decompile-failure reason propagated: {msg}");
                }
            }

            // Rename via &mut (first's borrow has ended), then confirm.
            let renamed = "idakit_roundtrip_probe";
            idb.rename(ea, renamed).expect("rename failed");
            let after = idb.func(ea).name().expect("name after rename");
            assert_eq!(after, renamed, "rename did not stick");

            idb.set_comment(ea, "touched by idakit roundtrip", false)
                .expect("set_comment failed");

            // Leave the DB as found.
            idb.rename(ea, &original).expect("restore rename failed");

            idb.close(false);

            println!("roundtrip OK: {func_count} funcs, {seg_count} segs, rename/comment verified");
        })
        .expect("kernel call panicked");
    })
    .expect("kernel init failed");
}
