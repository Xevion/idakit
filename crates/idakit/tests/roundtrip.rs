//! End-to-end cycle against a real database: open, read, write, re-read.
//!
//! A normal `#[test]`: the kernel runs on the thread `Ida::run` spawns (8 MiB stack), so no
//! `harness = false`. The nextest `serial-kernel` group serializes it against the other
//! kernel tests. Runs against `IDAKIT_TEST_DB` or `$IDADIR/libida.so.i64` (see
//! [`common::test_db`]); skips when neither is present.

mod common;

#[test]
fn roundtrip() {
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

fn run(idb: &mut idakit::Idb, db: &str) {
    idb.open(db).call().expect("open failed");

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

    // Best-effort; just exercise the paths (consume the lazy xref cursors).
    let _ = first.xrefs_to().count();
    let _ = first.xrefs_from().count();
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
            use idakit::ctree::{Cexpr, Cinsn, NodeRef};
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

            // Round-trip the owned tree back to C-like pseudocode and check it
            // against IDA's own rendering. Exact text won't match (IDA has its own
            // formatting), but every lvar our tree references must appear in IDA's
            // pseudocode: the names come from the same lvar table, so a dropped or
            // misresolved `Var` surfaces here as a missing name.
            let rendered = tree.to_pseudocode();
            if let Some(ida_pc) = cf.pseudocode() {
                let mut referenced: Vec<String> = tree
                    .exprs()
                    .filter_map(|(_, e)| match &e.kind {
                        Cexpr::Var(v) => Some(tree.lvar(*v).name.clone()),
                        _ => None,
                    })
                    .collect();
                referenced.sort();
                referenced.dedup();
                let missing: Vec<&String> = referenced
                    .iter()
                    .filter(|name| !ida_pc.contains(name.as_str()))
                    .collect();
                assert!(
                    missing.is_empty(),
                    "lvar names referenced by the tree but absent from IDA's \
                             pseudocode (extraction dropped or misresolved a Var): {missing:?}"
                );
                println!(
                    "round-trip OK: {} referenced lvars all present in IDA's pseudocode",
                    referenced.len()
                );
                println!("--- idakit render ---\n{rendered}\n--- IDA pseudocode ---\n{ida_pc}");
            } else {
                println!("round-trip: IDA pseudocode unavailable; rendered:\n{rendered}");
            }
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
}
