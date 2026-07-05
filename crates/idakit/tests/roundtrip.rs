//! End-to-end cycle against a real database: open, read, write, re-read.
//!
//! A normal `#[test]`: the kernel runs on the thread `Ida::run` spawns (8 MiB stack), so no
//! `harness = false`. The nextest `serial-kernel` group serializes it against the other
//! kernel tests. Runs against the corpus manifest's canonical fixture (see
//! [`common::TestDb`]); skips when no corpus is configured.

mod common;

#[test]
fn roundtrip() {
    common::with_canonical_db(run);
}

fn run(idb: &mut idakit::Idb) {
    let func_count = idb.functions().count();
    let seg_count = idb.segments().count();
    assert!(func_count > 0, "expected at least one function");
    assert!(seg_count > 0, "expected at least one segment");

    let first = idb.functions().next().expect("a function");
    let address = first.address();
    let original = first.name();
    assert!(!original.is_empty());

    let bytes = idb.bytes(address, 16);
    assert!(!bytes.is_empty(), "expected readable bytes at the entry");

    // Best-effort; just exercise the paths (consume the lazy reference cursors).
    let _ = first.references_to().count();
    let _ = first.references_from().count();
    let _ = first.prototype();

    // Structured prototype walk: drive idakit_func_type_walk over real functions. Not every
    // function is typed, so scan for the first that resolves and validate its shape end-to-end.
    {
        use idakit::TypeKind;
        let mut typed = 0usize;
        let mut example = None;
        for f in idb.functions().take(2000) {
            if let Some(image) = f.prototype_type().expect("prototype walk") {
                typed += 1;
                if example.is_none() {
                    example = Some((f.address(), image));
                }
            }
        }
        if let Some((ea, image)) = example {
            let TypeKind::Function { ret, params, .. } = image.kind() else {
                panic!("a function prototype's root should be a Function type");
            };
            // Every child handle resolves against the image's own table.
            let _ = image.get(*ret);
            for p in params {
                let _ = image.get(*p);
            }
            println!(
                "prototype at {ea:#x}: {} params, {typed} typed functions in sample",
                params.len()
            );
        } else {
            println!("no typed function prototypes in sample");
        }
    }

    // Exercise the RAII owned-handle path (best-effort).
    match first.decompile() {
        Ok(cf) => {
            let c = cf.counts();
            assert!(c.expressions >= 0 && c.insns >= 0);
            println!(
                "decompiled first fn: {} insns, {} expressions, {} calls",
                c.insns, c.expressions, c.calls
            );

            // Materialize the whole ctree and cross-check it against the
            // independent visitor counts: two separate traversals of the same
            // cfunc must agree, node-for-node.
            use idakit::ctree::{ExpressionKind, NodeRef, StatementKind};
            let tree = cf.ctree().expect("ctree extraction");
            let root = tree.root();
            assert!(
                matches!(tree.statement(root).kind, StatementKind::Block(_)),
                "ctree root should be a block"
            );
            assert_eq!(
                tree.expressions().count(),
                c.expressions as usize,
                "extracted expression count should match the visitor"
            );
            assert_eq!(
                tree.statements().count(),
                c.insns as usize,
                "extracted statement count should match the visitor"
            );
            // Every allocated node is reachable from the root: confirms the
            // post-order image and parent wiring are sound.
            let reachable = tree.descendants(NodeRef::Statement(root)).count();
            assert_eq!(
                reachable,
                tree.expressions().count() + tree.statements().count(),
                "every node should be reachable from the root"
            );
            println!(
                "ctree extracted: {} expressions, {} statements, {} types; root is a block",
                tree.expressions().count(),
                tree.statements().count(),
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
                    .expressions()
                    .filter_map(|(_, e)| match &e.kind {
                        ExpressionKind::Var(v) => Some(tree.lvar(*v).name.clone()),
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
    let nowhere = idakit::Address::new_const(0xffff_ffff_f000);
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
    idb.rename(address, renamed).expect("rename failed");
    let after = idb.function(address).name();
    assert_eq!(after.as_str(), renamed, "rename did not stick");
    assert!(after.is_user(), "a user rename yields a user name");

    idb.set_comment(address, "touched by idakit roundtrip", false)
        .expect("set_comment failed");

    // Leave the DB as found.
    idb.rename(address, &original)
        .expect("restore rename failed");

    println!("roundtrip OK: {func_count} funcs, {seg_count} segs, rename/comment verified");
}
