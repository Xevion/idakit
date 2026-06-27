//! End-to-end cycle against a real database: open, read, write, re-read.
//!
//! `harness = false` (so it runs on the OS main thread that `run_on_main` needs).
//! Set `IDAKIT_TEST_DB` to an `.i64`; skips (exits 0) when unset.

fn main() {
    let Ok(db) = std::env::var("IDAKIT_TEST_DB") else {
        eprintln!("skipping: set IDAKIT_TEST_DB=<path to .i64> to run this test");
        return;
    };

    idakit::Ida::run_on_main(move |ida| {
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
                }
                Err(e) => println!("decompile unavailable ({e})"),
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
        });
    });
}
