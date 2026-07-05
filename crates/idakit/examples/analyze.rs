//! Auto-analyze a raw binary headlessly and report what IDA found -- the inverse of
//! the other examples, which open an already-analyzed `.i64`. This is the path that
//! turns a fixture binary into an analyzed database (IDA writes `<binary>.i64` beside
//! the input), so it doubles as the smoke test for `open(...).run_auto(true)`.
//!
//!   cargo run -p idakit --example analyze -- <path/to/binary>

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bin = std::env::args()
        .nth(1)
        .expect("usage: analyze <path/to/binary>");

    idakit::Ida::run(move |ida| -> Result<(), idakit::Error> {
        ida.call(move |idb| -> Result<(), idakit::Error> {
            idb.open(&bin).run_auto(true).call()?;

            let funcs = idb.functions().count();
            let segs = idb.segments().count();
            println!("analyzed {bin}: {funcs} functions, {segs} segments");
            assert!(funcs > 0, "auto-analysis found no functions");

            // Control-flow shape: over a bounded prefix, find the function with the most
            // basic blocks and summarize its graph (blocks, edges, return blocks) plus the
            // entry block's instruction count via the ranged `instructions_in` walk.
            if let Some((address, cfg)) = idb
                .functions()
                .take(2000)
                .filter_map(|f| f.cfg().ok().map(|c| (f.address(), c)))
                .max_by_key(|(_, c)| c.len())
            {
                let edges: usize = cfg.blocks().map(|(_, b)| b.successors().len()).sum();
                let returns = cfg.blocks().filter(|(_, b)| b.kind().is_return()).count();
                let entry_insns = idb.instructions_in(cfg.block(cfg.entry()).range()).count();
                println!(
                    "largest CFG @ {address:#x}: {} blocks, {edges} edges, {returns} return block(s); \
                     entry block has {entry_insns} instruction(s)",
                    cfg.len()
                );
            }

            idb.close(false);
            Ok(())
        })?
    })??;

    Ok(())
}
