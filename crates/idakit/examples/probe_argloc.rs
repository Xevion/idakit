//! Tally decompiled-local `LocalLocation` variants across a database, printing the histogram and
//! a few example scattered/pair locations. Verifies which argloc variants a fixture exercises.
//!
//!   `cargo run -p idakit --example probe_argloc -- <db.i64> [max-funcs]`

use idakit::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use idakit::decompiler::ctree::LocalLocation as L;
    let mut args = std::env::args().skip(1);
    let bin = args
        .next()
        .expect("usage: probe_argloc <db.i64> [max-funcs]");
    let max: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(2000);

    Ida::run(move |ida| -> Result<(), Error> {
        ida.call(move |idb| -> Result<(), Error> {
            idb.open(&bin).run_auto(false).call()?;

            let mut n = [0usize; 8];
            let mut decompiled = 0usize;
            let mut examples: Vec<String> = Vec::new();
            let eas: Vec<_> = idb.functions().take(max).map(|f| f.address()).collect();
            for ea in eas {
                let Ok(cf) = idb.decompile(ea) else { continue };
                let Ok(tree) = cf.ctree() else { continue };
                decompiled += 1;
                for lv in tree.locals() {
                    let i = match &lv.location {
                        L::Register(_) => 0,
                        L::RegisterPair { .. } => 1,
                        L::Stack(_) => 2,
                        L::RegisterRelative { .. } => 3,
                        L::Static(_) => 4,
                        L::Scattered(_) => 5,
                        L::Custom => 6,
                        L::Unallocated => 7,
                    };
                    n[i] += 1;
                    if matches!(lv.location, L::Scattered(_) | L::RegisterPair { .. } | L::RegisterRelative { .. })
                        && examples.len() < 12
                    {
                        examples.push(format!("  {} {:?} = {:?}", lv.name, lv.width, lv.location));
                    }
                }
            }
            println!(
                "{decompiled} fns | reg={} pair={} stack={} rrel={} static={} scatter={} custom={} none={}",
                n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7]
            );
            if !examples.is_empty() {
                println!("rich-variant examples:");
                for e in &examples {
                    println!("{e}");
                }
            }
            idb.close(false);
            Ok(())
        })?
    })??;
    Ok(())
}
