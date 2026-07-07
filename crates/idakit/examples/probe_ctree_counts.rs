//! Find the first function whose extracted ctree expression count disagrees with the
//! Hex-Rays visitor count, then dump its structure. Diagnostic for the ARM64 extraction
//! discrepancy.
//!
//!   cargo run -p idakit --example probe_ctree_counts -- <db-copy.i64>

use idakit::prelude::*;

fn dump(
    tree: &idakit::decompiler::ctree::Ctree,
    node: idakit::decompiler::ctree::NodeRef,
    depth: usize,
) {
    use idakit::decompiler::ctree::NodeRef;
    let pad = "  ".repeat(depth);
    let label = match node {
        NodeRef::Expression(id) => format!("{:?}", tree.kind(id)),
        NodeRef::Statement(id) => format!("{:?}", tree.statement_kind(id)),
    };
    let line: String = label
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(90)
        .collect();
    println!("{pad}{line}");
    for c in tree.children(node) {
        dump(tree, c, depth + 1);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bin = std::env::args()
        .nth(1)
        .expect("usage: probe_ctree_counts <db.i64>");

    Ida::run(move |ida| -> Result<(), Error> {
        ida.call(move |idb| -> Result<(), Error> {
            idb.open(&bin).run_auto(false).call()?;

            let eas: Vec<_> = idb
                .functions()
                .map(|f| (f.address(), String::from(f.name())))
                .collect();
            let mut checked = 0usize;
            let mut mismatches = 0usize;
            let mut first_dumped = false;
            for (address, name) in eas {
                let Ok(cf) = idb.decompile(address) else {
                    continue;
                };
                let Ok(tree) = cf.ctree() else { continue };
                checked += 1;
                let (visitor_total, expected) = cf.expr_extraction_expectation();
                let extracted = tree.expressions().count() as i32;
                if extracted != expected {
                    mismatches += 1;
                    println!(
                        "MISMATCH {name} @ {address:#x}: extracted={extracted} expected={expected} \
                         visitor={visitor_total} (elided empties {})",
                        visitor_total - expected
                    );
                    if !first_dumped {
                        first_dumped = true;
                        println!("--- idakit render ---\n{}", tree.to_pseudocode());
                        println!("--- structure ---");
                        dump(
                            &tree,
                            idakit::decompiler::ctree::NodeRef::Statement(tree.root()),
                            0,
                        );
                    }
                }
            }
            println!("\n[probe] {checked} decompiled, {mismatches} mismatched");
            idb.close(false);
            Ok(())
        })?
    })??;
    Ok(())
}
