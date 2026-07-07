//! Auto-analyzes a binary and dumps the ctree of matching functions, IDA's own pseudocode
//! beside our owned-tree render.
//!
//! A development lens for seeing the real node shapes the decompiler produces (e.g. how a
//! constructor installs a vtable).
//!
//!   cargo run -p idakit --example ctree_dump -- <binary> [name-substring]

use idakit::prelude::*;

/// Recursively prints each node's kind, indented by depth.
///
/// The structural ground truth behind the render.
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
    let mut args = std::env::args().skip(1);
    let bin = args
        .next()
        .expect("usage: ctree_dump <binary> [name-substring]");
    let filter = args.next().unwrap_or_default();

    Ida::run(move |ida| -> Result<(), Error> {
        ida.call(move |idb| -> Result<(), Error> {
            idb.open(&bin).run_auto(true).call()?;

            let mut matched = 0;
            let eas: Vec<_> = idb.functions().map(|f| (f.address(), f.name())).collect();
            for (address, name) in eas {
                let name = String::from(name);
                if !filter.is_empty() && !name.contains(&filter) {
                    continue;
                }
                let Ok(cf) = idb.decompile(address) else {
                    continue;
                };
                let Ok(tree) = cf.ctree() else { continue };
                matched += 1;
                println!("\n========== {name}  @ {address:#x} ==========");
                if let Some(pc) = cf.pseudocode() {
                    println!("--- IDA ---\n{pc}");
                }
                println!("--- idakit ---\n{}", tree.to_pseudocode());
                println!("--- structure ---");
                dump(
                    &tree,
                    idakit::decompiler::ctree::NodeRef::Statement(tree.root()),
                    0,
                );
            }
            println!("\n[ctree_dump] {matched} function(s) matched filter {filter:?}");

            idb.close(false);
            Ok(())
        })?
    })??;

    Ok(())
}
