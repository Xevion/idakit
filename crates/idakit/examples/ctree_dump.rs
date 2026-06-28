//! Auto-analyze a binary and dump the ctree of matching functions: IDA's own
//! pseudocode beside our owned-tree render. A development lens for seeing the real
//! node shapes the decompiler produces (e.g. how a constructor installs a vtable).
//!
//!   cargo run -p idakit --example ctree_dump -- <binary> [name-substring]

/// Recursively print each node's kind, indented by depth — the structural ground truth
/// behind the render.
fn dump(tree: &idakit::ctree::Ctree, node: idakit::ctree::NodeRef, depth: usize) {
    use idakit::ctree::NodeRef;
    let pad = "  ".repeat(depth);
    let label = match node {
        NodeRef::Expr(id) => format!("{:?}", tree.kind(id)),
        NodeRef::Stmt(id) => format!("{:?}", tree.stmt_kind(id)),
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

    idakit::Ida::run(move |ida| -> Result<(), idakit::Error> {
        ida.call(move |idb| -> Result<(), idakit::Error> {
            idb.open(&bin).run_auto(true).call()?;

            let mut matched = 0;
            let eas: Vec<_> = idb.functions().map(|f| (f.ea(), f.name())).collect();
            for (ea, name) in eas {
                let name = name.unwrap_or_default();
                if !filter.is_empty() && !name.contains(&filter) {
                    continue;
                }
                let Ok(cf) = idb.decompile(ea) else { continue };
                let Ok(tree) = cf.ctree() else { continue };
                matched += 1;
                println!("\n========== {name}  @ {ea:#x} ==========");
                if let Some(pc) = cf.pseudocode() {
                    println!("--- IDA ---\n{pc}");
                }
                println!("--- idakit ---\n{}", tree.to_pseudocode());
                println!("--- structure ---");
                dump(&tree, idakit::ctree::NodeRef::Stmt(tree.root()), 0);
            }
            println!("\n[ctree_dump] {matched} function(s) matched filter {filter:?}");

            idb.close(false);
            Ok(())
        })?
    })??;

    Ok(())
}
