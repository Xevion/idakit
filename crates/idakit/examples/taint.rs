//! A non-trivial consumer of the materialized ctree, used as a stress test and a
//! benchmark. For every function in the database it runs a crude intra-procedural
//! taint pass (call-return sources -> lvar def/use fixpoint -> dangerous-call sinks)
//! and times the work in four separate phases:
//!
//!   decompile   — Hex-Rays, kernel thread, serial and unavoidable
//!   extract     — `cfunc.ctree()`, the facade DFS + Rust rebuild, kernel thread
//!   resolve     — turning `Obj(ea)` callees into names, kernel thread (needs `&Idb`)
//!   analyze     — the pure taint pass over the Send image (no kernel access)
//!
//! The split answers the live question: how much of the work is the serial kernel
//! floor (decompile + extract + resolve) versus the part that could ever be fanned
//! out (analyze)? If `analyze` is a rounding error, parallelism buys nothing and we
//! stay sequential. The run also exercises every node kind, so it is where API
//! friction shows up.
//!
//! Run (release matters for the numbers):
//!   cargo run -p idakit --release --example taint -- <db.i64>
//! Cap the sweep with `TAINT_LIMIT=2000` while iterating.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use idakit::ctree::{Cexpr, Ctree, ExprId, LvarId, NodeRef};
use idakit::{Ea, Idb};

/// Calls whose return value introduces taint (matched as a substring of the name).
const SOURCES: &[&str] = &["recv", "read", "fgets", "getenv", "scanf", "gets"];
/// Calls whose arguments are dangerous to feed tainted data into.
const SINKS: &[&str] = &[
    "memcpy", "memmove", "strcpy", "strcat", "sprintf", "system", "malloc", "alloca", "exec",
];

fn matches(name: &str, set: &[&str]) -> bool {
    set.iter().any(|n| name.contains(n))
}

/// A function lifted into a Send-able analysis input. The callee-name map is the
/// telling part: the ctree's `Call` carries only an `Obj(ea)`/`Helper`, so the names
/// every analysis actually keys on have to be resolved *here*, on the kernel thread,
/// and folded in — the bare tree cannot answer "what does this call?" off-thread.
struct FuncImage {
    tree: Ctree,
    /// Call expr -> resolved callee name (only the ones that resolve to a symbol).
    callees: HashMap<ExprId, String>,
}

/// Resolve a call's callee to a name, if it is a direct symbol or a decompiler helper.
/// Indirect calls (through a variable or computed pointer) stay unresolved. Enrichment
/// win: the symbol name now rides on the `Obj` node, so this no longer needs the kernel.
fn callee_name(tree: &Ctree, callee: ExprId) -> Option<String> {
    match &tree.expr(callee).kind {
        Cexpr::Obj { name, .. } => name.clone(),
        Cexpr::Helper(h) => Some(h.clone()),
        _ => None,
    }
}

/// Build the callee-name map for a tree. Now that the tree carries callee names, this is
/// pure (no `Idb`) — the kernel-thread name resolution that used to dominate is gone.
fn resolve_callees(tree: &Ctree) -> HashMap<ExprId, String> {
    let mut map = HashMap::new();
    for (id, node) in tree.exprs() {
        if let Cexpr::Call { callee, .. } = &node.kind
            && let Some(name) = callee_name(tree, *callee)
        {
            map.insert(id, name);
        }
    }
    map
}

/// Does `e`'s subtree read a tainted lvar or call a source directly? Flow-insensitive
/// and deliberately crude — the point is to do real work proportional to tree size.
fn expr_tainted(img: &FuncImage, e: ExprId, tainted: &HashSet<u32>) -> bool {
    img.tree
        .descendants(NodeRef::Expr(e))
        .any(|node| match node {
            NodeRef::Expr(id) => match img.tree.expr(id).kind {
                Cexpr::Var(LvarId(i)) => tainted.contains(&i),
                _ => img.callees.get(&id).is_some_and(|n| matches(n, SOURCES)),
            },
            NodeRef::Stmt(_) => false,
        })
}

/// The pure phase: returns the number of source->sink flows found. No `Idb` access,
/// so this is exactly the work that could move to a worker thread.
fn analyze(img: &FuncImage) -> usize {
    // Collect `Var(i) = rhs` definitions once.
    let defs: Vec<(u32, ExprId)> = img
        .tree
        .exprs()
        .filter_map(|(_, node)| match &node.kind {
            Cexpr::Assign { x, y, .. } => match img.tree.expr(*x).kind {
                Cexpr::Var(LvarId(i)) => Some((i, *y)),
                _ => None,
            },
            _ => None,
        })
        .collect();

    // Fixpoint: an lvar is tainted once any of its defining RHS is tainted.
    let mut tainted: HashSet<u32> = HashSet::new();
    loop {
        let before = tainted.len();
        for &(lv, rhs) in &defs {
            if !tainted.contains(&lv) && expr_tainted(img, rhs, &tainted) {
                tainted.insert(lv);
            }
        }
        if tainted.len() == before {
            break;
        }
    }

    // Sinks: a tainted argument to a dangerous call is a flow.
    img.tree
        .exprs()
        .filter(|(id, node)| {
            let Cexpr::Call { args, .. } = &node.kind else {
                return false;
            };
            img.callees.get(id).is_some_and(|n| matches(n, SINKS))
                && args.iter().any(|a| expr_tainted(img, *a, &tainted))
        })
        .count()
}

#[derive(Default)]
struct Totals {
    decompile: Duration,
    extract: Duration,
    resolve: Duration,
    analyze: Duration,
    funcs: usize,
    decompile_failed: usize,
    extract_failed: usize,
    flows: usize,
    nodes: u64,
}

fn run(idb: &mut Idb, db: &str) -> Result<(), idakit::Error> {
    idb.open(db).call()?;

    let limit = std::env::var("TAINT_LIMIT")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(usize::MAX);

    let eas: Vec<Ea> = idb.functions().map(|f| f.ea()).take(limit).collect();
    println!("[taint] sweeping {} functions", eas.len());

    let mut t = Totals::default();
    let wall = Instant::now();

    for (i, &ea) in eas.iter().enumerate() {
        let started = Instant::now();
        let cf = match idb.decompile(ea) {
            Ok(cf) => cf,
            Err(_) => {
                t.decompile_failed += 1;
                continue;
            }
        };
        t.decompile += started.elapsed();

        let started = Instant::now();
        let tree = match cf.ctree() {
            Ok(tree) => tree,
            Err(_) => {
                t.extract_failed += 1;
                continue;
            }
        };
        t.extract += started.elapsed();

        let started = Instant::now();
        let callees = resolve_callees(&tree);
        t.resolve += started.elapsed();

        t.nodes += (tree.exprs().count() + tree.stmts().count()) as u64;
        let img = FuncImage { tree, callees };

        let started = Instant::now();
        t.flows += analyze(&img);
        t.analyze += started.elapsed();

        t.funcs += 1;
        if (i + 1) % 5000 == 0 {
            println!("[taint] {} / {} ...", i + 1, eas.len());
        }
    }

    report(&t, wall.elapsed());
    idb.close(false);
    Ok(())
}

fn report(t: &Totals, wall: Duration) {
    let kernel = t.decompile + t.extract + t.resolve;
    let pct = |d: Duration| 100.0 * d.as_secs_f64() / wall.as_secs_f64().max(f64::EPSILON);
    let per = |d: Duration| {
        if t.funcs == 0 {
            0.0
        } else {
            d.as_secs_f64() * 1e6 / t.funcs as f64
        }
    };

    println!("\n=== taint sweep ===");
    println!(
        "functions analyzed: {}  (decompile-failed {}, extract-failed {})",
        t.funcs, t.decompile_failed, t.extract_failed
    );
    println!("ctree nodes total:  {}", t.nodes);
    println!("source->sink flows: {}", t.flows);
    println!("wall:               {:.2}s", wall.as_secs_f64());
    println!(
        "  decompile  {:>7.2}s  {:>5.1}%   {:>7.1} us/fn",
        t.decompile.as_secs_f64(),
        pct(t.decompile),
        per(t.decompile)
    );
    println!(
        "  extract    {:>7.2}s  {:>5.1}%   {:>7.1} us/fn",
        t.extract.as_secs_f64(),
        pct(t.extract),
        per(t.extract)
    );
    println!(
        "  resolve    {:>7.2}s  {:>5.1}%   {:>7.1} us/fn",
        t.resolve.as_secs_f64(),
        pct(t.resolve),
        per(t.resolve)
    );
    println!(
        "  analyze    {:>7.2}s  {:>5.1}%   {:>7.1} us/fn   (the only parallelizable part)",
        t.analyze.as_secs_f64(),
        pct(t.analyze),
        per(t.analyze)
    );
    println!(
        "kernel-bound (decompile+extract+resolve): {:.1}% of wall — the serial floor",
        pct(kernel)
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = std::env::args()
        .nth(1)
        .expect("usage: taint <db.i64>  (set TAINT_LIMIT to cap the sweep)");

    idakit::Ida::run(move |ida| -> Result<(), idakit::Error> {
        ida.call(move |idb| run(idb, &db)).expect("kernel call")
    })??;

    Ok(())
}
