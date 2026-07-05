//! Control-flow graph against a real database: a multi-block function builds a sound graph
//! (every block is a non-empty range, internal edges reference valid blocks and mirror as
//! predecessors, out-of-function exits point outside the graph), block lookup and per-block
//! instruction walking agree with the block ranges, the build knobs behave, and a
//! non-function address is rejected. Read-only; opens `save = false`.
//!
//! `BlockKind`/flag composition is unit-tested (kernel-free) in `cfg.rs`; this covers the
//! parts that need a live kernel. Skips when no test database is present.

mod common;

use idakit::{Cfg, Ea, Error, Idb};

#[test]
fn cfg() {
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

fn run(idb: &mut Idb, db: &str) {
    idb.open(db).call().expect("open failed");

    let cfg = first_multiblock_cfg(idb).expect("a function with at least two basic blocks");
    structure_is_sound(&cfg);
    entry_and_lookup(&cfg);
    instructions_walk_the_entry_block(idb, &cfg);
    exits_leave_the_function(idb);
    knobs_behave(idb, cfg.func());
    non_function_is_rejected(idb);

    // Cfg is an owned snapshot -- it holds no borrow of `idb`, so the &mut close needs no
    // drop dance (unlike a Pattern).
    idb.close(false);
    println!(
        "cfg OK: {} blocks, edges sound and symmetric, exits + knobs + NoFunction verified",
        cfg.len()
    );
}

/// The first function (scanning a bounded prefix) whose CFG has two or more blocks -- enough
/// to exercise edges. Single-block leaf functions are common, so a scan is needed.
fn first_multiblock_cfg(idb: &Idb) -> Option<Cfg> {
    idb.functions().take(4000).find_map(|f| {
        let cfg = f.cfg().ok()?;
        (cfg.len() >= 2).then_some(cfg)
    })
}

/// Every block is a non-empty range; every internal edge endpoint is a valid handle; every
/// exit points outside the graph; and -- since internal successors are the only block-to-block
/// edges -- A -> B as a successor implies A is one of B's predecessors.
fn structure_is_sound(cfg: &Cfg) {
    for (id, b) in cfg.blocks() {
        assert!(b.end() > b.start(), "every block spans a non-empty range");
        for &s in b.successors() {
            assert!(s.index() < cfg.len(), "successor handle in range");
            assert!(
                cfg.block(s).predecessors().contains(&id),
                "edge {:?} -> {:?} is not mirrored in predecessors",
                id.index(),
                s.index()
            );
        }
        for &p in b.predecessors() {
            assert!(p.index() < cfg.len(), "predecessor handle in range");
        }
        for e in b.exits() {
            assert!(
                cfg.block_at(e.target).is_none(),
                "exit target {:#x} lies in no block of the graph",
                e.target
            );
        }
    }
}

/// The entry is block 0, `block_at` resolves an address inside it back to it, and an address
/// below every block resolves to nothing.
fn entry_and_lookup(cfg: &Cfg) {
    let entry = cfg.entry();
    assert!(entry.index() == 0, "the entry is block 0");

    let start = cfg.block(entry).start();
    assert!(
        cfg.block_at(start) == Some(entry),
        "block_at should map the entry's start to the entry block"
    );

    // Address 0 is below any real code segment here, so it lies in no block.
    if start > Ea::new_const(0) {
        assert!(
            cfg.block_at(Ea::new_const(0)).is_none(),
            "block_at should miss an address outside every block"
        );
    }
}

/// Walking the entry block's range decodes at least its first instruction, and every decoded
/// instruction stays within the block.
fn instructions_walk_the_entry_block(idb: &Idb, cfg: &Cfg) {
    let entry = cfg.block(cfg.entry());
    let insns: Vec<_> = idb.instructions_in(entry.range()).collect();

    assert!(!insns.is_empty(), "the entry block decodes an instruction");
    assert!(
        insns[0].ea == entry.start(),
        "the first instruction sits at the block start"
    );
    for insn in &insns {
        assert!(
            insn.ea >= entry.start() && insn.ea < entry.end(),
            "instruction {:#x} escapes the block range",
            insn.ea
        );
    }
}

/// The first function (over a bounded prefix) that transfers out of itself: every exit target
/// resolves to an address in no block of the graph, so lifting external stubs to edges kept
/// them addressable and out-of-graph. External stubs are common but not universal, so a scan
/// is needed; skip if the prefix has none.
fn exits_leave_the_function(idb: &Idb) {
    let found = idb.functions().take(4000).find_map(|f| {
        let cfg = f.cfg().ok()?;
        let has_exit = cfg.blocks().any(|(_, b)| !b.exits().is_empty());
        has_exit.then_some(cfg)
    });
    let Some(cfg) = found else {
        println!("cfg: no function with an external exit in the prefix; skipping the exit check");
        return;
    };
    let exits: usize = cfg.blocks().map(|(_, b)| b.exits().len()).sum();
    for (_, b) in cfg.blocks() {
        for e in b.exits() {
            assert!(
                cfg.block_at(e.target).is_none(),
                "exit target {:#x} should lie outside every block",
                e.target
            );
        }
    }
    println!("cfg: verified {exits} external exit(s) leave the function");
}

/// `call_ends` only ever splits more blocks, `externals(false)` drops every out-of-function
/// exit, and `predecessors(false)` leaves predecessor lists empty.
fn knobs_behave(idb: &Idb, func: Ea) {
    let base = idb.cfg(func).expect("base cfg");

    let split = idb
        .func(func)
        .cfg_with()
        .call_ends(true)
        .call()
        .expect("call-ends cfg");
    assert!(
        split.len() >= base.len(),
        "call_ends splits more (or equal) blocks: {} < {}",
        split.len(),
        base.len()
    );

    let no_ext = idb
        .func(func)
        .cfg_with()
        .externals(false)
        .call()
        .expect("no-externals cfg");
    assert!(
        no_ext.blocks().all(|(_, b)| b.exits().is_empty()),
        "externals(false) records no exits"
    );

    let no_preds = idb
        .func(func)
        .cfg_with()
        .predecessors(false)
        .call()
        .expect("no-preds cfg");
    assert!(
        no_preds.blocks().all(|(_, b)| b.predecessors().is_empty()),
        "predecessors(false) leaves every predecessor list empty"
    );
}

/// Building a CFG at an address in no function returns `NoFunction`.
fn non_function_is_rejected(idb: &Idb) {
    // A non-executable segment's start is mapped but belongs to no function.
    let Some(start) = idb
        .segments()
        .find(|s| !s.is_executable())
        .and_then(|s| s.start())
    else {
        println!("cfg: no non-executable segment; skipping the NoFunction check");
        return;
    };
    let r = idb.cfg(start);
    assert!(
        matches!(r, Err(Error::NoFunction { .. })),
        "a non-function address should be NoFunction, got {r:?}"
    );
}
