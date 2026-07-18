//! End-to-end proof of the warm-kernel harness, run through real `cargo nextest`.
//!
//! This binary is its own runner ([`idakit_test::main`]); the test recipe starts its daemon, and
//! nextest's per-case proxies drive the warm children. The cases exercise every fundamental at
//! once: a plain rstest, a parametrized `#[rstest]` (full case expansion and fixture injection over
//! the harness), the heaviest real path (Hex-Rays) inside a forked child, copy-on-write isolation
//! between two sibling children, and daemon-side weighted admission.
//!
//! Every case here passes, so it is safe under a plain `just test`; without a daemon each proxy
//! skips (prints why, exits 0), matching the corpus rule that an absent fixture passes.

use idakit_test::{DbRef, db_ref, kernel_test};
use rstest::{fixture, rstest};

/// The warm database, injected into each rstest case by name.
#[fixture]
fn db() -> DbRef {
    db_ref()
}

/// Plain rstest (no `#[case]`): the enumeration API works against the warm database.
#[rstest]
#[test_attr(idakit_test::register)]
fn func_count_positive(db: DbRef) {
    db.with(|d| {
        let n = d.functions().count();
        assert!(n > 0, "database has no functions");
        println!("{n} functions");
    });
}

/// Parametrized rstest: three `#[case]` rows over a fixture, proving the full rstest engine (case
/// expansion plus fixture injection) rides the harness rather than a subset look-alike.
#[rstest]
#[case::front(0.0)]
#[case::middle(0.5)]
#[case::back(0.99)]
#[test_attr(idakit_test::register)]
fn func_addr_in_range(db: DbRef, #[case] frac: f64) {
    db.with(|d| {
        let n = d.functions().count();
        assert!(n > 0, "no functions");
        let idx = (((n - 1) as f64) * frac) as usize;
        let f = d.functions().nth(idx).expect("nth function in range");
        println!("func[{idx}] @ {:#x}", f.address().get());
    });
}

/// Heaviest real path (Hex-Rays) inside a forked child: decompile the first decompilable function.
#[rstest]
#[test_attr(idakit_test::register)]
fn decompile_first(db: DbRef) {
    db.with(|d| {
        for f in d.functions().take(400) {
            if f.decompile().is_ok() {
                println!("decompiled a function at {:#x}", f.address().get());
                return;
            }
        }
        panic!("decompiled none of the first 400 functions");
    });
}

/// Renames func[0] in this child only; its sibling below must not observe it (copy-on-write fork
/// isolation).
#[kernel_test]
fn rename_isolation() {
    db_ref().with(|d| {
        let addr = d.functions().next().expect("a function").address();
        d.at_mut(addr).rename("RENAMED_BY_SIBLING").expect("rename");
        let got = d.function(addr).name();
        assert_eq!(got.as_str(), "RENAMED_BY_SIBLING", "rename did not take");
        println!("renamed func[0] locally");
    });
}

/// The sibling of [`rename_isolation`]: func[0] still holds its original name, proving the rename
/// stayed in the other child's copy-on-write pages.
#[kernel_test]
fn original_name_intact() {
    db_ref().with(|d| {
        let addr = d.functions().next().expect("a function").address();
        let name = d.function(addr).name();
        assert_ne!(name.as_str(), "RENAMED_BY_SIBLING", "isolation breach");
        println!("func[0] name still {:?}", name.as_str());
    });
}

/// Two heavy cases: with a small token pool they cannot co-run, so the daemon serializes them while
/// light cases pack in around them. Weight is the inline knob nextest lacks.
#[kernel_test(weight = 64)]
fn heavy_decompile_a() {
    let done = decompile_prefix();
    println!("heavy_a decompiled {done} functions");
}

#[kernel_test(weight = 64)]
fn heavy_decompile_b() {
    let done = decompile_prefix();
    println!("heavy_b decompiled {done} functions");
}

/// Decompiles as many of the first 200 functions as Hex-Rays accepts, the shared body of the two
/// heavy weight cases.
fn decompile_prefix() -> usize {
    db_ref().with(|d| {
        d.functions()
            .take(200)
            .filter(|f| f.decompile().is_ok())
            .count()
    })
}

fn main() {
    idakit_test::main();
}
