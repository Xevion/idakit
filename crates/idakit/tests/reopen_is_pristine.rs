//! Regression guard: `close(false)` followed by reopening the same working copy is a clean reset.
//!
//! Opening a `.i64` unpacks sidecar files (`.id0`/`.id1`/`.id2`/`.nam`/`.til`) next to it, and
//! `close(false)` deletes them rather than merely skipping the write, so a mutation living only
//! in a sidecar cannot survive into the next open. The `.i64` container itself is never touched.
//! Any harness that resets between mutating cases this way, instead of re-copying the fixture,
//! rests on that.

mod common;

use assert2::assert;
use idakit::prelude::*;

use common::TestDb;

#[test]
fn reopen_after_close_is_pristine() {
    let Some(db) = TestDb::acquire() else {
        println!("skipping: no corpus configured");
        return;
    };
    let path = db.path().to_owned();

    Ida::run(move |ida| {
        ida.call(move |idb| run(idb, &path))
            .unwrap_or_else(|e| e.resume());
    })
    .expect("kernel init failed");
}

fn run(idb: &mut Database, path: &str) {
    idb.open(path).call().expect("open failed");

    let type_name = "idakit_reopen_probe_t";
    idb.types_mut()
        .define(format!("struct {type_name} {{ int x; }};"))
        .expect("define probe type");
    assert!(
        idb.type_named(type_name).is_ok(),
        "probe type should resolve right after define"
    );

    let address = idb.functions().next().expect("a function").address();
    let renamed = "idakit_reopen_probe_renamed";
    idb.at_mut(address).rename(renamed).expect("rename failed");
    assert!(
        idb.function(address).name().as_str() == renamed,
        "rename should have taken right after the write"
    );

    idb.close(false);
    idb.open(path).call().expect("reopen failed");

    assert!(
        idb.type_named(type_name).is_err(),
        "a defined type must not survive close(false) + reopen for the reset to be clean"
    );
    assert!(
        idb.function(address).name().as_str() != renamed,
        "a rename must not survive close(false) + reopen for the reset to be clean"
    );

    idb.close(false);
    println!("reopen is pristine OK");
}
