//! Write path against a real database: comment round-trip (set then read back on both
//! channels) and byte patching (patch then read back), plus the unmapped-address
//! rejection. Closes with `save = false`, so the `.i64` on disk is never touched.

mod common;

use idakit::{Ea, Error};

#[test]
fn write() {
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

fn run(idb: &mut idakit::Idb, db: &str) {
    idb.open(db).call().expect("open failed");

    let ea = idb.functions().next().expect("a function").ea();

    comment_round_trips(idb, ea);
    patch_round_trips(idb, ea);
    patch_rejects_unmapped(idb);

    idb.close(false);
    println!("write OK: comment round-trip, patch round-trip, unmapped patch rejected");
}

/// A regular and a repeatable comment set on `ea` read back verbatim on their own channels.
fn comment_round_trips(idb: &mut idakit::Idb, ea: Ea) {
    idb.set_comment(ea, "idakit regular", false)
        .expect("set regular comment");
    idb.set_comment(ea, "idakit repeatable", true)
        .expect("set repeatable comment");

    assert!(idb.comment(ea, false).as_deref() == Some("idakit regular"));
    assert!(idb.comment(ea, true).as_deref() == Some("idakit repeatable"));
    // The two channels are independent -- reading one never returns the other.
    assert!(
        idb.comment(ea, false) != idb.comment(ea, true),
        "regular and repeatable channels should be distinct"
    );
}

/// Patching bytes is visible to a read-back, and restoring returns the originals.
fn patch_round_trips(idb: &mut idakit::Idb, ea: Ea) {
    let original = idb.bytes(ea, 4);
    assert!(original.len() == 4, "need 4 readable bytes at the entry");

    // Bitwise-not is guaranteed to differ from the original in every byte.
    let flipped: Vec<u8> = original.iter().map(|b| !b).collect();
    idb.patch(ea, &flipped).expect("patch failed");
    assert!(
        idb.bytes(ea, 4) == flipped,
        "read-back should show patched bytes"
    );

    idb.patch(ea, &original).expect("restore failed");
    assert!(
        idb.bytes(ea, 4) == original,
        "restore should return the originals"
    );
}

/// A patch targeting an unmapped address is rejected whole, as a typed `WriteRejected`.
fn patch_rejects_unmapped(idb: &mut idakit::Idb) {
    let nowhere = Ea::new_const(0xffff_ffff_f000);
    let r = idb.patch(nowhere, &[0x90, 0x90]);
    assert!(
        matches!(r, Err(Error::WriteRejected { op: "patch", .. })),
        "unmapped patch should be WriteRejected, got {r:?}"
    );
}
