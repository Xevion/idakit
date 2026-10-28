//! Comment round-trip (set then read back on both channels) and byte patching (patch then read
//! back), plus the unmapped-address rejection.

use assert2::assert;
use idakit::prelude::*;
use idakit_runner_macros::kernel_test;

/// A regular and a repeatable comment set on `address` read back verbatim on their own channels,
/// read through the same write cursor (the cursor is read-capable).
#[kernel_test]
fn comment_round_trips() {
    crate::common::with_canonical_db(|idb| {
        let address = idb.functions().next().expect("a function").address();
        let mut loc = idb.at_mut(address);
        loc.set_comment("idakit regular", false)
            .expect("set regular comment");
        loc.set_comment("idakit repeatable", true)
            .expect("set repeatable comment");

        assert!(loc.comment().as_deref() == Some("idakit regular"));
        assert!(loc.repeatable_comment().as_deref() == Some("idakit repeatable"));
        // The two channels are independent, so reading one never returns the other.
        assert!(
            loc.comment() != loc.repeatable_comment(),
            "regular and repeatable channels should be distinct"
        );
    });
}

/// Patching bytes is visible to a read-back on the same cursor, and restoring returns the originals.
#[kernel_test]
fn patch_round_trips() {
    crate::common::with_canonical_db(|idb| {
        let address = idb.functions().next().expect("a function").address();
        let original = idb.at(address).bytes(4);
        assert!(original.len() == 4, "need 4 readable bytes at the entry");

        // Bitwise-not is guaranteed to differ from the original in every byte.
        let flipped: Vec<u8> = original.iter().map(|b| !b).collect();
        let mut loc = idb.at_mut(address);
        loc.patch(&flipped).expect("patch failed");
        assert!(
            loc.bytes(4) == flipped,
            "read-back should show patched bytes"
        );

        loc.patch(&original).expect("restore failed");
        assert!(
            loc.bytes(4) == original,
            "restore should return the originals"
        );
    });
}

/// A patch targeting an unmapped address is rejected whole, as a typed `WriteRejected`.
#[kernel_test]
fn patch_rejects_unmapped() {
    crate::common::with_canonical_db(|idb| {
        let nowhere = Address::new_const(0xffff_ffff_f000);
        let r = idb.at_mut(nowhere).patch(&[0x90, 0x90]);
        assert!(let Err(Error::WriteRejected { op: "patch", .. }) = r);
    });
}

/// A plain rename onto a taken name is rejected, while `FORCE` takes a suffixed variant instead.
#[kernel_test]
fn rename_force_resolves_a_taken_name() {
    crate::common::with_canonical_db(|idb| {
        let mut entries = idb.functions().map(|f| f.address());
        let first = entries.next().expect("a function");
        let second = entries.next().expect("a second function");
        drop(entries);

        let taken = "idakit_rename_force_probe";
        idb.at_mut(first).rename(taken).expect("first rename");

        let plain = idb.at_mut(second).rename_with(taken, RenameFlags::NO_WARN);
        assert!(let Err(Error::WriteRejected { op: "rename", .. }) = plain);

        idb.at_mut(second)
            .rename_with(taken, RenameFlags::NO_WARN | RenameFlags::FORCE)
            .expect("forced rename");
        let name = idb.function(second).name();
        assert!(name.as_str() != taken && name.as_str().starts_with(taken));
    });
}
