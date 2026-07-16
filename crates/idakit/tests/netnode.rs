//! End-to-end netnode cycle against a real database: create, write every array, read back,
//! iterate, then clear and kill.
//!
//! A normal `#[test]` on the kernel thread `Ida::run` spawns, serialized by the nextest
//! `serial-kernel` group. It only creates `"$ "`-prefixed user nodes and never saves, so the
//! fixture is untouched on disk. Skips when no corpus is configured.
//!
//! Every case runs in one session: each owns a distinct node name and kills it on the way out,
//! so they never see each other, and kernel bring-up is paid once rather than per case.

mod common;

use assert2::assert;
use idakit::Database;

/// A named case, run against the shared session's database.
type Case = (&'static str, fn(&mut Database));

/// The cases, each independent of every other.
const CASES: &[Case] = &[
    ("roundtrip", roundtrip_run),
    ("tag view", tag_run),
    ("boundary alt", boundary_alt_run),
    ("boundary sup", boundary_sup_run),
    ("empty value rejection", empty_value_run),
    ("oversized value rejection", oversized_value_run),
    ("write rejection", write_rejection_run),
    ("large blob", large_blob_run),
    ("reused validated bytes", reused_bytes_run),
];

#[test]
fn netnode() {
    common::with_canonical_db(run);
}

fn run(idb: &mut Database) {
    for (name, case) in CASES {
        case(idb);
        println!("netnode {name} OK");
    }
    #[cfg(feature = "serde")]
    {
        serde_run(idb);
        println!("netnode serde OK");
    }
}

#[cfg(feature = "serde")]
fn serde_run(idb: &mut Database) {
    let name = "$ idakit.netnode.serde";
    let value: (u32, Vec<String>) = (0xbeef, vec!["a".into(), "b".into()]);

    let id = {
        let mut node = idb.netnode_mut(name);
        node.put_serde("cfg", &value).expect("put_serde"); // hash-backed
        node.put_serde_at(1, &value).expect("put_serde_at"); // blob-backed
        node.id()
    };

    let node = idb.netnode_at(id);
    assert!(node.get_serde::<(u32, Vec<String>)>("cfg").as_ref() == Some(&value));
    assert!(node.get_serde_at::<(u32, Vec<String>)>(1).as_ref() == Some(&value));
    assert!(node.get_serde::<(u32, Vec<String>)>("missing").is_none());

    idb.netnode_mut(name).kill();
}

fn tag_run(idb: &mut Database) {
    use idakit::Tag;
    let name = "$ idakit.netnode.tag";
    let user = Tag::new(b'X');

    let id = {
        let mut node = idb.netnode_mut(name);
        let mut t = node.tag(user);
        t.set_int(1, 111).expect("set_int");
        t.set_value(2, b"data").expect("set_value");
        t.set_hash("k", b"v").expect("set_hash");
        node.id()
    };

    let node = idb.netnode_at(id);
    let t = node.tag(user);
    assert!(t.int(1) == 111);
    assert!(t.value(2).as_deref() == Some(b"data".as_slice()));
    assert!(t.hash("k").as_deref() == Some(b"v".as_slice()));

    // int and value are two views of one numeric array, so both slots enumerate together.
    let indices: Vec<u64> = t.values().map(|(i, _)| i).collect();
    assert!(indices == vec![1, 2]);

    // A different tag is a separate array: the default-tag slot at index 2 is untouched.
    assert!(
        node.sup(2).is_none(),
        "tag 'X' is isolated from the default tag"
    );

    idb.netnode_mut(name).kill();
}

/// The alt array's boundary indices (`0`, `u64::MAX`) both store and read back.
fn boundary_alt_run(idb: &mut Database) {
    let name = "$ idakit.netnode.boundary.alt";
    let mut node = idb.netnode_mut(name);

    node.set_alt(0, 0xAAAA).expect("set_alt at index 0");
    assert!(node.alt(0) == 0xAAAA, "alt at index 0 did not stick");

    node.set_alt(u64::MAX, 0xBBBB).expect("set_alt at u64::MAX");
    assert!(
        node.alt(u64::MAX) == 0xBBBB,
        "alt at index u64::MAX did not stick"
    );

    node.kill();
}

/// The sup array's boundary indices (`0`, `u64::MAX`) both store and read back.
fn boundary_sup_run(idb: &mut Database) {
    let name = "$ idakit.netnode.boundary.sup";
    let mut node = idb.netnode_mut(name);

    node.set_sup(0, b"zero").expect("set_sup at index 0");
    assert!(
        node.sup(0).as_deref() == Some(b"zero".as_slice()),
        "sup at index 0 did not stick"
    );

    node.set_sup(u64::MAX, b"max").expect("set_sup at u64::MAX");
    assert!(
        node.sup(u64::MAX).as_deref() == Some(b"max".as_slice()),
        "sup at index u64::MAX did not stick"
    );

    node.kill();
}

/// Every byte-valued setter rejects an empty value rather than reaching the kernel.
///
/// The SDK's `set`/`supset`/`hashset` read a `length` of 0 as "measure the value with strlen",
/// so an empty slice would hand them a dangling pointer to walk, and no length stores zero
/// bytes at all. Rejecting keeps the unstorable case out of the kernel and off the niche that
/// separates an unset slot from a present one.
fn empty_value_run(idb: &mut Database) {
    use idakit::NetnodeBytesError;
    use idakit::error::Error;

    let name = "$ idakit.netnode.boundary.empty";
    let mut node = idb.netnode_mut(name);

    // The typed variant proves the rejection happened in `NetnodeBytes::try_from`, not the
    // kernel (which would be `Error::WriteRejected`).
    assert!(let Err(Error::InvalidNetnodeBytes { source: NetnodeBytesError::Empty }) = node.set_sup(1, b""));
    assert!(
        node.sup(1).is_none(),
        "the rejected sup write left no value"
    );

    assert!(let Err(Error::InvalidNetnodeBytes { source: NetnodeBytesError::Empty }) = node.set_hash("k", b""));
    assert!(
        node.hash("k").is_none(),
        "the rejected hash write left no value"
    );

    assert!(let Err(Error::InvalidNetnodeBytes { source: NetnodeBytesError::Empty }) = node.set_value(b""));
    assert!(
        node.value().is_none(),
        "the rejected value write left no value"
    );

    // A one-byte value is the smallest the SDK can represent, and it must still round-trip.
    node.set_sup(1, b"\0").expect("set_sup with a single NUL");
    assert!(
        node.sup(1).as_deref() == Some(b"\0".as_slice()),
        "a one-byte sup value did not round-trip"
    );

    node.kill();
}

/// Every byte-valued setter enforces `MAXSPECSIZE` rather than silently truncating.
///
/// An over-cap `supset` returns success while storing only the first `MAXSPECSIZE` bytes, so a
/// caller trusting the `Ok` would silently lose data. idakit rejects the write client-side
/// instead, matching the empty-value guard.
fn oversized_value_run(idb: &mut Database) {
    use idakit::NetnodeBytesError;
    use idakit::error::Error;

    let name = "$ idakit.netnode.boundary.oversized";
    let mut node = idb.netnode_mut(name);

    // Exactly the cap: stores and round-trips in full.
    let at_cap = vec![0x11u8; 1024];
    node.set_sup(0, &at_cap).expect("set_sup at MAXSPECSIZE");
    assert!(
        node.sup(0).as_deref() == Some(at_cap.as_slice()),
        "a value at the cap did not round-trip exactly"
    );

    // One byte over: rejected before the kernel, with the length and cap on the typed error.
    let over_cap = vec![0x22u8; 1025];
    assert!(
        let Err(Error::InvalidNetnodeBytes {
            source: NetnodeBytesError::TooLarge { len: 1025, cap: 1024 },
        }) = node.set_sup(1, &over_cap)
    );
    assert!(
        node.sup(1).is_none(),
        "the rejected sup write left no value"
    );

    // Far over the cap: same rejection.
    let far_over = vec![0x33u8; 4096];
    assert!(
        let Err(Error::InvalidNetnodeBytes {
            source: NetnodeBytesError::TooLarge { len: 4096, cap: 1024 },
        }) = node.set_sup(2, &far_over)
    );
    assert!(
        node.sup(2).is_none(),
        "the rejected sup write left no value"
    );

    // hashset shares the same guard.
    assert!(let Err(Error::InvalidNetnodeBytes { source: NetnodeBytesError::TooLarge { .. } }) = node.set_hash("k", &over_cap));
    assert!(
        node.hash("k").is_none(),
        "the rejected hash write left no value"
    );

    // The node value shares the same guard.
    assert!(let Err(Error::InvalidNetnodeBytes { source: NetnodeBytesError::TooLarge { .. } }) = node.set_value(&over_cap));
    assert!(
        node.value().is_none(),
        "the rejected value write left no value"
    );

    node.kill();
}

/// A kernel-level rejection, unlike the client-side `NetnodeBytes` guard above, surfaces as
/// `Error::WriteRejected` through both `NetnodeMut::checked` and `TaggedNetnodeMut::checked`,
/// which are separate implementations rather than one delegating to the other.
///
/// `netnode::altdel`/`supdel` return `false` when the slot was never set, a deterministic
/// kernel-side rejection reachable with no invalid input.
fn write_rejection_run(idb: &mut Database) {
    use idakit::Tag;
    use idakit::error::Error;

    let name = "$ idakit.netnode.checked";
    let mut node = idb.netnode_mut(name);

    assert!(let Err(Error::WriteRejected { .. }) = node.remove_alt(9_999));

    {
        let mut t = node.tag(Tag::new(b'Z'));
        assert!(let Err(Error::WriteRejected { .. }) = t.remove(9_999));
    }

    node.kill();
}

/// A `NetnodeBytes` validated once is itself accepted back into the setters it exists for, so
/// one validation reuses across several writes instead of re-validating identical bytes.
fn reused_bytes_run(idb: &mut Database) {
    use idakit::NetnodeBytes;

    let name = "$ idakit.netnode.reused_bytes";
    let mut node = idb.netnode_mut(name);

    let bytes = NetnodeBytes::try_from(b"shared".as_slice()).expect("valid bytes");
    node.set_sup(0, bytes).expect("set_sup with a NetnodeBytes");
    node.set_hash("k", bytes)
        .expect("set_hash with the same NetnodeBytes");

    assert!(node.sup(0).as_deref() == Some(b"shared".as_slice()));
    assert!(node.hash("k").as_deref() == Some(b"shared".as_slice()));

    node.kill();
}

/// A 64 KiB blob, well past the 1024-byte cap that binds the hash/sup arrays, round-trips
/// exactly, proving blobs are genuinely unbounded rather than sharing that cap.
fn large_blob_run(idb: &mut Database) {
    let name = "$ idakit.netnode.boundary.blob";
    let mut node = idb.netnode_mut(name);

    let big = vec![0x5Au8; 64 * 1024];
    node.set_blob(&big).expect("set_blob with a 64 KiB value");
    assert!(
        node.blob_size() == big.len(),
        "blob_size disagrees with the blob's actual length"
    );
    assert!(
        node.blob().as_deref() == Some(big.as_slice()),
        "large blob did not round-trip exactly"
    );

    node.kill();
    assert!(idb.netnode(name).is_none(), "node is gone after kill");
}

/// The full cycle: create, write every store, read back, iterate, then clear and kill.
fn roundtrip_run(idb: &mut Database) {
    let name = "$ idakit.netnode.roundtrip";

    // Create the node and populate every store through the write cursor.
    let id = {
        let mut node = idb.netnode_mut(name);
        node.set_value(b"payload").expect("set_value");
        node.set_alt(1, 111).expect("set_alt 1");
        node.set_alt(2, 222).expect("set_alt 2");
        node.set_sup(0, b"sup-zero").expect("set_sup");
        node.set_hash("greeting", b"hi").expect("set_hash");
        node.set_hash_int("count", 7).expect("set_hash_int");
        node.set_blob(&[1, 2, 3, 4, 5]).expect("set_blob");
        node.put::<u64>("typed_u64", &0xdead_beef).expect("put u64");
        node.put::<String>("typed_str", &"idakit".to_string())
            .expect("put str");
        node.id()
    };

    // Reopen by name and by id: both resolve to the same node.
    let node = idb.netnode(name).expect("node exists after creation");
    assert!(node.id() == id);
    assert!(idb.netnode_at(id).name().as_deref() == Some(name));

    // Debug renders the real id and name, not an empty shell.
    let rendered = format!("{node:?}");
    assert!(rendered.contains(&format!("{id:?}")));
    assert!(rendered.contains(name));

    // Scalar reads.
    assert!(node.value().as_deref() == Some(b"payload".as_slice()));
    assert!(node.value_str().as_deref() == Some("payload"));
    assert!(node.alt(1) == 111);
    assert!(node.alt(2) == 222);
    assert!(node.alt(99) == 0, "an unset alt reads as 0");
    assert!(node.sup(0).as_deref() == Some(b"sup-zero".as_slice()));
    assert!(node.sup(1).is_none(), "an unset sup is None");
    assert!(node.hash("greeting").as_deref() == Some(b"hi".as_slice()));
    assert!(node.hash_int("count") == 7);
    assert!(node.blob().as_deref() == Some([1, 2, 3, 4, 5].as_slice()));
    assert!(node.blob_size() == 5);

    // Typed key/value round-trip; a width/type mismatch decodes to None, not a wrong value.
    assert!(node.get::<u64>("typed_u64") == Some(0xdead_beef));
    assert!(node.get::<String>("typed_str") == Some("idakit".to_string()));
    assert!(node.contains("typed_u64"));
    assert!(!node.contains("missing"));
    assert!(
        node.get::<u64>("typed_str").is_none(),
        "a 6-byte string is not a u64"
    );

    // Iterators enumerate exactly the populated entries, in ascending order, checked per item
    // as it's pulled rather than via collect(): a mutant next() that repeats or fabricates an
    // item then fails on that item instead of hanging an unbounded collect() forever.
    let mut alts = node.alts();
    for expected in [(1u64, 111u64), (2, 222)] {
        assert!(alts.next() == Some(expected), "alts item mismatch");
    }
    assert!(alts.next().is_none(), "alts: unexpected extra entry");

    let mut sups = node.sups();
    assert!(
        sups.next() == Some((0u64, b"sup-zero".to_vec())),
        "sups item mismatch"
    );
    assert!(sups.next().is_none(), "sups: unexpected extra entry");

    let mut hash_entries = node.hash_entries();
    for expected_key in ["count", "greeting", "typed_str", "typed_u64"] {
        let (key, _) = hash_entries
            .next()
            .expect("hash_entries: expected another entry");
        assert!(key == expected_key, "hash_entries key mismatch");
    }
    assert!(
        hash_entries.next().is_none(),
        "hash_entries: unexpected extra entry"
    );

    // The node appears in the whole-database enumeration.
    assert!(
        idb.netnodes().any(|n| n.id() == id),
        "created node appears in netnodes()"
    );

    // Remove, clear, and kill through a fresh cursor.
    {
        let mut node = idb.netnode_mut(name);

        // `remove` deletes the typed value `put` stored, not merely reporting success.
        node.put::<u64>("removable", &42).expect("put removable");
        assert!(node.get::<u64>("removable") == Some(42));
        node.remove("removable").expect("remove");
        assert!(
            node.get::<u64>("removable").is_none(),
            "remove did not delete the value"
        );

        node.remove_alt(1).expect("remove_alt");
        assert!(node.alt(1) == 0, "a removed alt reads as 0");
        node.clear_alts().expect("clear_alts");
        assert!(node.alts().next().is_none(), "alts empty after clear");
        node.clear_hash().expect("clear_hash");
        assert!(
            node.hash_entries().next().is_none(),
            "hash empty after clear"
        );
        node.kill();
    }
    assert!(idb.netnode(name).is_none(), "node is gone after kill");
}
