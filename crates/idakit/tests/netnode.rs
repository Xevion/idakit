//! End-to-end netnode cycle against a real database: create, write every array, read back,
//! iterate, then clear and kill.
//!
//! A normal `#[test]` on the kernel thread `Ida::run` spawns, serialized by the nextest
//! `serial-kernel` group. It only creates a `"$ "`-prefixed user node and never saves, so the
//! fixture is untouched on disk. Skips when no corpus is configured.

mod common;

use assert2::assert;

#[test]
fn netnode_roundtrip() {
    common::with_canonical_db(run);
}

#[cfg(feature = "serde")]
#[test]
fn netnode_serde_roundtrip() {
    common::with_canonical_db(serde_run);
}

#[cfg(feature = "serde")]
fn serde_run(idb: &mut idakit::Database) {
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

#[test]
fn netnode_tag_view() {
    common::with_canonical_db(tag_run);
}

fn tag_run(idb: &mut idakit::Database) {
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

#[test]
fn netnode_boundary_alt() {
    common::with_canonical_db(boundary_alt_run);
}

/// The alt array's boundary indices (`0`, `u64::MAX`) both store and read back.
fn boundary_alt_run(idb: &mut idakit::Database) {
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
    println!("netnode boundary alt OK");
}

#[test]
fn netnode_boundary_sup() {
    common::with_canonical_db(boundary_sup_run);
}

/// The sup array's boundary indices (`0`, `u64::MAX`) both store and read back.
fn boundary_sup_run(idb: &mut idakit::Database) {
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
    println!("netnode boundary sup OK");
}

#[test]
fn netnode_empty_value_is_rejected() {
    common::with_canonical_db(empty_value_run);
}

/// Every byte-valued setter rejects an empty value rather than reaching the kernel.
///
/// The SDK's `set`/`supset`/`hashset` read a `length` of 0 as "measure the value with strlen",
/// so an empty slice would hand them a dangling pointer to walk, and no length stores zero
/// bytes at all. Rejecting keeps the unstorable case out of the kernel and off the niche that
/// separates an unset slot from a present one.
fn empty_value_run(idb: &mut idakit::Database) {
    let name = "$ idakit.netnode.boundary.empty";
    let mut node = idb.netnode_mut(name);

    assert!(
        node.set_sup(1, b"").is_err(),
        "an empty sup value is unstorable"
    );
    assert!(
        node.sup(1).is_none(),
        "the rejected sup write left no value"
    );

    assert!(
        node.set_hash("k", b"").is_err(),
        "an empty hash value is unstorable"
    );
    assert!(
        node.hash("k").is_none(),
        "the rejected hash write left no value"
    );

    assert!(
        node.set_value(b"").is_err(),
        "an empty node value is unstorable"
    );
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
    println!("netnode empty value rejection OK");
}

#[test]
fn netnode_large_blob() {
    common::with_canonical_db(large_blob_run);
}

/// A 64 KiB blob, well past the 1024-byte cap that binds the hash/sup arrays, round-trips
/// exactly, proving blobs are genuinely unbounded rather than sharing that cap.
fn large_blob_run(idb: &mut idakit::Database) {
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
    println!("netnode large blob OK");
}

fn run(idb: &mut idakit::Database) {
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

    // Iterators enumerate exactly the populated entries, in order.
    let alts: Vec<(u64, u64)> = node.alts().collect();
    assert!(alts == vec![(1, 111), (2, 222)]);
    let sups: Vec<(u64, Vec<u8>)> = node.sups().collect();
    assert!(sups == vec![(0, b"sup-zero".to_vec())]);
    let keys: Vec<String> = node.hash_entries().map(|(k, _)| k).collect();
    assert!(keys.len() == 4, "four hash keys, got {keys:?}");
    assert!(
        keys.windows(2).all(|w| w[0] <= w[1]),
        "hash keys iterate lexically"
    );

    // The node appears in the whole-database enumeration.
    assert!(
        idb.netnodes().any(|n| n.id() == id),
        "created node appears in netnodes()"
    );

    // Remove, clear, and kill through a fresh cursor.
    {
        let mut node = idb.netnode_mut(name);
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

    println!("netnode roundtrip OK");
}
