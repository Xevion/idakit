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
