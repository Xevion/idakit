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

use std::cell::RefCell;
use std::collections::BTreeMap;

use assert2::assert;
use idakit::Database;
use idakit::netnode::NetnodeMut;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

/// A named case, run against the shared session's database.
type Case = (&'static str, fn(&mut Database));

/// The cases, each independent of every other.
const CASES: &[Case] = &[
    ("roundtrip", roundtrip_run),
    ("tag view", tag_run),
    ("boundary altval", boundary_altval_run),
    ("boundary supval", boundary_supval_run),
    ("empty value rejection", empty_value_run),
    ("oversized value rejection", oversized_value_run),
    ("write rejection", write_rejection_run),
    ("large blob", large_blob_run),
    ("reused validated bytes", reused_bytes_run),
    ("deletion ops", deletion_run),
    ("tagged deletion ops", tagged_deletion_run),
    ("model", model_run),
];

/// Altval/supval indices the model generates over. Small, so overwrites and deletes collide often.
const INDICES: u64 = 4;
/// Hash keys the model generates over, kept equally small and in lexical order.
const KEYS: [&str; 3] = ["a", "b", "c"];

/// One generated write against the default tag.
#[derive(Debug, Clone)]
enum Op {
    SetValue(Vec<u8>),
    ClearValue,
    SetAltval(u64, u64),
    RemoveAltval(u64),
    ClearAltvals,
    SetSupval(u64, Vec<u8>),
    RemoveSupval(u64),
    ClearSupvals,
    SetHash(String, Vec<u8>),
    SetHashInteger(String, u64),
    RemoveHash(String),
    ClearHash,
    SetBlob(Vec<u8>),
    RemoveBlob,
}

/// The netnode state a reader can observe, tracked alongside the real node.
///
/// An altval present with value `0` is deliberately distinct from an absent one: `altset` stores
/// an object, so the slot enumerates, while `altval` reads `0` either way.
#[derive(Default)]
struct Model {
    value: Option<Vec<u8>>,
    altvals: BTreeMap<u64, u64>,
    supvals: BTreeMap<u64, Vec<u8>>,
    hash: BTreeMap<String, Vec<u8>>,
    blob: Option<Vec<u8>>,
}

impl Model {
    /// Apply `op` and predict the kernel's answer: a setter reports whether it succeeded, a delete
    /// reports whether there was anything there to remove.
    fn apply(&mut self, op: &Op) -> bool {
        match op {
            Op::SetValue(v) => {
                self.value = Some(v.clone());
                true
            }
            Op::ClearValue => self.value.take().is_some(),
            Op::SetAltval(i, v) => {
                self.altvals.insert(*i, *v);
                true
            }
            Op::RemoveAltval(i) => self.altvals.remove(i).is_some(),
            Op::ClearAltvals => {
                let had = !self.altvals.is_empty();
                self.altvals.clear();
                had
            }
            Op::SetSupval(i, v) => {
                self.supvals.insert(*i, v.clone());
                true
            }
            Op::RemoveSupval(i) => self.supvals.remove(i).is_some(),
            Op::ClearSupvals => {
                let had = !self.supvals.is_empty();
                self.supvals.clear();
                had
            }
            Op::SetHash(k, v) => {
                self.hash.insert(k.clone(), v.clone());
                true
            }
            // The integer setter is `hashset(idx, &value, sizeof(value))`, so it lands in the same
            // array as the byte setter, as the host's 8 raw bytes.
            Op::SetHashInteger(k, v) => {
                self.hash.insert(k.clone(), v.to_le_bytes().to_vec());
                true
            }
            Op::RemoveHash(k) => self.hash.remove(k).is_some(),
            Op::ClearHash => {
                let had = !self.hash.is_empty();
                self.hash.clear();
                had
            }
            Op::SetBlob(v) => {
                self.blob = Some(v.clone());
                true
            }
            Op::RemoveBlob => self.blob.take().is_some(),
        }
    }
}

fn op_strategy() -> impl Strategy<Value = Op> {
    let index = 0..INDICES;
    let key = (0..KEYS.len()).prop_map(|i| KEYS[i].to_string());
    // Never empty and never over MAXSPECSIZE: both are rejected before the kernel by
    // `NetnodeBytes`, and the client-side guard has its own cases above.
    let bytes = prop::collection::vec(any::<u8>(), 1..=8);
    prop_oneof![
        bytes.clone().prop_map(Op::SetValue),
        Just(Op::ClearValue),
        (index.clone(), any::<u64>()).prop_map(|(i, v)| Op::SetAltval(i, v)),
        index.clone().prop_map(Op::RemoveAltval),
        Just(Op::ClearAltvals),
        (index.clone(), bytes.clone()).prop_map(|(i, v)| Op::SetSupval(i, v)),
        index.prop_map(Op::RemoveSupval),
        Just(Op::ClearSupvals),
        (key.clone(), bytes.clone()).prop_map(|(k, v)| Op::SetHash(k, v)),
        (key.clone(), any::<u64>()).prop_map(|(k, v)| Op::SetHashInteger(k, v)),
        key.prop_map(Op::RemoveHash),
        Just(Op::ClearHash),
        bytes.prop_map(Op::SetBlob),
        Just(Op::RemoveBlob),
    ]
}

/// Run `op` against the real node, reducing both shapes to the one bit the model predicts.
fn apply_real(node: &mut NetnodeMut<'_>, op: &Op) -> bool {
    match op {
        Op::SetValue(v) => node.set_value(v.as_slice()).is_ok(),
        Op::ClearValue => node.clear_value(),
        Op::SetAltval(i, v) => node.set_altval(*i, *v).is_ok(),
        Op::RemoveAltval(i) => node.remove_altval(*i),
        Op::ClearAltvals => node.clear_altvals(),
        Op::SetSupval(i, v) => node.set_supval(*i, v.as_slice()).is_ok(),
        Op::RemoveSupval(i) => node.remove_supval(*i),
        Op::ClearSupvals => node.clear_supvals(),
        Op::SetHash(k, v) => node.set_hash(k, v.as_slice()).is_ok(),
        Op::SetHashInteger(k, v) => node.set_hash_integer(k, *v).is_ok(),
        Op::RemoveHash(k) => node.remove_hash(k),
        Op::ClearHash => node.clear_hash(),
        Op::SetBlob(v) => node.set_blob(v).is_ok(),
        Op::RemoveBlob => node.remove_blob(),
    }
}

/// Every scalar read and every iterator agrees with the model.
fn check(node: &NetnodeMut<'_>, model: &Model) -> Result<(), TestCaseError> {
    prop_assert_eq!(node.value(), model.value.clone(), "value");
    prop_assert_eq!(node.blob(), model.blob.clone(), "blob");
    prop_assert_eq!(
        node.blob_size(),
        model.blob.as_ref().map_or(0, Vec::len),
        "blob_size"
    );

    for i in 0..INDICES {
        let altval = model.altvals.get(&i).copied().unwrap_or(0);
        prop_assert_eq!(node.altval(i), altval, "altval {}", i);
        prop_assert_eq!(
            node.supval(i),
            model.supvals.get(&i).cloned(),
            "supval {}",
            i
        );
    }

    for key in KEYS {
        let stored = model.hash.get(key).cloned();
        prop_assert_eq!(node.hash(key), stored.clone(), "hash {}", key);
        // `hashval_long` is only defined over what the int setter wrote, so a byte value of some
        // other width has no expected reading; an absent key is documented to read 0.
        match stored {
            None => prop_assert_eq!(node.hash_integer(key), 0, "hash_integer {} unset", key),
            Some(bytes) if bytes.len() == 8 => {
                let want = u64::from_le_bytes(bytes.try_into().expect("8 bytes"));
                prop_assert_eq!(node.hash_integer(key), want, "hash_integer {}", key);
            }
            Some(_) => {}
        }
    }

    let altvals: Vec<(u64, u64)> = node.altvals().collect();
    let want: Vec<(u64, u64)> = model.altvals.iter().map(|(i, v)| (*i, *v)).collect();
    prop_assert_eq!(altvals, want, "altvals enumeration");

    let supvals: Vec<(u64, Vec<u8>)> = node.supvals().collect();
    let want: Vec<(u64, Vec<u8>)> = model.supvals.iter().map(|(i, v)| (*i, v.clone())).collect();
    prop_assert_eq!(supvals, want, "supvals enumeration");

    let entries: Vec<(String, Vec<u8>)> = node.hash_entries().collect();
    let want: Vec<(String, Vec<u8>)> = model
        .hash
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    prop_assert_eq!(entries, want, "hash_entries enumeration");

    Ok(())
}

/// A random op sequence drives the real node and a model in lockstep, asserting both the accepted
/// or rejected outcome and the full observable state after every step.
///
/// The `write_ops!` macro generates most of this surface, and cargo-mutants never expands macros,
/// so none of those bodies emits a mutant to kill. This covers by construction what mutation
/// testing structurally cannot reach here.
///
/// The runner is driven inline rather than through `proptest!` so the whole sweep reuses this
/// session's kernel and database instead of standing up its own.
fn model_run(idb: &mut Database) {
    let name = "$ idakit.netnode.model";
    let mut runner = TestRunner::new(Config {
        cases: 48,
        ..Config::default()
    });

    // The runner takes an `Fn`, so the database reaches it through a RefCell rather than a
    // captured `&mut`.
    let db = RefCell::new(idb);
    let result = runner.run(&prop::collection::vec(op_strategy(), 1..16), |ops| {
        let mut idb = db.borrow_mut();
        // Each case starts from an empty node, so a sequence never inherits the last one.
        idb.netnode_mut(name).kill();
        let mut node = idb.netnode_mut(name);
        let mut model = Model::default();

        for op in &ops {
            let expected = model.apply(op);
            prop_assert_eq!(apply_real(&mut node, op), expected, "outcome of {:?}", op);
            check(&node, &model)?;
        }
        Ok(())
    });

    db.into_inner().netnode_mut(name).kill();
    result.expect("the model and the kernel agree");
}

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
        t.set_integer(1, 111).expect("set_integer");
        t.set_value(2, b"data").expect("set_value");
        t.set_hash("k", b"v").expect("set_hash");
        node.id()
    };

    let node = idb.netnode_at(id);
    let t = node.tag(user);
    assert!(t.integer(1) == 111);
    assert!(t.value(2).as_deref() == Some(b"data".as_slice()));
    assert!(t.hash("k").as_deref() == Some(b"v".as_slice()));

    // integer and value are two views of one numeric array, so both slots enumerate together.
    let indices: Vec<u64> = t.values().map(|(i, _)| i).collect();
    assert!(indices == vec![1, 2]);

    // A different tag is a separate array: the default-tag slot at index 2 is untouched.
    assert!(
        node.supval(2).is_none(),
        "tag 'X' is isolated from the default tag"
    );

    idb.netnode_mut(name).kill();
}

/// The altval array's boundary indices (`0`, `u64::MAX`) both store and read back.
fn boundary_altval_run(idb: &mut Database) {
    let name = "$ idakit.netnode.boundary.altval";
    let mut node = idb.netnode_mut(name);

    node.set_altval(0, 0xAAAA).expect("set_altval at index 0");
    assert!(node.altval(0) == 0xAAAA, "altval at index 0 did not stick");

    node.set_altval(u64::MAX, 0xBBBB)
        .expect("set_altval at u64::MAX");
    assert!(
        node.altval(u64::MAX) == 0xBBBB,
        "altval at index u64::MAX did not stick"
    );

    node.kill();
}

/// The supval array's boundary indices (`0`, `u64::MAX`) both store and read back.
fn boundary_supval_run(idb: &mut Database) {
    let name = "$ idakit.netnode.boundary.supval";
    let mut node = idb.netnode_mut(name);

    node.set_supval(0, b"zero").expect("set_supval at index 0");
    assert!(
        node.supval(0).as_deref() == Some(b"zero".as_slice()),
        "supval at index 0 did not stick"
    );

    node.set_supval(u64::MAX, b"max")
        .expect("set_supval at u64::MAX");
    assert!(
        node.supval(u64::MAX).as_deref() == Some(b"max".as_slice()),
        "supval at index u64::MAX did not stick"
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
    assert!(let Err(Error::InvalidNetnodeBytes { source: NetnodeBytesError::Empty }) = node.set_supval(1, b""));
    assert!(
        node.supval(1).is_none(),
        "the rejected supval write left no value"
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
    node.set_supval(1, b"\0")
        .expect("set_supval with a single NUL");
    assert!(
        node.supval(1).as_deref() == Some(b"\0".as_slice()),
        "a one-byte supval did not round-trip"
    );

    node.kill();
}

/// Every byte-valued setter enforces [`NetnodeBytes::MAX_SIZE`] rather than silently truncating.
///
/// An over-cap `supset` returns success while storing only the first `MAX_SIZE` bytes, so a
/// caller trusting the `Ok` would silently lose data. idakit rejects the write client-side
/// instead, matching the empty-value guard.
fn oversized_value_run(idb: &mut Database) {
    use idakit::NetnodeBytesError;
    use idakit::error::Error;

    let name = "$ idakit.netnode.boundary.oversized";
    let mut node = idb.netnode_mut(name);

    // Exactly the cap: stores and round-trips in full.
    let at_cap = vec![0x11u8; 1024];
    node.set_supval(0, &at_cap).expect("set_supval at MAX_SIZE");
    assert!(
        node.supval(0).as_deref() == Some(at_cap.as_slice()),
        "a value at the cap did not round-trip exactly"
    );

    // One byte over: rejected before the kernel, with the length and cap on the typed error.
    let over_cap = vec![0x22u8; 1025];
    assert!(
        let Err(Error::InvalidNetnodeBytes {
            source: NetnodeBytesError::TooLarge { len: 1025, cap: 1024 },
        }) = node.set_supval(1, &over_cap)
    );
    assert!(
        node.supval(1).is_none(),
        "the rejected supval write left no value"
    );

    // Far over the cap: same rejection.
    let far_over = vec![0x33u8; 4096];
    assert!(
        let Err(Error::InvalidNetnodeBytes {
            source: NetnodeBytesError::TooLarge { len: 4096, cap: 1024 },
        }) = node.set_supval(2, &far_over)
    );
    assert!(
        node.supval(2).is_none(),
        "the rejected supval write left no value"
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
/// `Error::WriteRejected` carrying the kernel's own error channel.
///
/// Renaming onto a name another node already holds is the one write here the kernel refuses on
/// valid input. Deletes cannot stand in: their `false` means the slot was empty, which is an
/// answer rather than a refusal, so they report it as `bool` and never reach this path.
fn write_rejection_run(idb: &mut Database) {
    use idakit::error::Error;

    let taken = "$ idakit.netnode.checked.taken";
    let name = "$ idakit.netnode.checked";

    let _ = idb.netnode_mut(taken);
    let mut node = idb.netnode_mut(name);

    let rejected = node.rename(taken);
    assert!(let Err(Error::WriteRejected { op: "rename", .. }) = rejected);
    assert!(
        node.name().as_deref() == Some(name),
        "the rejected rename left the node's name alone"
    );

    node.kill();
    idb.netnode_mut(taken).kill();
}

/// A `NetnodeBytes` validated once is itself accepted back into the setters it exists for, so
/// one validation reuses across several writes instead of re-validating identical bytes.
fn reused_bytes_run(idb: &mut Database) {
    use idakit::NetnodeBytes;

    let name = "$ idakit.netnode.reused_bytes";
    let mut node = idb.netnode_mut(name);

    let bytes = NetnodeBytes::try_from(b"shared".as_slice()).expect("valid bytes");
    node.set_supval(0, bytes)
        .expect("set_supval with a NetnodeBytes");
    node.set_hash("k", bytes)
        .expect("set_hash with the same NetnodeBytes");

    assert!(node.supval(0).as_deref() == Some(b"shared".as_slice()));
    assert!(node.hash("k").as_deref() == Some(b"shared".as_slice()));

    node.kill();
}

/// A 64 KiB blob, well past the 1024-byte cap that binds the hash/supval arrays, round-trips
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

/// Each deletion op removes exactly what it names, read back rather than trusting its `Ok`. A
/// targeted delete leaves its siblings alone, so a mutant that clears the whole array fails here
/// too.
fn deletion_run(idb: &mut Database) {
    let name = "$ idakit.netnode.deletion";
    let renamed = "$ idakit.netnode.deletion.renamed";

    let id = {
        let mut node = idb.netnode_mut(name);

        node.set_value(b"payload").expect("set_value");
        assert!(node.value().is_some(), "set_value did not store");
        assert!(node.clear_value(), "clear_value did not report the removal");
        assert!(node.value().is_none(), "clear_value left the node value");
        assert!(
            !node.clear_value(),
            "clearing an absent value removed something"
        );

        node.set_supval(0, b"sup-zero").expect("set_supval 0");
        node.set_supval(1, b"sup-one").expect("set_supval 1");
        assert!(
            node.remove_supval(0),
            "remove_supval did not report the removal"
        );
        assert!(
            node.supval(0).is_none(),
            "remove_supval left the supval at 0"
        );
        assert!(
            node.supval(1).is_some(),
            "remove_supval took the supval at 1 too"
        );
        assert!(
            !node.remove_supval(0),
            "removing an absent supval removed something"
        );
        assert!(
            node.clear_supvals(),
            "clear_supvals did not report the removal"
        );
        assert!(
            node.supvals().next().is_none(),
            "clear_supvals left a supval"
        );
        assert!(
            !node.clear_supvals(),
            "clearing an empty supval array removed something"
        );

        node.set_blob(&[1, 2, 3]).expect("set_blob");
        assert!(node.blob().is_some(), "set_blob did not store");
        assert!(node.remove_blob(), "remove_blob did not report the removal");
        assert!(node.blob().is_none(), "remove_blob left the blob");
        assert!(
            !node.remove_blob(),
            "removing an absent blob removed something"
        );

        node.rename(renamed).expect("rename");
        node.id()
    };

    // The rename moved the node rather than copying it: the id is stable, the old name resolves
    // to nothing, and the new one resolves back to the same node.
    assert!(idb.netnode(name).is_none(), "the old name still resolves");
    assert!(
        idb.netnode(renamed).map(|n| n.id()) == Some(id),
        "the new name does not resolve to the renamed node"
    );
    assert!(idb.netnode_at(id).name().as_deref() == Some(renamed));

    idb.netnode_mut(renamed).kill();
    assert!(idb.netnode(renamed).is_none(), "node is gone after kill");
}

/// The tagged cursor's hash deletions hit only their own tag, leaving the default tag's hash
/// array intact.
fn tagged_deletion_run(idb: &mut Database) {
    use idakit::Tag;
    let name = "$ idakit.netnode.deletion.tagged";
    let user = Tag::new(b'Y');

    {
        let mut node = idb.netnode_mut(name);
        node.set_hash("shared", b"default-tag").expect("set_hash");

        let mut t = node.tag(user);
        t.set_hash("a", b"1").expect("set_hash a");
        t.set_hash("b", b"2").expect("set_hash b");
        assert!(t.remove_hash("a"), "remove_hash did not report the removal");
        assert!(t.hash("a").is_none(), "remove_hash left the entry");
        assert!(t.hash("b").is_some(), "remove_hash took the wrong entry");
        assert!(
            !t.remove_hash("a"),
            "removing an absent entry removed something"
        );
        assert!(t.clear_hash(), "clear_hash did not report the removal");
        assert!(t.hash("b").is_none(), "clear_hash left an entry");
        assert!(!t.clear_hash(), "clearing an empty hash removed something");

        assert!(
            node.hash("shared").as_deref() == Some(b"default-tag".as_slice()),
            "the tagged hash deletions reached the default tag"
        );
        node.kill();
    }
    assert!(idb.netnode(name).is_none(), "node is gone after kill");
}

/// The full cycle: create, write every store, read back, iterate, then clear and kill.
fn roundtrip_run(idb: &mut Database) {
    let name = "$ idakit.netnode.roundtrip";

    // Create the node and populate every store through the write cursor.
    let id = {
        let mut node = idb.netnode_mut(name);
        node.set_value(b"payload").expect("set_value");
        node.set_altval(1, 111).expect("set_altval 1");
        node.set_altval(2, 222).expect("set_altval 2");
        node.set_supval(0, b"sup-zero").expect("set_supval");
        node.set_hash("greeting", b"hi").expect("set_hash");
        node.set_hash_integer("count", 7).expect("set_hash_integer");
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
    assert!(node.altval(1) == 111);
    assert!(node.altval(2) == 222);
    assert!(node.altval(99) == 0, "an unset altval reads as 0");
    assert!(node.supval(0).as_deref() == Some(b"sup-zero".as_slice()));
    assert!(node.supval(1).is_none(), "an unset supval is None");
    assert!(node.hash("greeting").as_deref() == Some(b"hi".as_slice()));
    assert!(node.hash_integer("count") == 7);
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
    let mut altvals = node.altvals();
    for expected in [(1u64, 111u64), (2, 222)] {
        assert!(altvals.next() == Some(expected), "altvals item mismatch");
    }
    assert!(altvals.next().is_none(), "altvals: unexpected extra entry");

    let mut supvals = node.supvals();
    assert!(
        supvals.next() == Some((0u64, b"sup-zero".to_vec())),
        "supvals item mismatch"
    );
    assert!(supvals.next().is_none(), "supvals: unexpected extra entry");

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
        assert!(
            node.remove("removable"),
            "remove did not report the removal"
        );
        assert!(
            node.get::<u64>("removable").is_none(),
            "remove did not delete the value"
        );

        assert!(
            node.remove_altval(1),
            "remove_altval did not report the removal"
        );
        assert!(node.altval(1) == 0, "a removed altval reads as 0");
        assert!(
            node.clear_altvals(),
            "clear_altvals did not report the removal"
        );
        assert!(node.altvals().next().is_none(), "altvals empty after clear");
        assert!(node.clear_hash(), "clear_hash did not report the removal");
        assert!(
            node.hash_entries().next().is_none(),
            "hash empty after clear"
        );
        node.kill();
    }
    assert!(idb.netnode(name).is_none(), "node is gone after kill");
}
