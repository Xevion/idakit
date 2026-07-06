//! Binary pattern search against a real database: every constructor form finds a known
//! sequence, and each kernel-dependent rejection trips its typed error.
//!
//! The grammar tokenizers are unit-tested (kernel-free) in `search.rs`; this covers the
//! parts that need a live database -- the actual search, the `ida` parser, and the
//! `NoAnchor`/`MaskMismatch`/`Unparseable` paths. Skips when no test database is present.

mod common;

use idakit::{Address, Error, Pattern, PatternRejection};

#[test]
fn search() {
    common::with_canonical_db(run);
}

fn run(idb: &mut idakit::Database) {
    let first = idb.functions().next().expect("a function");
    let address = first.address();
    let bytes = idb.bytes(address, 8);
    assert!(bytes.len() == 8, "need 8 readable bytes at the entry");

    exact_forms_all_find_entry(idb, address, &bytes);
    wildcards_still_match(idb, address, &bytes);
    range_excludes_start(idb, address, &bytes);
    rejections_trip(idb);

    println!("search OK: all four constructor forms match; rejections trip typed errors");
}

/// hex / bytes / code_mask built from the same entry bytes must each list `address`.
fn exact_forms_all_find_entry(idb: &idakit::Database, address: Address, bytes: &[u8]) {
    let hex_str = bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");

    let hex = Pattern::hex(idb, &hex_str).expect("hex compiles");
    assert!(
        idb.search(&hex).any(|m| m == address),
        "hex should match entry"
    );

    let raw = Pattern::bytes(idb, bytes).call().expect("bytes compiles");
    assert!(
        idb.search(&raw).any(|m| m == address),
        "bytes should match entry"
    );

    let full_mask = "x".repeat(bytes.len());
    let cm = Pattern::code_mask(idb, bytes, &full_mask).expect("code_mask compiles");
    assert!(
        idb.search(&cm).any(|m| m == address),
        "code_mask should match entry"
    );

    // ida() over the same bytes as a hex string finds it too (its parser, our bytes).
    let ida = Pattern::ida(idb, &hex_str).call().expect("ida compiles");
    assert!(
        idb.search(&ida).any(|m| m == address),
        "ida should match entry"
    );
}

/// A byte- and a nibble-wildcard both still match `address` (mask can only widen the set).
fn wildcards_still_match(idb: &idakit::Database, address: Address, bytes: &[u8]) {
    // Byte wildcard on the second byte.
    let mut wild: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
    wild[1] = "?".to_owned();
    let byte_wild = Pattern::hex(idb, wild.join(" ")).expect("byte-wildcard compiles");
    assert!(
        idb.search(&byte_wild).any(|m| m == address),
        "byte wildcard should still match entry"
    );

    // Nibble wildcard: keep the high nibble of the second byte, free the low one.
    wild[1] = format!("{:X}?", bytes[1] >> 4);
    let nib_wild = Pattern::hex(idb, wild.join(" ")).expect("nibble-wildcard compiles");
    assert!(
        idb.search(&nib_wild).any(|m| m == address),
        "nibble wildcard should still match entry"
    );
}

/// A search range starting past `address` must not report `address`.
fn range_excludes_start(idb: &idakit::Database, address: Address, bytes: &[u8]) {
    let pat = Pattern::bytes(idb, bytes).call().expect("bytes compiles");
    let bounds = idb
        .address_range()
        .expect("open database has an address range");
    let after: Vec<Address> = idb.search_in((address + 1)..bounds.end, &pat).collect();
    assert!(
        !after.contains(&address),
        "range after {address:#x} should exclude it"
    );
}

/// Each kernel-dependent rejection returns its specific typed `PatternRejection`.
fn rejections_trip(idb: &idakit::Database) {
    // All-wildcard hex -> NoAnchor.
    let_no_anchor(Pattern::hex(idb, "? ?"), 2);

    // Mask shorter than the bytes -> MaskMismatch.
    let r = Pattern::bytes(idb, &[0x90, 0x90]).mask(&[0xFF]).call();
    assert!(
        matches!(
            r,
            Err(Error::PatternRejected {
                kind: PatternRejection::MaskMismatch { bytes: 2, mask: 1 },
                ..
            })
        ),
        "short mask should be MaskMismatch, got {r:?}"
    );

    // Empty ida pattern -> Unparseable (IDA's parser rejects it outright).
    let r = Pattern::ida(idb, "").call();
    assert!(
        matches!(
            r,
            Err(Error::PatternRejected {
                kind: PatternRejection::Unparseable { .. },
                ..
            })
        ),
        "empty ida pattern should be Unparseable, got {r:?}"
    );
}

/// Assert a compile result is `NoAnchor { total }`.
fn let_no_anchor(r: idakit::Result<Pattern<'_>>, total: usize) {
    assert!(
        matches!(
            r,
            Err(Error::PatternRejected {
                kind: PatternRejection::NoAnchor { total: t },
                ..
            }) if t == total
        ),
        "expected NoAnchor {{ total: {total} }}, got {r:?}"
    );
}
