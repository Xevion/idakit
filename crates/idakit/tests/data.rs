//! Typed data reads against a real database: byte reads agree with the raw image, wider reads
//! resolve at a mapped address and fail at an unmapped one, and `read_string` reproduces a
//! listed string. Read-only; opens `save = false`.

mod common;

use idakit::{Address, BADADDR, Idb};

#[test]
fn data() {
    common::with_canonical_db(run);
}

fn run(idb: &mut Idb) {
    // A mapped address: the first function's entry.
    let entry = idb.functions().next().expect("a function").address();

    // read_u8 agrees with the raw byte at the same address.
    let raw = idb.bytes(entry, 1);
    assert!(!raw.is_empty(), "the entry byte should be readable");
    assert!(
        idb.read_u8(entry) == Some(raw[0]),
        "read_u8 should match the raw image byte"
    );

    // Wider reads at a mapped, in-segment address all resolve.
    assert!(idb.read_u16(entry).is_some());
    assert!(idb.read_u32(entry).is_some());
    assert!(idb.read_u64(entry).is_some());

    // An address just below the sentinel is unmapped: every read fails cleanly rather than
    // returning zero.
    let unmapped = Address::new_const(BADADDR - 1);
    assert!(idb.read_u8(unmapped).is_none());
    assert!(idb.read_u32(unmapped).is_none());
    assert!(idb.read_u64(unmapped).is_none());
    assert!(idb.read_pointer(unmapped).is_none());

    // Exercise the pointer read at a mapped spot -- it must resolve or fail without panicking.
    let _ = idb.read_pointer(entry);

    // read_string re-reads a listed 1-byte string to the same text, via the auto-length path
    // rather than the string list's recorded length.
    let listed = idb
        .strings()
        .find(|s| s.char_width() == 1 && s.text().is_some_and(|t| !t.is_empty()))
        .map(|s| (s.address(), s.text().expect("has text")));
    if let Some((address, text)) = listed {
        let read = idb
            .read_string(address)
            .expect("a listed string address should read back a string");
        assert!(
            read == text,
            "read_string {read:?} != listed text {text:?} at {address:#x}"
        );
        println!("read_string at {address:#x}: {read:?}");
    } else {
        println!("read_string: no 1-byte string in the list to cross-check");
    }

    println!("data OK: typed integer/pointer/string reads verified");
}
