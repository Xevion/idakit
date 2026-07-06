//! Database metadata and name lookup against a real database.
//!
//! A normal `#[test]`: the kernel runs on the thread `Ida::run` spawns (8 MiB stack), so no
//! `harness = false`. The nextest `serial-kernel` group keeps it from overlapping the other
//! kernel tests. Runs against `IDAKIT_TEST_DB` or `$IDADIR/libida.so.i64` (see
//! [`common::test_db`]); skips when neither is present. Read-only; opens `save = false`.

use idakit::{Bitness, Idb, Name};

mod common;

#[test]
fn dbinfo() {
    common::with_canonical_db(run);
}

fn run(idb: &mut Idb) {
    // Metadata snapshot: an x86 database is 32- or 64-bit, has a processor name, and its
    // full input path ends with the bare root filename.
    let meta = idb.meta();
    assert!(
        matches!(meta.bitness, Some(Bitness::Bits32 | Bitness::Bits64)),
        "unexpected bitness {:?}",
        meta.bitness
    );
    let proc = meta.processor.as_deref().unwrap_or_default();
    assert!(!proc.is_empty(), "processor name is empty");
    if let (Some(path), Some(root)) = (&meta.input_path, &meta.root_filename) {
        assert!(
            path.ends_with(root.as_str()),
            "input path {path:?} does not end with root filename {root:?}"
        );
    }
    println!(
        "meta: bitness={:?} proc={proc} file_type={:?} base={:?} root={:?}",
        meta.bitness, meta.file_type, meta.image_base, meta.root_filename
    );

    // The name list is non-empty and each name round-trips address -> name -> address for at least some
    // entries (local/duplicate names need not resolve from BADADDR, so this is a positive
    // check rather than a universal one).
    let mut listed = 0usize;
    let mut round_tripped = 0usize;
    for Name { address, name } in idb.names().take(500) {
        assert!(!name.is_empty(), "empty name at {:#x}", address.get());
        assert!(
            idb.name(address).as_deref() == Some(name.as_str()),
            "name({:#x}) disagrees with the name list",
            address.get()
        );
        if idb.address_of(&name) == Some(address) {
            round_tripped += 1;
        }
        listed += 1;
    }
    assert!(listed > 0, "the name list is empty");
    assert!(
        round_tripped > 0,
        "no name round-tripped address -> name -> address"
    );
    println!("names: {round_tripped}/{listed} round-tripped name -> address");

    // A plainly unmangled string is not a mangled name. If the binary carries a mangled
    // symbol, show that it demangles (informational -- some inputs store no mangled names).
    assert!(
        idb.demangle("not a mangled name").is_none(),
        "a non-symbol demangled to something"
    );
    if let Some(n) = idb
        .names()
        .find(|n| n.name.starts_with("_Z") || n.name.starts_with('?'))
    {
        println!("demangle {:?} -> {:?}", n.name, idb.demangle(&n.name));
    }

    println!("ok");
}
