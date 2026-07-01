//! Database metadata and name lookup against a real database.
//!
//! `harness = false` (owns `fn main()`) like the other kernel tests; set `IDAKIT_TEST_DB` to
//! an absolute `.i64` path or it skips. Read-only; opens `save = false`.

use idakit::{Ida, Name};

fn main() {
    let Ok(db) = std::env::var("IDAKIT_TEST_DB") else {
        eprintln!("skipping: set IDAKIT_TEST_DB=<path to .i64> to run this test");
        return;
    };

    let mut idb = Ida::here().expect("kernel init failed");
    idb.open(&db).call().expect("open failed");

    // Metadata snapshot: an x86 database is 32- or 64-bit, has a processor name, and its
    // full input path ends with the bare root filename.
    let meta = idb.meta();
    assert!(
        meta.bitness == 32 || meta.bitness == 64,
        "unexpected bitness {}",
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
        "meta: bitness={} proc={proc} file_type={:?} base={:?} root={:?}",
        meta.bitness, meta.file_type, meta.image_base, meta.root_filename
    );

    // The name list is non-empty and each name round-trips ea -> name -> ea for at least some
    // entries (local/duplicate names need not resolve from BADADDR, so this is a positive
    // check rather than a universal one).
    let mut listed = 0usize;
    let mut round_tripped = 0usize;
    for Name { ea, name } in idb.names().take(500) {
        assert!(!name.is_empty(), "empty name at {:#x}", ea.get());
        assert!(
            idb.name(ea).as_deref() == Some(name.as_str()),
            "name({:#x}) disagrees with the name list",
            ea.get()
        );
        if idb.name_ea(&name) == Some(ea) {
            round_tripped += 1;
        }
        listed += 1;
    }
    assert!(listed > 0, "the name list is empty");
    assert!(round_tripped > 0, "no name round-tripped ea -> name -> ea");
    println!("names: {round_tripped}/{listed} round-tripped name -> ea");

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

    idb.close(false);
    println!("ok");
}
