//! Database metadata and name lookup against a real database.
//!
//! A normal `#[test]`: the kernel runs on the thread `Ida::run` spawns (8 MiB stack), so no
//! `harness = false`. The nextest `serial-kernel` group keeps it from overlapping the other
//! kernel tests. Runs against the corpus manifest's canonical fixture (see
//! [`common::TestDb`]); skips when no corpus is configured. Read-only; opens `save = false`.

use idakit::prelude::*;

mod common;

#[test]
fn dbinfo() {
    common::with_canonical_db(run);
}

// A raw name in the canonical fixture carrying a forbidden leading '.', which GN_VISIBLE
// substitutes for '_'.
const SUBST_ADDRESS: u64 = 0x0025_5b00;
const SUBST_RAW: &str = ".block_loop";
const SUBST_VISIBLE: &str = "_block_loop";

// A publicly exported function and a local helper beside it in the same fixture.
const PUBLIC_ADDRESS: u64 = 0x0000_1d50;
const PUBLIC_NAME: &str = "_AES_encrypt";
const LOCAL_ADDRESS: u64 = 0x0000_18f0;
const LOCAL_NAME: &str = "_x86_64_AES_encrypt";

fn run(idb: &mut Database) {
    // Metadata snapshot: an x86 database is 32- or 64-bit, has a processor name, and its
    // full input path ends with the bare root filename.
    let info = idb.info();
    assert!(
        matches!(info.bitness, Some(Bitness::Bits32 | Bitness::Bits64)),
        "unexpected bitness {:?}",
        info.bitness
    );
    let proc = info.processor.as_deref().unwrap_or_default();
    assert!(!proc.is_empty(), "processor name is empty");
    if let (Some(path), Some(root)) = (&info.input_path, &info.root_filename) {
        assert!(
            path.ends_with(root.as_str()),
            "input path {path:?} does not end with root filename {root:?}"
        );
    }
    println!(
        "info: bitness={:?} proc={proc} file_type={:?} base={:?} root={:?}",
        info.bitness, info.file_type, info.image_base, info.root_filename
    );

    // The name list is non-empty and each name round-trips address -> name -> address for at least some
    // entries (local/duplicate names need not resolve from BADADDR, so this is a positive
    // check rather than a universal one).
    let mut listed = 0usize;
    let mut round_tripped = 0usize;
    let mut prev_listed = None;
    for Name { address, name } in idb.names().take(500) {
        // Ascent is checked here, not just in the drain below, so a cursor that fails to advance
        // fails on the second entry rather than spinning in the unbounded scans further down.
        assert!(
            prev_listed.is_none_or(|prev| prev < address),
            "name list is not strictly increasing at {:#x}",
            address.get()
        );
        prev_listed = Some(address);
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
    // symbol, show that it demangles (informational: some inputs store no mangled names).
    assert!(
        idb.demangle("not a mangled name").is_none(),
        "a non-symbol demangled to something"
    );
    if let Some(n) = idb
        .names()
        .take(500)
        .find(|n| n.name.starts_with("_Z") || n.name.starts_with('?'))
    {
        println!("demangle {:?} -> {:?}", n.name, idb.demangle(&n.name));
    }

    // The fixture carries no mangled symbols to anchor against, so pin the demangler itself
    // with a fixed Itanium-mangled string.
    assert!(
        idb.demangle("_Z1fv").as_deref() == Some("f(void)"),
        "known mangled name failed to demangle"
    );

    // The raw name keeps its forbidden '.', every name_with-derived wrapper substitutes it, so
    // dropping VISIBLE from any wrapper's flag composition shows up here.
    let subst = Address::new_const(SUBST_ADDRESS);
    assert!(idb.name(subst).as_deref() == Some(SUBST_RAW));
    assert!(idb.visible_name(subst).as_deref() == Some(SUBST_VISIBLE));
    assert!(idb.short_name(subst).as_deref() == Some(SUBST_VISIBLE));
    assert!(idb.long_name(subst).as_deref() == Some(SUBST_VISIBLE));
    assert!(idb.demangled_name(subst).as_deref() == Some(SUBST_VISIBLE));
    assert!(
        idb.name_with(subst, GnFlags::VISIBLE).as_deref() == Some(SUBST_VISIBLE),
        "name_with(VISIBLE) did not substitute the forbidden character"
    );
    assert!(
        idb.name_with(subst, GnFlags::empty()).as_deref() == Some(SUBST_RAW),
        "name_with(no flags) unexpectedly substituted"
    );

    // Public/weak linkage: an exported symbol against a local helper beside it.
    let public = Address::new_const(PUBLIC_ADDRESS);
    let local = Address::new_const(LOCAL_ADDRESS);
    assert!(idb.name(public).as_deref() == Some(PUBLIC_NAME));
    assert!(idb.name(local).as_deref() == Some(LOCAL_NAME));
    assert!(idb.is_public_name(public), "{PUBLIC_NAME} should be public");
    assert!(
        !idb.is_public_name(local),
        "{LOCAL_NAME} should not be public"
    );
    assert!(!idb.is_weak_name(public));
    assert!(!idb.is_weak_name(local));

    // `Names::size_hint` tracks the real remaining count, so a cursor that over/undershoots
    // `count` shows up as a stub-looking bound or a non-zero one after draining.
    let mut names_iter = idb.names();
    let (lower, upper) = names_iter.size_hint();
    assert!(lower == 0, "Names lower bound should stay 0");
    assert!(
        upper.is_some_and(|u| u > 1),
        "size_hint upper bound {upper:?} looks like a stub constant, not the real name count"
    );

    // The name list is address-ascending; a stuck cursor repeats the previous address, so this
    // fires on the 2nd item instead of looping forever.
    let mut drained = 0usize;
    let mut prev_address = None;
    for Name { address, .. } in &mut names_iter {
        assert!(
            prev_address.is_none_or(|prev| prev < address),
            "names iterator is not strictly increasing at {:#x}",
            address.get()
        );
        prev_address = Some(address);
        drained += 1;
    }
    assert!(drained > 1, "names iterator produced too few entries");
    assert!(names_iter.next().is_none());
    assert!(names_iter.size_hint() == (0, Some(0)));

    println!("ok");
}
