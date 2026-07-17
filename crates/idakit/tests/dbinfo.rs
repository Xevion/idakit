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

fn run(idb: &mut Database) {
    assert_metadata(idb);
    assert_name_list(idb);
    let anchors = Anchors::find(idb);
    assert_substitution(idb, &anchors);
    assert_demangled_wrappers(idb, &anchors);
    assert_linkage(idb, &anchors);
    assert_names_iterator(idb);
    println!("ok");
}

fn assert_metadata(idb: &Database) {
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
}

fn assert_name_list(idb: &Database) {
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

    // Pin the demangler itself against a fixed Itanium-mangled string, independent of whatever
    // the fixture happens to carry.
    assert!(
        idb.demangle("_Z1fv").as_deref() == Some("f(void)"),
        "known mangled name failed to demangle"
    );
}

/// Fixture-derived anchors for the name-flag assertions below, found by one bounded scan of the
/// name list. Content-derived (never a hardcoded address), so they survive the fixture changing.
struct Anchors {
    weak: Address,
    non_weak: Address,
    public: Address,
    local: Address,
    // (address, raw name, expected GN_VISIBLE substitution)
    subst: (Address, String, String),
    // (address, short_name output)
    short: (Address, String),
    // (address, long_name output)
    long: (Address, String),
}

impl Anchors {
    // Bounded so a mutation that makes a predicate unsatisfiable degrades to one fixed-size
    // pass instead of hanging.
    fn find(idb: &Database) -> Self {
        let mut weak = None;
        let mut non_weak = None;
        let mut public = None;
        let mut local = None;
        let mut subst: Option<(Address, String, String)> = None;
        let mut short: Option<(Address, String)> = None;
        let mut long: Option<(Address, String)> = None;

        for Name { address, name } in idb.names().take(10_000) {
            if weak.is_none() && idb.is_weak_name(address) {
                weak = Some(address);
            }
            if non_weak.is_none() && !idb.is_weak_name(address) {
                non_weak = Some(address);
            }
            if public.is_none() && idb.is_public_name(address) {
                public = Some(address);
            }
            if local.is_none() && !idb.is_public_name(address) {
                local = Some(address);
            }
            // A non-mangled name with a forbidden leading '.': GN_VISIBLE substitutes it for
            // '_' and nothing else changes, so short/long/demangled_name all agree with
            // visible_name.
            if subst.is_none()
                && let Some(rest) = name.strip_prefix('.')
                && !rest.starts_with("_Z")
            {
                subst = Some((address, name.clone(), format!("_{rest}")));
            }
            // A mangled name whose short/long form genuinely demangles: no longer contains the
            // "_Z" mangling prefix and reads as a real C++ signature (parens for the arg list).
            if short.is_none()
                && name.starts_with("_Z")
                && let (Some(s), Some(visible)) =
                    (idb.short_name(address), idb.visible_name(address))
                && s != visible
                && !s.contains("_Z")
                && s.contains('(')
            {
                short = Some((address, s));
            }
            if long.is_none()
                && name.starts_with("_Z")
                && let (Some(l), Some(visible)) =
                    (idb.long_name(address), idb.visible_name(address))
                && l != visible
                && !l.contains("_Z")
                && l.contains('(')
            {
                long = Some((address, l));
            }
            if weak.is_some()
                && non_weak.is_some()
                && public.is_some()
                && local.is_some()
                && subst.is_some()
                && short.is_some()
                && long.is_some()
            {
                break;
            }
        }

        Self {
            weak: weak.expect("no weak name in the first 10000 names"),
            non_weak: non_weak.expect("no non-weak name in the first 10000 names"),
            public: public.expect("no public name in the first 10000 names"),
            local: local.expect("no local (non-public) name in the first 10000 names"),
            subst: subst.expect(
                "no non-mangled name with a forbidden leading '.' in the first 10000 names",
            ),
            short: short.expect("no genuinely demangled short_name in the first 10000 names"),
            long: long.expect("no genuinely demangled long_name in the first 10000 names"),
        }
    }
}

fn assert_substitution(idb: &Database, anchors: &Anchors) {
    // The raw name keeps its forbidden '.', every name_with-derived wrapper substitutes it, so
    // dropping VISIBLE from any wrapper's flag composition shows up here.
    let (addr, raw, visible) = &anchors.subst;
    assert!(idb.name(*addr).as_deref() == Some(raw.as_str()));
    assert!(idb.visible_name(*addr).as_deref() == Some(visible.as_str()));
    assert!(idb.short_name(*addr).as_deref() == Some(visible.as_str()));
    assert!(idb.long_name(*addr).as_deref() == Some(visible.as_str()));
    assert!(idb.demangled_name(*addr).as_deref() == Some(visible.as_str()));
    assert!(
        idb.name_with(*addr, GnFlags::VISIBLE).as_deref() == Some(visible.as_str()),
        "name_with(VISIBLE) did not substitute the forbidden character"
    );
    assert!(
        idb.name_with(*addr, GnFlags::empty()).as_deref() == Some(raw.as_str()),
        "name_with(no flags) unexpectedly substituted"
    );
}

fn assert_demangled_wrappers(idb: &Database, anchors: &Anchors) {
    // `short_name`'s DEMANGLED & SHORT collapsing to zero (leaving VISIBLE alone) is only
    // observable where demangling actually changes the string, so pin a mangled symbol whose
    // short form both differs from visible_name and reads as a genuine demangled signature.
    let (short_addr, short_form) = &anchors.short;
    assert!(
        idb.short_name(*short_addr).as_deref() != idb.visible_name(*short_addr).as_deref(),
        "short_name({:#x}) collapsed to visible_name: demangling did not apply",
        short_addr.get()
    );
    assert!(
        !short_form.contains("_Z"),
        "short_name({:#x}) still looks mangled: {short_form:?}",
        short_addr.get()
    );
    assert!(
        short_form.contains('(') && short_form.contains(')'),
        "short_name({:#x}) doesn't read as a demangled C++ signature: {short_form:?}",
        short_addr.get()
    );

    // Same shape for `long_name`'s own DEMANGLED & LONG collapse.
    let (long_addr, long_form) = &anchors.long;
    assert!(
        idb.long_name(*long_addr).as_deref() != idb.visible_name(*long_addr).as_deref(),
        "long_name({:#x}) collapsed to visible_name: demangling did not apply",
        long_addr.get()
    );
    assert!(
        !long_form.contains("_Z"),
        "long_name({:#x}) still looks mangled: {long_form:?}",
        long_addr.get()
    );
    assert!(
        long_form.contains('(') && long_form.contains(')'),
        "long_name({:#x}) doesn't read as a demangled C++ signature: {long_form:?}",
        long_addr.get()
    );
}

fn assert_linkage(idb: &Database, anchors: &Anchors) {
    // Public/local linkage: an exported symbol against a local helper.
    assert!(
        idb.is_public_name(anchors.public),
        "{:#x} should be public",
        anchors.public.get()
    );
    assert!(
        !idb.is_public_name(anchors.local),
        "{:#x} should not be public",
        anchors.local.get()
    );

    // Weak linkage: both directions must be reachable, or a mutant collapsing `is_weak_name` to
    // a constant (either direction) goes uncaught.
    assert!(
        idb.is_weak_name(anchors.weak),
        "{:#x} should be weak",
        anchors.weak.get()
    );
    assert!(
        !idb.is_weak_name(anchors.non_weak),
        "{:#x} should not be weak",
        anchors.non_weak.get()
    );
}

fn assert_names_iterator(idb: &Database) {
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
}
