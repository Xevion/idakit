//! Import and export enumeration against a real database. Structural only, so it holds across
//! an ELF `.so` (many exports, some imports) and a PE `.exe` (few exports, many imports): every
//! export resolves to an address or a forwarder, every import carries a name or an ordinal, and
//! a real program has at least one of the two. Read-only; opens `save = false`.

mod common;

use idakit::prelude::*;

#[test]
fn symbols() {
    common::with_canonical_db(run);
}

fn run(idb: &mut Database) {
    // Every export must resolve to something: a local address or a forward target.
    let mut exports = 0usize;
    let mut named_exports = 0usize;
    let mut forwarders = 0usize;
    let mut exports_in_segment = 0usize;
    for export in idb.exports().take(4000) {
        exports += 1;
        named_exports += usize::from(export.name().is_some());
        forwarders += usize::from(export.forwarder().is_some());
        assert!(
            export.address().is_some() || export.forwarder().is_some(),
            "export #{} resolves to neither an address nor a forwarder",
            export.index()
        );
        // Cross-invariant: a local export's address is real -- it lies inside some segment, not
        // off in unmapped space.
        if let Some(ea) = export.address() {
            assert!(
                idb.segment_at(ea).is_some(),
                "export {:?} at {ea:#x} does not resolve to any segment",
                export.name()
            );
            exports_in_segment += 1;
        }
    }
    println!(
        "exports: {exports} total, {named_exports} named, {forwarders} forwarded, \
         {exports_in_segment} resolved to a segment"
    );

    // Every import must carry a way to resolve it: a name or an ordinal.
    let mut imports = 0usize;
    let mut by_name = 0usize;
    let mut by_ordinal = 0usize;
    let mut imports_in_segment = 0usize;
    for import in idb.imports().take(8000) {
        imports += 1;
        by_name += usize::from(import.name().is_some());
        by_ordinal += usize::from(import.ordinal().is_some());
        assert!(
            import.name().is_some() || import.ordinal().is_some(),
            "import at {:#x} has neither a name nor an ordinal",
            import.address()
        );
        // Cross-invariant: an import's slot address (the IAT entry / thunk) is a real address --
        // it lies inside some segment, not off in unmapped space.
        assert!(
            idb.segment_at(import.address()).is_some(),
            "import {:?} at {:#x} does not resolve to any segment",
            import.name(),
            import.address()
        );
        imports_in_segment += 1;
    }
    println!(
        "imports: {imports} total, {by_name} by name, {by_ordinal} by ordinal, \
         {imports_in_segment} resolved to a segment"
    );

    // A real program either exports or imports something; otherwise the enumeration is broken,
    // not merely empty.
    assert!(
        exports > 0 || imports > 0,
        "the database has neither exports nor imports"
    );

    println!("symbols OK: export/import enumeration verified");
}
