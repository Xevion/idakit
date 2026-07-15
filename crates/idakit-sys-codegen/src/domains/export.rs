use super::super::model::*;

/// The export (entry-point) domain: per-export scalar accessors plus the name and forwarder
/// strings, indexed `[0, export_qty)`. `export_qty` is a templated passthrough; the lookups are
/// hand-written in `facade/export_custom.cc` (a forwarder-less export legitimately `Err`s).
pub const EXPORT: Domain = Domain {
    name: "export",
    sdk_includes: &["<entry.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    consts: &[],
    custom_tu: Some("facade/export_custom.cc"),
    body_helpers: None,
    fns: fns! {
        "Number of exported entry points in the database (`get_entry_qty`)."
            export_qty() -> Usize = scalar("get_entry_qty()");
        "Address of export `idx`, or `BADADDR` when the export is a pure forwarder."
            export_ea(idx: Usize) -> U64;
        "Ordinal of export `idx`."
            export_ordinal(idx: Usize) -> U64;
        "Name of export `idx`; `Err` when it has none."
            export_name(idx: Usize) -> ResultString;
        "Forwarder target of export `idx`; `Err` when it has none (most exports do not)."
            export_forwarder(idx: Usize) -> ResultString;
    },
};
