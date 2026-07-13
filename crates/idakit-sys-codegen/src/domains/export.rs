use super::super::model::*;
use super::IDX;

/// The export (entry-point) domain: per-export scalar accessors plus the name and forwarder
/// strings, indexed `[0, export_qty)`. `export_qty` is a templated passthrough; the lookups are
/// hand-written in `facade/export_custom.cc` (a forwarder-less export legitimately `Err`s).
pub const EXPORT: Domain = Domain {
    name: "export",
    sdk_includes: &["<entry.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    custom_tu: Some("facade/export_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "export_qty",
            receiver: None,
            args: &[],
            ret: RetKind::Usize,
            body: BodyKind::ScalarCall {
                call: "get_entry_qty()",
            },
            doc: "Number of exported entry points in the database (`get_entry_qty`).",
        },
        FnSpec {
            name: "export_ea",
            receiver: None,
            args: IDX,
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Address of export `idx`, or `BADADDR` when the export is a pure forwarder.",
        },
        FnSpec {
            name: "export_ordinal",
            receiver: None,
            args: IDX,
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Ordinal of export `idx`.",
        },
        FnSpec {
            name: "export_name",
            receiver: None,
            args: IDX,
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Name of export `idx`; `Err` when it has none.",
        },
        FnSpec {
            name: "export_forwarder",
            receiver: None,
            args: IDX,
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Forwarder target of export `idx`; `Err` when it has none (most exports do not).",
        },
    ],
};
