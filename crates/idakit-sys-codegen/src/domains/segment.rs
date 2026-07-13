use super::super::model::*;
use super::N;

/// The segment domain: mirrors the hand-written `idakit_cxx::seg_*` bridge one-for-one, plus a
/// `Custom` proof. Templated bodies live in the generated `gen_seg_bodies.cc`; the one `Custom`
/// body is hand-written in `facade/custom_escape_hatch.cc`.
pub const SEGMENT: Domain = Domain {
    name: "seg",
    sdk_includes: &["<segment.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    custom_tu: Some("facade/custom_escape_hatch.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "gen_seg_qty",
            receiver: None,
            args: &[],
            ret: RetKind::Usize,
            body: BodyKind::ScalarCall {
                call: "get_segm_qty()",
            },
            doc: "Number of segments in the current database (`get_segm_qty`).",
        },
        FnSpec {
            name: "gen_seg_start",
            receiver: None,
            args: N,
            ret: RetKind::U64,
            body: BodyKind::SegScalar {
                accessor: "start_ea",
                null_sentinel: "BADADDR",
            },
            doc: "Start address of segment `n`, or `BADADDR` when `n` is out of range.",
        },
        FnSpec {
            name: "gen_seg_end",
            receiver: None,
            args: N,
            ret: RetKind::U64,
            body: BodyKind::SegScalar {
                accessor: "end_ea",
                null_sentinel: "BADADDR",
            },
            doc: "End address of segment `n`, or `BADADDR` when `n` is out of range.",
        },
        FnSpec {
            name: "gen_seg_perm",
            receiver: None,
            args: N,
            ret: RetKind::I32,
            body: BodyKind::SegScalar {
                accessor: "perm",
                null_sentinel: "0",
            },
            doc: "Permission bits (`SEGPERM_*`) of segment `n`, or `0` when out of range.",
        },
        FnSpec {
            name: "gen_seg_bitness",
            receiver: None,
            args: N,
            ret: RetKind::I32,
            body: BodyKind::SegScalar {
                accessor: "abits()",
                null_sentinel: "0",
            },
            doc: "Address bits (16/32/64) of segment `n`, or `0` when out of range.",
        },
        FnSpec {
            name: "gen_seg_name",
            receiver: None,
            args: N,
            ret: RetKind::ResultString,
            body: BodyKind::SegString {
                getter: "get_visible_segm_name",
                require_positive: false,
            },
            doc: "Visible name of segment `n`; `Err` when `n` is out of range.",
        },
        FnSpec {
            name: "gen_seg_class",
            receiver: None,
            args: N,
            ret: RetKind::ResultString,
            body: BodyKind::SegString {
                getter: "get_segm_class",
                require_positive: true,
            },
            doc: "Class of segment `n`; `Err` when `n` is out of range or has no class.",
        },
        // Escape hatch: sum of every segment's byte span. Too bespoke to template (it iterates the
        // whole table), so the spec declares only the signature; facade/custom_escape_hatch.cc defines it.
        FnSpec {
            name: "gen_seg_span_total",
            receiver: None,
            args: &[],
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Total byte span across all segments (sum of `end - start`). Hand-written body.",
        },
    ],
};
