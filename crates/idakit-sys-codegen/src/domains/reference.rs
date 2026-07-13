use super::super::model::*;

/// The cross-reference domain: every xref edge at an address returned as one owned `Vec<XrefRec>`
/// snapshot, retiring the raw open-cursor/next/close dance. The single body is hand-written in
/// `facade/reference_custom.cc` (one walk of an `xrefblk_t`).
pub const REFERENCE: Domain = Domain {
    name: "reference",
    sdk_includes: &["<xref.hpp>"],
    externs: &[],
    structs: &[SharedStruct {
        name: "XrefRec",
        doc: "One cross-reference edge, returned inside the [`xrefs_build`] snapshot.",
        fields: fields! {
            from: U64 = "Source address of the reference.";
            to: U64 = "Target address of the reference.";
            type_: I32 = "Raw `cref_t`/`dref_t` type code of the edge.";
            iscode: Bool = "`true` for a code reference, `false` for a data reference.";
            user: Bool = "`true` when user-defined, `false` when IDA's analysis generated it.";
        },
    }],
    custom_tu: Some("facade/reference_custom.cc"),
    body_helpers: None,
    fns: &[FnSpec {
        name: "xrefs_build",
        receiver: None,
        args: args!(ea: U64, is_to: Bool),
        ret: RetKind::Vec("XrefRec"),
        body: BodyKind::Custom,
        doc: "Every cross-reference edge at `ea` as an owned, `Send` snapshot: xrefs *to* `ea` \
              when `is_to`, else xrefs *from* it. Ordinary next-instruction flow edges are \
              excluded (`XREF_NOFLOW`).",
    }],
};
