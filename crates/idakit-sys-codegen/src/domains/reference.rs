use super::super::model::*;

/// The cross-reference domain: every xref edge at an address returned as one owned `Vec<XrefRec>`
/// snapshot, retiring the raw open-cursor/next/close dance. The single body is hand-written in
/// `facade/reference.cpp` (one walk of an `xrefblk_t`).
///
/// The `*_type_ids` functions there expose this SDK's own `cref_t`/`dref_t` values as `Vec<u8>`
/// alignment sources for idakit's mirror tests. They read header constants only, so they need no
/// kernel.
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
    consts: &[],
    custom_tus: &["facade/reference.cpp"],
    fns: fns! {
        "Every cross-reference edge at `ea` as an owned, `Send` snapshot: xrefs *to* `ea` when \
         `is_to`, else xrefs *from* it. Ordinary next-instruction flow edges are included only \
         when `flow` (`XREF_FLOW` vs `XREF_NOFLOW`)."
            xrefs_build(ea: U64, is_to: Bool, flow: Bool) -> Vec("XrefRec");
        "Whether `ea` has a reference from outside the function that contains it; `false` when \
         `ea` is not inside any function."
            has_external_refs(ea: U64) -> Bool;
        "Whether `ea` has an incoming jump or ordinary-flow code cross-reference."
            has_jump_or_flow_xref(ea: U64) -> Bool;
        "This SDK's `cref_t` (`fl_*`) values in idakit `CodeXref`'s discriminant order, an \
         alignment source pinning the Rust mirror to this SDK build in a test."
            cref_type_ids() -> VecU8;
        "This SDK's `dref_t` (`dr_*`) values in idakit `DataXref`'s discriminant order, an \
         alignment source for a mirror test."
            dref_type_ids() -> VecU8;
    },
};
