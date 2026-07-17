use super::super::model::*;

/// The segment domain: mirrors the hand-written `bridge::seg_*` bridge one-for-one. Most bodies
/// are templated, generated into `gen_seg_bodies.cc`; `gen_seg_cmt` is hand-written in
/// `facade/segment.cpp` (its extra `repeatable` argument doesn't fit the `seg_string` template).
///
/// The `*_ids` functions there expose this SDK's own `SEG_*`/`sa*`/`sc*` values as `Vec<u8>`
/// alignment sources for idakit's mirror tests. They read header constants only, so they need no
/// kernel or open database.
pub const SEGMENT: Domain = Domain {
    name: "seg",
    sdk_includes: &["<segment.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    consts: &[],
    custom_tus: &["facade/segment.cpp"],
    fns: fns! {
        "Number of segments in the current database (`get_segm_qty`)."
            gen_seg_qty() -> Usize = scalar("get_segm_qty()");
        "Start address of segment `n`, or `BADADDR` when `n` is out of range."
            gen_seg_start(n: I32) -> U64 = seg_scalar("start_ea", "BADADDR");
        "End address of segment `n`, or `BADADDR` when `n` is out of range."
            gen_seg_end(n: I32) -> U64 = seg_scalar("end_ea", "BADADDR");
        "Permission bits (`SEGPERM_*`) of segment `n`, or `0` when out of range."
            gen_seg_perm(n: I32) -> I32 = seg_scalar("perm", "0");
        "Address bits (16/32/64) of segment `n`, or `0` when out of range."
            gen_seg_bitness(n: I32) -> I32 = seg_scalar("abits()", "0");
        "Visible name of segment `n`; `Err` when `n` is out of range."
            gen_seg_name(n: I32) -> ResultString = seg_string("get_visible_segm_name");
        "Class of segment `n`; `Err` when `n` is out of range or has no class."
            gen_seg_class(n: I32) -> ResultString = seg_string_pos("get_segm_class");
        "Selector (`sel_t`) of segment `n`, or `BADSEL` when `n` is out of range."
            gen_seg_sel(n: I32) -> U64 = seg_scalar("sel", "BADSEL");
        "Segment type code (`SEG_*`) of segment `n`, or `SEG_NORM` when `n` is out of range."
            gen_seg_type(n: I32) -> I32 = seg_scalar("type", "SEG_NORM");
        "Background color (`bgcolor_t`) of segment `n`, or `DEFCOLOR` when `n` is out of range."
            gen_seg_color(n: I32) -> U32 = seg_scalar("color", "DEFCOLOR");
        "Flag bits (`SFL_*`) of segment `n`, or `0` when `n` is out of range."
            gen_seg_flags(n: I32) -> I32 = seg_scalar("flags", "0");
        "Alignment code (`sa*`) of segment `n`, or `0` when `n` is out of range."
            gen_seg_align(n: I32) -> I32 = seg_scalar("align", "0");
        "Combination code (`sc*`) of segment `n`, or `0` when `n` is out of range."
            gen_seg_comb(n: I32) -> I32 = seg_scalar("comb", "0");
        "Index of the segment containing `ea`, or `-1` when none does (`get_segm_num`)."
            gen_seg_at(ea: U64) -> I32 = scalar("get_segm_num(static_cast<ea_t>(ea))");
        "Comment of segment `n` (`repeatable` selects the repeatable channel); `Err` when `n` is \
         out of range."
            gen_seg_cmt(n: I32, repeatable: Bool) -> ResultString;
        "This SDK's `SEG_*` values in idakit `SegmentType`'s discriminant order, an alignment \
         source pinning the Rust mirror to this SDK build in a test."
            seg_type_ids() -> VecU8;
        "This SDK's `sa*` values in idakit `SegmentAlignment`'s discriminant order, an alignment \
         source for a mirror test."
            seg_align_ids() -> VecU8;
        "This SDK's `sc*` values in idakit `SegmentCombination`'s discriminant order, an alignment \
         source for a mirror test."
            seg_comb_ids() -> VecU8;
    },
};
