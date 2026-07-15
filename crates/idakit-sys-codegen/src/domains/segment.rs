use super::super::model::*;

/// The segment domain: mirrors the hand-written `idakit_cxx::seg_*` bridge one-for-one. Every
/// body is templated, generated into `gen_seg_bodies.cc`.
pub const SEGMENT: Domain = Domain {
    name: "seg",
    sdk_includes: &["<segment.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    consts: &[],
    custom_tu: None,
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
    },
};
