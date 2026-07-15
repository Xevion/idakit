use super::super::model::*;

/// The function-range domain: the SDK POD `range_t` bound as a `Trivial` `ExternType` that crosses
/// by value four ways (bare return, by-value argument, shared-struct field, and `Vec` element). All
/// bodies are hand-written in `facade/range.cpp` (they iterate a `func_tail_iterator_t`).
pub const RANGE: Domain = Domain {
    name: "range",
    sdk_includes: &["<funcs.hpp>", "<range.hpp>", "<stdexcept>"],
    externs: &[ExternTy {
        rust_name: "RangeT",
        cxx_name: "range_t",
        kind: ExternKind::Trivial(fields! {
            start: U64 = "`start_ea`, inclusive.";
            end: U64 = "`end_ea`, exclusive.";
        }),
        doc: "A `#[repr(C)]` mirror of the SDK's `range_t`, crossing the bridge by value as a \
              `Trivial` `ExternType`.",
        safety: "RangeT's two u64 fields mirror range_t's two ea_t members under __EA64__, and \
                 range_t is trivially move-constructible and destructible, so it crosses by value \
                 soundly. cxx re-checks the triviality half with a C++ static_assert.",
    }],
    structs: &[SharedStruct {
        name: "ChunkInfo",
        doc: "One function chunk: its index paired with its address range.",
        fields: fields! {
            index: Usize = "Zero-based chunk index (the entry chunk is `0`).";
            range: Extern("RangeT") = "The chunk's address range.";
        },
    }],
    consts: &[],
    custom_tu: Some("facade/range.cpp"),
    fns: fns! {
        "Entry chunk (index `0`) of the function containing `ea`, returned by value; `Err` when no \
         function is there."
            range_entry_chunk(ea: U64) -> ResultExtern("RangeT");
        "Size (`end - start`) of a `range_t` passed by value."
            range_size(r: Extern("RangeT")) -> U64;
        "Chunk `n` of the function at `ea` as a `ChunkInfo`; `Err` when `n` is out of range."
            range_chunk_info(ea: U64, n: Usize) -> ResultShared("ChunkInfo");
        "Every chunk (entry plus tails) of the function at `ea` as one owned `Vec`; `Err` when no \
         function is there."
            range_all_chunks(ea: U64) -> ResultVec("RangeT");
    },
};
