use super::super::model::*;
use super::EA;

/// The function-range domain: the SDK POD `range_t` bound as a `Trivial` `ExternType` that crosses
/// by value four ways (bare return, by-value argument, shared-struct field, and `Vec` element). All
/// bodies are hand-written in `facade/range_custom.cc` (they iterate a `func_tail_iterator_t`).
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
    custom_tu: Some("facade/range_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "range_entry_chunk",
            receiver: None,
            args: EA,
            ret: RetKind::ResultExtern("RangeT"),
            body: BodyKind::Custom,
            doc: "Entry chunk (index `0`) of the function containing `ea`, returned by value; \
                  `Err` when no function is there.",
        },
        FnSpec {
            name: "range_size",
            receiver: None,
            args: args!(r: Extern("RangeT")),
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Size (`end - start`) of a `range_t` passed by value.",
        },
        FnSpec {
            name: "range_chunk_info",
            receiver: None,
            args: args!(ea: U64, n: Usize),
            ret: RetKind::ResultShared("ChunkInfo"),
            body: BodyKind::Custom,
            doc: "Chunk `n` of the function at `ea` as a `ChunkInfo`; `Err` when `n` is out of \
                  range.",
        },
        FnSpec {
            name: "range_all_chunks",
            receiver: None,
            args: EA,
            ret: RetKind::ResultVec("RangeT"),
            body: BodyKind::Custom,
            doc: "Every chunk (entry plus tails) of the function at `ea` as one owned `Vec`; \
                  `Err` when no function is there.",
        },
    ],
};
