use super::super::model::*;

/// The bytes domain: raw byte-range reads, typed scalar reads (each `Err`s when a covered byte is
/// uninitialized), string-literal decode, item classification, and linear navigation. `min_ea`/
/// `max_ea` are templated passthroughs; every other body is hand-written in `facade/bytes.cpp`.
/// Writes (`patch_bytes`, `set_cmt`) and the binary-pattern search handle stay on the raw facade,
/// deferred to the write-side spine.
pub const BYTES: Domain = Domain {
    name: "bytes",
    sdk_includes: &["<bytes.hpp>", "<stdexcept>"],
    externs: &[ExternTy {
        rust_name: "CompiledBinpat",
        cxx_name: "compiled_binpat_vec_t",
        kind: ExternKind::Opaque,
        doc: "A compiled binary-search pattern (`compiled_binpat_vec_t`), owned behind a \
              [`UniquePtr`](cxx::UniquePtr) and passed by `&` to a search.",
        safety: "The type id names the real SDK typedef compiled_binpat_vec_t; Opaque is correct \
                 because it is a qvector with a nontrivial destructor, so it may only cross the \
                 bridge behind a reference or UniquePtr, never by value.",
    }],
    structs: &[SharedStruct {
        name: "BinpatStats",
        doc: "The compiled length and anchor count of a pattern, returned by value from \
              [`binpat_stats`].",
        fields: fields! {
            total: Usize = "Compiled byte length of the pattern.";
            anchors: Usize = "Count of concrete (non-wildcard) bytes; `0` means nothing to match on.";
        },
    }],
    consts: &[],
    custom_tu: Some("facade/bytes.cpp"),
    fns: fns! {
        "The `size` bytes at `ea` as an owned `Vec<u8>`; `Err` when the range is not fully mapped."
            get_bytes(ea: U64, size: Usize) -> ResultVecU8;
        "The byte at `ea`; `Err` when it is uninitialized."
            get_u8(ea: U64) -> ResultU8;
        "The little-endian word at `ea`; `Err` when any covered byte is uninitialized."
            get_u16(ea: U64) -> ResultU16;
        "The little-endian dword at `ea`; `Err` when any covered byte is uninitialized."
            get_u32(ea: U64) -> ResultU32;
        "The little-endian qword at `ea`; `Err` when any covered byte is uninitialized."
            get_u64(ea: U64) -> ResultU64;
        "The auto-detected string literal at `ea` (given its `STRTYPE`) decoded to UTF-8; `Err` \
         when there is none or it cannot be decoded."
            get_strlit(ea: U64, strtype: I32) -> ResultString;
        "Lowest mapped address in the database (`inf_get_min_ea`)."
            min_ea() -> U64 = scalar("inf_get_min_ea()");
        "One past the highest mapped address in the database (`inf_get_max_ea`)."
            max_ea() -> U64 = scalar("inf_get_max_ea()");
        "Flag word of the item at `ea` (`get_flags`)."
            get_flags(ea: U64) -> U64;
        "Start address of the item covering `ea` (`ea` itself when it is an item head)."
            get_item_head(ea: U64) -> U64;
        "Address just past the item covering `ea` (`get_item_end`)."
            get_item_end(ea: U64) -> U64;
        "Next item head after `ea`, searching up to `maxea`, or `BADADDR` when none."
            get_next_head(ea: U64, maxea: U64) -> U64;
        "Previous item head before `ea`, searching down to `minea`, or `BADADDR` when none."
            get_prev_head(ea: U64, minea: U64) -> U64;
        "The regular (or repeatable, when `rptble`) comment at `ea`; `Err` when there is none."
            get_cmt(ea: U64, rptble: Bool) -> ResultString;
        "Compile `pattern` via IDA's own parser (byte width taken from `ea`); `Err` carries the \
         parser's rejection message."
            binpat_compile(ea: U64, pattern: Str, radix: I32) -> ResultUniquePtr("CompiledBinpat");
        "Compile a pattern from raw `bytes` and a per-byte bit `mask`; an empty `mask` means every \
         byte is concrete."
            binpat_from_bytes(bytes: Bytes, mask: Bytes) -> UniquePtr("CompiledBinpat");
        "The compiled length and anchor count of `pat`."
            binpat_stats(pat: ExternRef("CompiledBinpat")) -> Shared("BinpatStats");
        "First address in `[start, end)` matching `pat`, or `BADADDR` when absent (headless: \
         `NOBREAK | NOSHOW` forced)."
            bin_search(start: U64, end: U64, pat: ExternRef("CompiledBinpat"), flags: I32) -> U64;
        "Patch `bytes` over `ea`, or `false` without writing when any target byte is unmapped."
            patch_bytes(ea: U64, bytes: Bytes) -> Bool;
    },
};
