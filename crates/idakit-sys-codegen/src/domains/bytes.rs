use super::super::model::*;
use super::EA;

/// The bytes domain: raw byte-range reads, typed scalar reads (each `Err`s when a covered byte is
/// uninitialized), string-literal decode, item classification, and linear navigation. `min_ea`/
/// `max_ea` are templated passthroughs; every other body is hand-written in `facade/bytes_custom.cc`.
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
    custom_tu: Some("facade/bytes_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "get_bytes",
            receiver: None,
            args: args!(ea: U64, size: Usize),
            ret: RetKind::ResultVecU8,
            body: BodyKind::Custom,
            doc: "The `size` bytes at `ea` as an owned `Vec<u8>`; `Err` when the range is not \
                  fully mapped.",
        },
        FnSpec {
            name: "get_u8",
            receiver: None,
            args: EA,
            ret: RetKind::ResultU8,
            body: BodyKind::Custom,
            doc: "The byte at `ea`; `Err` when it is uninitialized.",
        },
        FnSpec {
            name: "get_u16",
            receiver: None,
            args: EA,
            ret: RetKind::ResultU16,
            body: BodyKind::Custom,
            doc: "The little-endian word at `ea`; `Err` when any covered byte is uninitialized.",
        },
        FnSpec {
            name: "get_u32",
            receiver: None,
            args: EA,
            ret: RetKind::ResultU32,
            body: BodyKind::Custom,
            doc: "The little-endian dword at `ea`; `Err` when any covered byte is uninitialized.",
        },
        FnSpec {
            name: "get_u64",
            receiver: None,
            args: EA,
            ret: RetKind::ResultU64,
            body: BodyKind::Custom,
            doc: "The little-endian qword at `ea`; `Err` when any covered byte is uninitialized.",
        },
        FnSpec {
            name: "get_strlit",
            receiver: None,
            args: args!(ea: U64, strtype: I32),
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "The auto-detected string literal at `ea` (given its `STRTYPE`) decoded to UTF-8; \
                  `Err` when there is none or it cannot be decoded.",
        },
        FnSpec {
            name: "min_ea",
            receiver: None,
            args: &[],
            ret: RetKind::U64,
            body: BodyKind::ScalarCall {
                call: "inf_get_min_ea()",
            },
            doc: "Lowest mapped address in the database (`inf_get_min_ea`).",
        },
        FnSpec {
            name: "max_ea",
            receiver: None,
            args: &[],
            ret: RetKind::U64,
            body: BodyKind::ScalarCall {
                call: "inf_get_max_ea()",
            },
            doc: "One past the highest mapped address in the database (`inf_get_max_ea`).",
        },
        FnSpec {
            name: "get_flags",
            receiver: None,
            args: EA,
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Flag word of the item at `ea` (`get_flags`).",
        },
        FnSpec {
            name: "get_item_head",
            receiver: None,
            args: EA,
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Start address of the item covering `ea` (`ea` itself when it is an item head).",
        },
        FnSpec {
            name: "get_item_end",
            receiver: None,
            args: EA,
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Address just past the item covering `ea` (`get_item_end`).",
        },
        FnSpec {
            name: "get_next_head",
            receiver: None,
            args: args!(ea: U64, maxea: U64),
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Next item head after `ea`, searching up to `maxea`, or `BADADDR` when none.",
        },
        FnSpec {
            name: "get_prev_head",
            receiver: None,
            args: args!(ea: U64, minea: U64),
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Previous item head before `ea`, searching down to `minea`, or `BADADDR` when \
                  none.",
        },
        FnSpec {
            name: "get_cmt",
            receiver: None,
            args: args!(ea: U64, rptble: Bool),
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "The regular (or repeatable, when `rptble`) comment at `ea`; `Err` when there is \
                  none.",
        },
        FnSpec {
            name: "binpat_compile",
            receiver: None,
            args: args!(ea: U64, pattern: Str, radix: I32),
            ret: RetKind::ResultUniquePtr("CompiledBinpat"),
            body: BodyKind::Custom,
            doc: "Compile `pattern` via IDA's own parser (byte width taken from `ea`); `Err` \
                  carries the parser's rejection message.",
        },
        FnSpec {
            name: "binpat_from_bytes",
            receiver: None,
            args: args!(bytes: Bytes, mask: Bytes),
            ret: RetKind::UniquePtr("CompiledBinpat"),
            body: BodyKind::Custom,
            doc: "Compile a pattern from raw `bytes` and a per-byte bit `mask`; an empty `mask` \
                  means every byte is concrete.",
        },
        FnSpec {
            name: "binpat_stats",
            receiver: None,
            args: args!(pat: ExternRef("CompiledBinpat")),
            ret: RetKind::Shared("BinpatStats"),
            body: BodyKind::Custom,
            doc: "The compiled length and anchor count of `pat`.",
        },
        FnSpec {
            name: "bin_search",
            receiver: None,
            args: args!(start: U64, end: U64, pat: ExternRef("CompiledBinpat"), flags: I32),
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "First address in `[start, end)` matching `pat`, or `BADADDR` when absent \
                  (headless: `NOBREAK | NOSHOW` forced).",
        },
        FnSpec {
            name: "patch_bytes",
            receiver: None,
            args: args!(ea: U64, bytes: Bytes),
            ret: RetKind::Bool,
            body: BodyKind::Custom,
            doc: "Patch `bytes` over `ea`, or `false` without writing when any target byte is \
                  unmapped.",
        },
    ],
};
