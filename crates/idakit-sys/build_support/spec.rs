//! The declarative domain manifest driving the generator engine in [`super`].
//!
//! Every `const` here is one [`Domain`] slice of the facade; [`domains`] lists them in emission
//! order. This file is data only, except the netnode domain, which is matrix-generated in the
//! sibling `netnode` module. The engine that turns a [`Domain`] into the Rust bridge, the C++
//! header, and the `cxx` glue lives in the sibling `gen.rs`.

use std::sync::OnceLock;

use super::{
    Arg, ArgTy, BodyKind, Domain, ExternKind, ExternTy, Field, FieldTy, FnSpec, RetKind,
    SharedStruct, netnode,
};

const N: &[Arg] = &[Arg {
    name: "n",
    ty: ArgTy::I32,
}];

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

/// The import-table domain: the whole table returned as one owned `Vec<ImportRec>` snapshot,
/// retiring the raw handle/index/free dance. The single body is hand-written in
/// `facade/import_custom.cc` (a callback walk over every module's `enum_import_names`).
pub const IMPORT: Domain = Domain {
    name: "import",
    sdk_includes: &["<nalt.hpp>"],
    externs: &[],
    structs: &[SharedStruct {
        name: "ImportRec",
        doc: "One import-table row, returned inside the [`imports_build`] snapshot.",
        fields: &[
            Field {
                name: "ea",
                ty: FieldTy::U64,
                doc: "Address the import is bound to.",
            },
            Field {
                name: "ord",
                ty: FieldTy::U64,
                doc: "Ordinal, or `0` when imported by name.",
            },
            Field {
                name: "name",
                ty: FieldTy::Str,
                doc: "Symbol name, empty when imported by ordinal.",
            },
            Field {
                name: "module",
                ty: FieldTy::Str,
                doc: "Owning module (library) name.",
            },
        ],
    }],
    custom_tu: Some("facade/import_custom.cc"),
    body_helpers: None,
    fns: &[FnSpec {
        name: "imports_build",
        receiver: None,
        args: &[],
        ret: RetKind::Vec("ImportRec"),
        body: BodyKind::Custom,
        doc: "The whole import table as an owned, `Send` snapshot, built in one walk of every \
              module's `enum_import_names`.",
    }],
};

/// The function-range domain: the SDK POD `range_t` bound as a `Trivial` `ExternType` that crosses
/// by value four ways (bare return, by-value argument, shared-struct field, and `Vec` element). All
/// bodies are hand-written in `facade/range_custom.cc` (they iterate a `func_tail_iterator_t`).
pub const RANGE: Domain = Domain {
    name: "range",
    sdk_includes: &["<funcs.hpp>", "<range.hpp>", "<stdexcept>"],
    externs: &[ExternTy {
        rust_name: "RangeT",
        cxx_name: "range_t",
        kind: ExternKind::Trivial(&[
            Field {
                name: "start",
                ty: FieldTy::U64,
                doc: "`start_ea`, inclusive.",
            },
            Field {
                name: "end",
                ty: FieldTy::U64,
                doc: "`end_ea`, exclusive.",
            },
        ]),
        doc: "A `#[repr(C)]` mirror of the SDK's `range_t`, crossing the bridge by value as a \
              `Trivial` `ExternType`.",
        safety: "RangeT's two u64 fields mirror range_t's two ea_t members under __EA64__, and \
                 range_t is trivially move-constructible and destructible, so it crosses by value \
                 soundly. cxx re-checks the triviality half with a C++ static_assert.",
    }],
    structs: &[SharedStruct {
        name: "ChunkInfo",
        doc: "One function chunk: its index paired with its address range.",
        fields: &[
            Field {
                name: "index",
                ty: FieldTy::Usize,
                doc: "Zero-based chunk index (the entry chunk is `0`).",
            },
            Field {
                name: "range",
                ty: FieldTy::Extern("RangeT"),
                doc: "The chunk's address range.",
            },
        ],
    }],
    custom_tu: Some("facade/range_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "range_entry_chunk",
            receiver: None,
            args: &[Arg {
                name: "ea",
                ty: ArgTy::U64,
            }],
            ret: RetKind::ResultExtern("RangeT"),
            body: BodyKind::Custom,
            doc: "Entry chunk (index `0`) of the function containing `ea`, returned by value; \
                  `Err` when no function is there.",
        },
        FnSpec {
            name: "range_size",
            receiver: None,
            args: &[Arg {
                name: "r",
                ty: ArgTy::Extern("RangeT"),
            }],
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Size (`end - start`) of a `range_t` passed by value.",
        },
        FnSpec {
            name: "range_chunk_info",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "n",
                    ty: ArgTy::Usize,
                },
            ],
            ret: RetKind::ResultShared("ChunkInfo"),
            body: BodyKind::Custom,
            doc: "Chunk `n` of the function at `ea` as a `ChunkInfo`; `Err` when `n` is out of \
                  range.",
        },
        FnSpec {
            name: "range_all_chunks",
            receiver: None,
            args: &[Arg {
                name: "ea",
                ty: ArgTy::U64,
            }],
            ret: RetKind::ResultVec("RangeT"),
            body: BodyKind::Custom,
            doc: "Every chunk (entry plus tails) of the function at `ea` as one owned `Vec`; \
                  `Err` when no function is there.",
        },
    ],
};

const EA: &[Arg] = &[Arg {
    name: "ea",
    ty: ArgTy::U64,
}];

/// The function domain: per-function scalar accessors and the name string. Function *chunks* are
/// the `range` domain (`range_all_chunks`), so no chunk accessor lives here. `func_qty` is a
/// templated passthrough; the lookup accessors are hand-written in `facade/function_custom.cc`.
pub const FUNCTION: Domain = Domain {
    name: "function",
    sdk_includes: &["<funcs.hpp>", "<name.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    custom_tu: Some("facade/function_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "func_qty",
            receiver: None,
            args: &[],
            ret: RetKind::Usize,
            body: BodyKind::ScalarCall {
                call: "get_func_qty()",
            },
            doc: "Number of functions in the database (`get_func_qty`).",
        },
        FnSpec {
            name: "func_ea",
            receiver: None,
            args: &[Arg {
                name: "n",
                ty: ArgTy::Usize,
            }],
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Entry address of the `n`-th function, or `BADADDR` when `n` is out of range.",
        },
        FnSpec {
            name: "func_start",
            receiver: None,
            args: EA,
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Entry address of the function containing `ea`, or `BADADDR` when there is none.",
        },
        FnSpec {
            name: "func_end",
            receiver: None,
            args: EA,
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Entry-chunk end address of the function at `ea`, or `BADADDR` when not a function.",
        },
        FnSpec {
            name: "func_flags",
            receiver: None,
            args: EA,
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "`func_t::flags` of the function at `ea`, or `0` when `ea` is not a function.",
        },
        FnSpec {
            name: "func_chunk_qty",
            receiver: None,
            args: EA,
            ret: RetKind::I32,
            body: BodyKind::Custom,
            doc: "Number of chunks (entry plus tails) of the function at `ea`, or `0`.",
        },
        FnSpec {
            name: "func_name",
            receiver: None,
            args: EA,
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Name of the function at `ea`; `Err` when it has none.",
        },
    ],
};

const IDX: &[Arg] = &[Arg {
    name: "idx",
    ty: ArgTy::Usize,
}];

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

/// The meta domain: database-wide metadata (bitness, image base) and four identity strings
/// (processor, file-type text, input path, root filename). All bodies are hand-written in
/// `facade/meta_custom.cc`; the string getters throw when the SDK has no value.
pub const META: Domain = Domain {
    name: "meta",
    sdk_includes: &["<nalt.hpp>", "<loader.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    custom_tu: Some("facade/meta_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "bitness",
            receiver: None,
            args: &[],
            ret: RetKind::I32,
            body: BodyKind::Custom,
            doc: "Application bitness (`inf_get_app_bitness`): 16, 32, or 64.",
        },
        FnSpec {
            name: "image_base",
            receiver: None,
            args: &[],
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Preferred load address of the input (`get_imagebase`).",
        },
        FnSpec {
            name: "proc_name",
            receiver: None,
            args: &[],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Processor module id, e.g. `metapc`; `Err` when none is set.",
        },
        FnSpec {
            name: "file_type_name",
            receiver: None,
            args: &[],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Human-readable input file format text; `Err` when unavailable.",
        },
        FnSpec {
            name: "input_path",
            receiver: None,
            args: &[],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Full path of the analyzed input; `Err` when unknown.",
        },
        FnSpec {
            name: "root_filename",
            receiver: None,
            args: &[],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Base filename of the input; `Err` when unknown.",
        },
    ],
};

/// The name domain: name lookups (address<->name, demangle), the name-list accessors, and the
/// three flags-word name classifiers. Every body is hand-written in `facade/name_custom.cc` (the
/// getters throw on no-name, and SDK calls are `::`-qualified to avoid recursing on the shared
/// symbol spellings).
pub const NAME: Domain = Domain {
    name: "name",
    sdk_includes: &["<name.hpp>", "<bytes.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    custom_tu: Some("facade/name_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "get_ea_name",
            receiver: None,
            args: EA,
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Name at address `ea`; `Err` when the address has none.",
        },
        FnSpec {
            name: "get_name_ea",
            receiver: None,
            args: &[Arg {
                name: "name",
                ty: ArgTy::Str,
            }],
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Address the symbol `name` resolves to, or `BADADDR` when it is unknown.",
        },
        FnSpec {
            name: "demangle_name",
            receiver: None,
            args: &[Arg {
                name: "name",
                ty: ArgTy::Str,
            }],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Fully demangled form of `name`; `Err` when `name` is not mangled.",
        },
        FnSpec {
            name: "nlist_size",
            receiver: None,
            args: &[],
            ret: RetKind::Usize,
            body: BodyKind::Custom,
            doc: "Number of entries in the sorted name list (`get_nlist_size`).",
        },
        FnSpec {
            name: "nlist_ea",
            receiver: None,
            args: IDX,
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Address of name-list entry `idx`.",
        },
        FnSpec {
            name: "nlist_name",
            receiver: None,
            args: IDX,
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Name of name-list entry `idx`; `Err` when `idx` is out of range.",
        },
        FnSpec {
            name: "has_user_name",
            receiver: None,
            args: &[Arg {
                name: "flags",
                ty: ArgTy::U64,
            }],
            ret: RetKind::Bool,
            body: BodyKind::Custom,
            doc: "Whether a flags word marks a user-given (explicit) name.",
        },
        FnSpec {
            name: "has_auto_name",
            receiver: None,
            args: &[Arg {
                name: "flags",
                ty: ArgTy::U64,
            }],
            ret: RetKind::Bool,
            body: BodyKind::Custom,
            doc: "Whether a flags word marks an IDA-generated (auto) name.",
        },
        FnSpec {
            name: "has_dummy_name",
            receiver: None,
            args: &[Arg {
                name: "flags",
                ty: ArgTy::U64,
            }],
            ret: RetKind::Bool,
            body: BodyKind::Custom,
            doc: "Whether a flags word marks a dummy (address-derived) name.",
        },
    ],
};

/// The strings domain: IDA's string list plus per-literal decoding. `strlist_build` runs an
/// O(database) scan to (re)build the list; `strlist_item` returns the nth entry as a `StrlistItem`
/// (throws when out of range), and `strlit_contents` decodes one literal to UTF-8 (throws when
/// undecodable). All bodies are hand-written in `facade/strings_custom.cc`.
pub const STRINGS: Domain = Domain {
    name: "strings",
    sdk_includes: &["<strlist.hpp>", "<bytes.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[SharedStruct {
        name: "StrlistItem",
        doc: "One string-list entry: its address, octet length, and `STRTYPE` code.",
        fields: &[
            Field {
                name: "ea",
                ty: FieldTy::U64,
                doc: "Address of the string literal.",
            },
            Field {
                name: "length",
                ty: FieldTy::I32,
                doc: "Length in octets (raw bytes, not decoded characters).",
            },
            Field {
                name: "type_",
                ty: FieldTy::I32,
                doc: "`STRTYPE` code describing the encoding.",
            },
        ],
    }],
    custom_tu: Some("facade/strings_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "strlist_build",
            receiver: None,
            args: &[],
            ret: RetKind::Unit,
            body: BodyKind::Custom,
            doc: "(Re)build IDA's string list, an O(database) scan of the whole image.",
        },
        FnSpec {
            name: "strlist_qty",
            receiver: None,
            args: &[],
            ret: RetKind::Usize,
            body: BodyKind::Custom,
            doc: "Number of entries in the current string list (`get_strlist_qty`).",
        },
        FnSpec {
            name: "strlist_item",
            receiver: None,
            args: &[Arg {
                name: "n",
                ty: ArgTy::Usize,
            }],
            ret: RetKind::ResultShared("StrlistItem"),
            body: BodyKind::Custom,
            doc: "The `n`-th string-list entry as a `StrlistItem`; `Err` when `n` is out of range.",
        },
        FnSpec {
            name: "strlit_contents",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "len",
                    ty: ArgTy::Usize,
                },
                Arg {
                    name: "strtype",
                    ty: ArgTy::I32,
                },
            ],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Decode the string literal at `ea` (given octet length and `STRTYPE`) to UTF-8; \
                  `Err` when it cannot be decoded.",
        },
    ],
};

/// The control-flow-graph domain: the SDK's `qflow_chart_t` bound as an `Opaque` `ExternType`
/// (`FlowChart`) owned by [`UniquePtr`](cxx::UniquePtr), so its C++ deleter handles cleanup without
/// a manual free function or a hand-written `Drop` impl. `size` is a `self:`-member call bound straight to
/// `qflow_chart_t::size()` (no facade body); every other accessor is a free function over a
/// `&FlowChart`, hand-written in `facade/cfg_custom.cc`. Block bounds return by value as a `BlockInfo`
/// shared struct, and the successor/predecessor edge lists copy into owned `Vec<u32>`.
pub const CFG: Domain = Domain {
    name: "cfg",
    sdk_includes: &["<funcs.hpp>", "<gdl.hpp>", "<stdexcept>"],
    externs: &[ExternTy {
        rust_name: "FlowChart",
        cxx_name: "qflow_chart_t",
        kind: ExternKind::Opaque,
        doc: "The SDK's `qflow_chart_t`, an opaque control-flow graph handled only behind \
              indirection (`&FlowChart` or `UniquePtr<FlowChart>`).",
        safety: "The type id names the real SDK class qflow_chart_t; Opaque is correct because \
                 qflow_chart_t has a virtual destructor (nontrivial), so it may only cross the \
                 bridge behind a reference or UniquePtr, never by value.",
    }],
    structs: &[SharedStruct {
        name: "BlockInfo",
        doc: "One basic block's bounds and kind, returned by value from [`cfg_block`].",
        fields: &[
            Field {
                name: "start",
                ty: FieldTy::U64,
                doc: "Start address of the block.",
            },
            Field {
                name: "end",
                ty: FieldTy::U64,
                doc: "End address (exclusive) of the block.",
            },
            Field {
                name: "kind",
                ty: FieldTy::I32,
                doc: "Raw `fc_block_type_t` discriminant (`fcb_normal`, `fcb_ret`, ...).",
            },
        ],
    }],
    custom_tu: Some("facade/cfg_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "cfg_build",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "flags",
                    ty: ArgTy::I32,
                },
            ],
            ret: RetKind::ResultUniquePtr("FlowChart"),
            body: BodyKind::Custom,
            doc: "Build the flow chart for the function containing `ea`; `Err` when no function \
                  is there. Runs analysis, so it can also fail from a thrown SDK exception.",
        },
        FnSpec {
            name: "size",
            receiver: Some("FlowChart"),
            args: &[],
            ret: RetKind::I32,
            body: BodyKind::Custom,
            doc: "Number of basic blocks, bound to `qflow_chart_t::size()` directly (the `self:` \
                  receiver). The return is `i32` to match the member's exact `int` signature.",
        },
        FnSpec {
            name: "cfg_nblocks",
            receiver: None,
            args: &[Arg {
                name: "fc",
                ty: ArgTy::ExternRef("FlowChart"),
            }],
            ret: RetKind::Usize,
            body: BodyKind::Custom,
            doc: "Total number of basic blocks (external blocks included).",
        },
        FnSpec {
            name: "cfg_nproper",
            receiver: None,
            args: &[Arg {
                name: "fc",
                ty: ArgTy::ExternRef("FlowChart"),
            }],
            ret: RetKind::Usize,
            body: BodyKind::Custom,
            doc: "Number of blocks belonging to the function's own range.",
        },
        FnSpec {
            name: "cfg_block",
            receiver: None,
            args: &[
                Arg {
                    name: "fc",
                    ty: ArgTy::ExternRef("FlowChart"),
                },
                Arg {
                    name: "n",
                    ty: ArgTy::Usize,
                },
            ],
            ret: RetKind::ResultShared("BlockInfo"),
            body: BodyKind::Custom,
            doc: "Bounds and kind of block `n`; `Err` when `n` is out of range.",
        },
        FnSpec {
            name: "cfg_nsucc",
            receiver: None,
            args: &[
                Arg {
                    name: "fc",
                    ty: ArgTy::ExternRef("FlowChart"),
                },
                Arg {
                    name: "n",
                    ty: ArgTy::Usize,
                },
            ],
            ret: RetKind::Usize,
            body: BodyKind::Custom,
            doc: "Number of successors of block `n` (`0` when `n` is out of range).",
        },
        FnSpec {
            name: "cfg_succ",
            receiver: None,
            args: &[
                Arg {
                    name: "fc",
                    ty: ArgTy::ExternRef("FlowChart"),
                },
                Arg {
                    name: "n",
                    ty: ArgTy::Usize,
                },
                Arg {
                    name: "i",
                    ty: ArgTy::Usize,
                },
            ],
            ret: RetKind::ResultUsize,
            body: BodyKind::Custom,
            doc: "The `i`-th successor block index of block `n`; `Err` when `n`/`i` is out of range.",
        },
        FnSpec {
            name: "cfg_npred",
            receiver: None,
            args: &[
                Arg {
                    name: "fc",
                    ty: ArgTy::ExternRef("FlowChart"),
                },
                Arg {
                    name: "n",
                    ty: ArgTy::Usize,
                },
            ],
            ret: RetKind::Usize,
            body: BodyKind::Custom,
            doc: "Number of predecessors of block `n` (`0` when `n` is out of range).",
        },
        FnSpec {
            name: "cfg_pred",
            receiver: None,
            args: &[
                Arg {
                    name: "fc",
                    ty: ArgTy::ExternRef("FlowChart"),
                },
                Arg {
                    name: "n",
                    ty: ArgTy::Usize,
                },
                Arg {
                    name: "i",
                    ty: ArgTy::Usize,
                },
            ],
            ret: RetKind::ResultUsize,
            body: BodyKind::Custom,
            doc: "The `i`-th predecessor block index of block `n`; `Err` when `n`/`i` is out of \
                  range.",
        },
        FnSpec {
            name: "cfg_succs",
            receiver: None,
            args: &[
                Arg {
                    name: "fc",
                    ty: ArgTy::ExternRef("FlowChart"),
                },
                Arg {
                    name: "n",
                    ty: ArgTy::Usize,
                },
            ],
            ret: RetKind::ResultVecU32,
            body: BodyKind::Custom,
            doc: "The whole successor edge list of block `n` as one owned `Vec<u32>`; `Err` when \
                  `n` is out of range.",
        },
        FnSpec {
            name: "cfg_preds",
            receiver: None,
            args: &[
                Arg {
                    name: "fc",
                    ty: ArgTy::ExternRef("FlowChart"),
                },
                Arg {
                    name: "n",
                    ty: ArgTy::Usize,
                },
            ],
            ret: RetKind::ResultVecU32,
            body: BodyKind::Custom,
            doc: "The whole predecessor edge list of block `n` as one owned `Vec<u32>`; `Err` \
                  when `n` is out of range.",
        },
    ],
};

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
        fields: &[
            Field {
                name: "from",
                ty: FieldTy::U64,
                doc: "Source address of the reference.",
            },
            Field {
                name: "to",
                ty: FieldTy::U64,
                doc: "Target address of the reference.",
            },
            Field {
                name: "type_",
                ty: FieldTy::I32,
                doc: "Raw `cref_t`/`dref_t` type code of the edge.",
            },
            Field {
                name: "iscode",
                ty: FieldTy::Bool,
                doc: "`true` for a code reference, `false` for a data reference.",
            },
            Field {
                name: "user",
                ty: FieldTy::Bool,
                doc: "`true` when user-defined, `false` when IDA's analysis generated it.",
            },
        ],
    }],
    custom_tu: Some("facade/reference_custom.cc"),
    body_helpers: None,
    fns: &[FnSpec {
        name: "xrefs_build",
        receiver: None,
        args: &[
            Arg {
                name: "ea",
                ty: ArgTy::U64,
            },
            Arg {
                name: "is_to",
                ty: ArgTy::Bool,
            },
        ],
        ret: RetKind::Vec("XrefRec"),
        body: BodyKind::Custom,
        doc: "Every cross-reference edge at `ea` as an owned, `Send` snapshot: xrefs *to* `ea` \
              when `is_to`, else xrefs *from* it. Ordinary next-instruction flow edges are \
              excluded (`XREF_NOFLOW`).",
    }],
};

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
        fields: &[
            Field {
                name: "total",
                ty: FieldTy::Usize,
                doc: "Compiled byte length of the pattern.",
            },
            Field {
                name: "anchors",
                ty: FieldTy::Usize,
                doc: "Count of concrete (non-wildcard) bytes; `0` means nothing to match on.",
            },
        ],
    }],
    custom_tu: Some("facade/bytes_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "get_bytes",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "size",
                    ty: ArgTy::Usize,
                },
            ],
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
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "strtype",
                    ty: ArgTy::I32,
                },
            ],
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
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "maxea",
                    ty: ArgTy::U64,
                },
            ],
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Next item head after `ea`, searching up to `maxea`, or `BADADDR` when none.",
        },
        FnSpec {
            name: "get_prev_head",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "minea",
                    ty: ArgTy::U64,
                },
            ],
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Previous item head before `ea`, searching down to `minea`, or `BADADDR` when \
                  none.",
        },
        FnSpec {
            name: "get_cmt",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "rptble",
                    ty: ArgTy::Bool,
                },
            ],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "The regular (or repeatable, when `rptble`) comment at `ea`; `Err` when there is \
                  none.",
        },
        FnSpec {
            name: "binpat_compile",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "pattern",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "radix",
                    ty: ArgTy::I32,
                },
            ],
            ret: RetKind::ResultUniquePtr("CompiledBinpat"),
            body: BodyKind::Custom,
            doc: "Compile `pattern` via IDA's own parser (byte width taken from `ea`); `Err` \
                  carries the parser's rejection message.",
        },
        FnSpec {
            name: "binpat_from_bytes",
            receiver: None,
            args: &[
                Arg {
                    name: "bytes",
                    ty: ArgTy::Bytes,
                },
                Arg {
                    name: "mask",
                    ty: ArgTy::Bytes,
                },
            ],
            ret: RetKind::UniquePtr("CompiledBinpat"),
            body: BodyKind::Custom,
            doc: "Compile a pattern from raw `bytes` and a per-byte bit `mask`; an empty `mask` \
                  means every byte is concrete.",
        },
        FnSpec {
            name: "binpat_stats",
            receiver: None,
            args: &[Arg {
                name: "pat",
                ty: ArgTy::ExternRef("CompiledBinpat"),
            }],
            ret: RetKind::Shared("BinpatStats"),
            body: BodyKind::Custom,
            doc: "The compiled length and anchor count of `pat`.",
        },
        FnSpec {
            name: "bin_search",
            receiver: None,
            args: &[
                Arg {
                    name: "start",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "end",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "pat",
                    ty: ArgTy::ExternRef("CompiledBinpat"),
                },
                Arg {
                    name: "flags",
                    ty: ArgTy::I32,
                },
            ],
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "First address in `[start, end)` matching `pat`, or `BADADDR` when absent \
                  (headless: `NOBREAK | NOSHOW` forced).",
        },
        FnSpec {
            name: "patch_bytes",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "bytes",
                    ty: ArgTy::Bytes,
                },
            ],
            ret: RetKind::Bool,
            body: BodyKind::Custom,
            doc: "Patch `bytes` over `ea`, or `false` without writing when any target byte is \
                  unmapped.",
        },
    ],
};

/// The instruction-decode domain: x86/x64 `decode_insn` folded into an owned, by-value
/// [`InstructionData`] shared struct instead of a flat out-param POD. The struct nests
/// [`OperandData`] (a `Vec`, right-sized to the populated operands) and [`RegisterData`] by value,
/// and carries a `status` field standing in for the raw facade's return code, so the whole decode
/// crosses as one value with no `Result` (the five outcomes, ok plus `-1..-4`, are structured
/// payloads a string-only `cxx` exception could not carry). `reg_class_ids`/`op_dtype_ids` expose
/// the facade's own discriminants as `Vec<u8>` alignment sources for idakit's mirror tests. The
/// whole body is hand-written in `facade/instruction_custom.cc`.
pub const INSTRUCTION: Domain = Domain {
    name: "instruction",
    sdk_includes: &[],
    externs: &[],
    structs: &[
        SharedStruct {
            name: "RegisterData",
            doc: "One register reference in a decoded operand, nested by value in an \
                  [`OperandData`].",
            fields: &[
                Field {
                    name: "num",
                    ty: FieldTy::U16,
                    doc: "Register number, or `0xFFFF` for an absent base/index slot.",
                },
                Field {
                    name: "cls",
                    ty: FieldTy::U8,
                    doc: "idakit `RegisterClass` code.",
                },
                Field {
                    name: "width",
                    ty: FieldTy::U8,
                    doc: "Byte width selecting the name alias.",
                },
                Field {
                    name: "name",
                    ty: FieldTy::Str,
                    doc: "IDA's resolved register name, empty if unresolved.",
                },
            ],
        },
        SharedStruct {
            name: "OperandData",
            doc: "One decoded operand; which fields are meaningful depends on `kind`.",
            fields: &[
                Field {
                    name: "kind",
                    ty: FieldTy::U8,
                    doc: "Semantic kind (0 reg, 1 mem, 2 imm, 3 near, 4 far).",
                },
                Field {
                    name: "idx",
                    ty: FieldTy::U8,
                    doc: "Original operand slot index (feature bits are keyed by it).",
                },
                Field {
                    name: "data_type",
                    ty: FieldTy::U8,
                    doc: "Raw `op_dtype_t`.",
                },
                Field {
                    name: "access",
                    ty: FieldTy::U8,
                    doc: "Access bits: bit0 read, bit1 written.",
                },
                Field {
                    name: "scale",
                    ty: FieldTy::U8,
                    doc: "Memory index scale multiplier (1/2/4/8).",
                },
                Field {
                    name: "reg",
                    ty: FieldTy::Struct("RegisterData"),
                    doc: "Register (kind = reg). Named `reg`, not `register` (a C++ keyword).",
                },
                Field {
                    name: "base",
                    ty: FieldTy::Struct("RegisterData"),
                    doc: "Memory base register (kind = mem).",
                },
                Field {
                    name: "index",
                    ty: FieldTy::Struct("RegisterData"),
                    doc: "Memory index register (kind = mem).",
                },
                Field {
                    name: "disp",
                    ty: FieldTy::I64,
                    doc: "Memory displacement (kind = mem).",
                },
                Field {
                    name: "value",
                    ty: FieldTy::U64,
                    doc: "Immediate value (kind = imm) or far offset (kind = far).",
                },
                Field {
                    name: "addr",
                    ty: FieldTy::U64,
                    doc: "Near target, or memory static target / `BADADDR` (kind = near/mem).",
                },
                Field {
                    name: "sel",
                    ty: FieldTy::U16,
                    doc: "Far selector (kind = far).",
                },
            ],
        },
        SharedStruct {
            name: "InstructionData",
            doc: "A decoded instruction, returned by value from [`decode_insn`]; `status` carries \
                  the raw result code and `ops` is right-sized to the populated operands.",
            fields: &[
                Field {
                    name: "status",
                    ty: FieldTy::I32,
                    doc: "Result code: 0 ok, -1 no instruction, -2 unsupported processor, \
                          -3 unmodeled operand, -4 unmodeled register.",
                },
                Field {
                    name: "err_op",
                    ty: FieldTy::U8,
                    doc: "On the -3/-4 status, the offending operand index.",
                },
                Field {
                    name: "err_optype",
                    ty: FieldTy::U8,
                    doc: "On -3 the offending raw operand type; on -4 the register number.",
                },
                Field {
                    name: "address",
                    ty: FieldTy::U64,
                    doc: "Instruction address.",
                },
                Field {
                    name: "target",
                    ty: FieldTy::U64,
                    doc: "Direct branch/call target, or `BADADDR`.",
                },
                Field {
                    name: "itype",
                    ty: FieldTy::U16,
                    doc: "Processor-local canonical instruction id.",
                },
                Field {
                    name: "len",
                    ty: FieldTy::U8,
                    doc: "Encoded length in bytes.",
                },
                Field {
                    name: "isa",
                    ty: FieldTy::U8,
                    doc: "0 = x86, 1 = x64.",
                },
                Field {
                    name: "nops",
                    ty: FieldTy::U8,
                    doc: "Number of populated operands (matches `ops.len()`).",
                },
                Field {
                    name: "flow",
                    ty: FieldTy::U8,
                    doc: "`IDAKIT_FLOW_*` bit flags.",
                },
                Field {
                    name: "mnemonic",
                    ty: FieldTy::Str,
                    doc: "Canonical mnemonic.",
                },
                Field {
                    name: "ops",
                    ty: FieldTy::VecStruct("OperandData"),
                    doc: "Decoded operands; only meaningful when `status == 0`.",
                },
            ],
        },
    ],
    custom_tu: Some("facade/instruction_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "decode_insn",
            receiver: None,
            args: &[Arg {
                name: "ea",
                ty: ArgTy::U64,
            }],
            ret: RetKind::Shared("InstructionData"),
            body: BodyKind::Custom,
            doc: "Decode the instruction at `ea`, folding raw operands into semantic kinds with \
                  resolved register names and control-flow facts. Infallible at the boundary: the \
                  result code lands in [`InstructionData::status`] rather than throwing, since the \
                  -3/-4 failures carry structured payloads.",
        },
        FnSpec {
            name: "reg_class_ids",
            receiver: None,
            args: &[],
            ret: RetKind::VecU8,
            body: BodyKind::Custom,
            doc: "The facade's `RegisterClass` codes in idakit's discriminant order, an alignment \
                  source pinning the Rust mirror to this SDK build in a test.",
        },
        FnSpec {
            name: "op_dtype_ids",
            receiver: None,
            args: &[],
            ret: RetKind::VecU8,
            body: BodyKind::Custom,
            doc: "This SDK's `op_dtype_t` (`dt_*`) values in idakit `DataType`'s discriminant \
                  order, an alignment source for a mirror test.",
        },
    ],
};

/// The Hex-Rays decompiler domain: the SDK's `cfuncptr_t` (`qrefcnt_t<cfunc_t>`) bound as an
/// `Opaque` `ExternType` ([`CFunc`]) owned by [`UniquePtr`](cxx::UniquePtr), so its cxx deleter runs
/// `~cfuncptr_t` (`release()`) on drop, retiring the raw `new`/`delete` handle dance. `decompile`
/// wraps the microcode pipeline in the facade's `guarded<>` trap and throws on failure; the read
/// accessors take a borrowed `&CFunc` and return pseudocode, ctree counts, and the extraction-gap
/// diagnostic. The ctree walk itself is a separate hand-written `cxx` bridge (`bridge_visitors`) fed
/// the same `&CFunc`. Bodies are in `facade/hexrays_custom.cc`.
pub const HEXRAYS: Domain = Domain {
    name: "hexrays",
    // funcs.hpp (pulling bytes.hpp/xref.hpp) precedes hexrays.hpp so the generated header is
    // self-sufficient: hexrays.hpp names casevec_t from xref.hpp, and gen_bridge.h pulls this
    // header into every domain TU.
    sdk_includes: &["<funcs.hpp>", "<hexrays.hpp>"],
    externs: &[ExternTy {
        rust_name: "CFunc",
        cxx_name: "cfuncptr_t",
        kind: ExternKind::Opaque,
        doc: "The SDK's `cfuncptr_t` (`qrefcnt_t<cfunc_t>`), an opaque decompilation result \
              handled only behind indirection (`&CFunc` or `UniquePtr<CFunc>`).",
        safety: "The type id names the real SDK typedef cfuncptr_t; Opaque is correct because \
                 qrefcnt_t<cfunc_t> has a nontrivial copy-ctor and destructor, so it may only cross \
                 the bridge behind a reference or UniquePtr, never by value.",
    }],
    structs: &[
        SharedStruct {
            name: "CtreeCounts",
            doc: "Statement, expression, and call-site counts of a decompiled function's ctree, \
                  returned by value from [`cfunc_counts`].",
            fields: &[
                Field {
                    name: "insns",
                    ty: FieldTy::I32,
                    doc: "Number of statement nodes.",
                },
                Field {
                    name: "expressions",
                    ty: FieldTy::I32,
                    doc: "Number of expression nodes.",
                },
                Field {
                    name: "calls",
                    ty: FieldTy::I32,
                    doc: "Number of call sites.",
                },
            ],
        },
        SharedStruct {
            name: "ExprGap",
            doc: "The ctree extraction-fidelity diagnostic, returned by value from \
                  [`cfunc_expr_gap`].",
            fields: &[
                Field {
                    name: "visitor_total",
                    ty: FieldTy::I32,
                    doc: "Every expression the SDK's own ctree visitor sees.",
                },
                Field {
                    name: "expected",
                    ty: FieldTy::I32,
                    doc: "How many the extraction walker should materialize (visitor total minus \
                          elided empty-expression placeholders in optional slots).",
                },
            ],
        },
    ],
    custom_tu: Some("facade/hexrays_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "decompile",
            receiver: None,
            args: &[Arg {
                name: "ea",
                ty: ArgTy::U64,
            }],
            ret: RetKind::ResultUniquePtr("CFunc"),
            body: BodyKind::Custom,
            doc: "Decompile the function at `ea` into a heap `cfuncptr_t` owned by a \
                  [`UniquePtr`](cxx::UniquePtr) (one owned ref); `Err` on any decompile failure. \
                  Wrapped in the facade trap, so a fatal `exit()` surfaces as a trapped `Err` the \
                  caller distinguishes via its own trap query. The `UniquePtr`'s cxx deleter runs \
                  `~cfuncptr_t` (`release()`) on drop.",
        },
        FnSpec {
            name: "cfunc_pseudocode",
            receiver: None,
            args: &[Arg {
                name: "cf",
                ty: ArgTy::ExternRef("CFunc"),
            }],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "The rendered pseudocode of `cf`, tags stripped; `Err` if the SDK cannot produce \
                  it.",
        },
        FnSpec {
            name: "cfunc_counts",
            receiver: None,
            args: &[Arg {
                name: "cf",
                ty: ArgTy::ExternRef("CFunc"),
            }],
            ret: RetKind::Shared("CtreeCounts"),
            body: BodyKind::Custom,
            doc: "Statement, expression, and call-site counts of `cf`'s ctree.",
        },
        FnSpec {
            name: "cfunc_refresh_text",
            receiver: None,
            args: &[Arg {
                name: "cf",
                ty: ArgTy::ExternRef("CFunc"),
            }],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Re-print `cf`'s pseudocode from its current ctree (`refresh_func_ctext`), then \
                  return it; `Err` if the SDK cannot produce it. Cheap compared to a re-decompile, \
                  since it walks the already-decompiled ctree, but reflects only what the ctree \
                  already encodes (a rename resolves fresh; a structural or type change needs a \
                  fresh [`decompile`]).",
        },
        FnSpec {
            name: "cfunc_expr_gap",
            receiver: None,
            args: &[Arg {
                name: "cf",
                ty: ArgTy::ExternRef("CFunc"),
            }],
            ret: RetKind::Shared("ExprGap"),
            body: BodyKind::Custom,
            doc: "The extraction-fidelity diagnostic for `cf`: total expressions the SDK visitor \
                  sees vs how many the extraction walker should materialize.",
        },
        FnSpec {
            name: "hexrays_init",
            receiver: None,
            args: &[],
            ret: RetKind::Bool,
            body: BodyKind::Custom,
            doc: "Initialize the Hex-Rays decompiler (loading the plugin if needed); `true` once \
                  ready.",
        },
        FnSpec {
            name: "mark_cfunc_dirty",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "close_views",
                    ty: ArgTy::Bool,
                },
            ],
            ret: RetKind::Bool,
            body: BodyKind::Custom,
            doc: "Evict the cached decompilation for `ea`; `true` if an entry existed, `false` if \
                  none or the decompiler is not initialized.",
        },
        FnSpec {
            name: "clear_cached_cfuncs",
            receiver: None,
            args: &[],
            ret: RetKind::Unit,
            body: BodyKind::Custom,
            doc: "Evict every cached decompilation; a no-op if the decompiler is not initialized.",
        },
        FnSpec {
            name: "has_cached_cfunc",
            receiver: None,
            args: &[Arg {
                name: "ea",
                ty: ArgTy::U64,
            }],
            ret: RetKind::Bool,
            body: BodyKind::Custom,
            doc: "Whether `ea` has a cached decompilation; `false` if none or not initialized.",
        },
    ],
};

/// The type-write domain: parse, resolve, build, and apply `tinfo`s, define/delete/rename types in
/// the local til, and edit UDT/enum members. Every call returns a [`TypeWriteResult`] (or [`SigWriteResult`]
/// for the two signature-surgery fns that also report the parameter count) in place of the raw
/// facade's `int` code plus error-buffer out-param: the struct's `code` carries the same return
/// value and `reason` the captured diagnostic. Bodies are hand-written in `facade/type_build_custom.cc`.
pub const TYPE_BUILD: Domain = Domain {
    name: "type_build",
    sdk_includes: &["<kernwin.hpp>", "<nalt.hpp>", "<typeinf.hpp>"],
    externs: &[ExternTy {
        rust_name: "TInfo",
        cxx_name: "tinfo_t",
        kind: ExternKind::Opaque,
        doc: "The SDK's `tinfo_t`, an opaque type-info handle handled only behind indirection \
              (`&TInfo` or `UniquePtr<TInfo>`).",
        safety: "The type id names the real SDK class tinfo_t; Opaque is correct because tinfo_t \
                 has a nontrivial copy-ctor and destructor, so it may only cross the bridge behind \
                 a reference or UniquePtr, never by value. The UniquePtr's cxx deleter runs \
                 ~tinfo_t, matching the raw handle's free.",
    }],
    structs: &[
        SharedStruct {
            name: "TypeWriteResult",
            doc: "The outcome of a type-write call, returned by value from every type-write \
                  function except the two signature-surgery fns.",
            fields: &[
                Field {
                    name: "code",
                    ty: FieldTy::I32,
                    doc: "Raw facade code: an `IDAKIT_TYPE_*`/`IDAKIT_TEDIT_*` sentinel, a negative \
                          `tinfo_code_t`, or `define_type`'s parse-error count.",
                },
                Field {
                    name: "reason",
                    ty: FieldTy::Str,
                    doc: "Captured IDA diagnostic, empty when the call has no error channel.",
                },
            ],
        },
        SharedStruct {
            name: "SigWriteResult",
            doc: "The outcome of a signature-surgery call that also reports the function's \
                  parameter count.",
            fields: &[
                Field {
                    name: "code",
                    ty: FieldTy::I32,
                    doc: "Raw facade `IDAKIT_SIG_*` code.",
                },
                Field {
                    name: "arity",
                    ty: FieldTy::Usize,
                    doc: "Parameter count of the edited function type (`0` when it has no type).",
                },
                Field {
                    name: "reason",
                    ty: FieldTy::Str,
                    doc: "Captured IDA diagnostic, empty when none.",
                },
            ],
        },
    ],
    custom_tu: Some("facade/type_build_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "apply_type_decl",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "decl",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "flags",
                    ty: ArgTy::I32,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Parse `decl` against the local til and apply it at `ea`. `code` is \
                  `IDAKIT_TYPE_OK`, `_ERR_INPUT` (parse failed), or `_ERR_APPLY`.",
        },
        FnSpec {
            name: "apply_named_type",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "name",
                    ty: ArgTy::Str,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Resolve the existing named type `name` and apply it at `ea`. `code` \
                  distinguishes not-found (`_ERR_INPUT`) from an apply rejection (`_ERR_APPLY`); \
                  `reason` is empty (no error channel).",
        },
        FnSpec {
            name: "clear_type",
            receiver: None,
            args: EA,
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Clear any type applied at `ea`. Idempotent: `code` is `IDAKIT_TYPE_OK` when \
                  there was nothing to clear; `reason` is empty (no error channel).",
        },
        FnSpec {
            name: "apply_type_recipe",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "recipe",
                    ty: ArgTy::Bytes,
                },
                Arg {
                    name: "flags",
                    ty: ArgTy::I32,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Build the `tinfo` the postfix recipe encodes and apply it at `ea`. Same codes as \
                  [`apply_type_decl`]; `_ERR_INPUT` is a malformed buffer or an unparseable \
                  embedded decl. An unknown named leaf builds a forward reference that fails later \
                  at apply, not here.",
        },
        FnSpec {
            name: "define_type",
            receiver: None,
            args: &[Arg {
                name: "input",
                ty: ArgTy::Str,
            }],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Parse the C declaration(s) in `input` into the local til. `code` is the \
                  parse-error count (`0` = ok).",
        },
        FnSpec {
            name: "delete_type",
            receiver: None,
            args: &[Arg {
                name: "type_name",
                ty: ArgTy::Str,
            }],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Delete the named type `type_name` from the local til, the inverse of \
                  [`define_type`]. See the `IDAKIT_TEDIT_*` codes.",
        },
        FnSpec {
            name: "rename_type",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "new_name",
                    ty: ArgTy::Str,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Rename the named type `type_name` to `new_name` in place, preserving its \
                  ordinal. Same `IDAKIT_TEDIT_*` codes as the `udt_*`/`enum_*` fns.",
        },
        FnSpec {
            name: "forward_declare_type",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "decl_type",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Reserve `type_name` in the local til as an incomplete aggregate \
                  (`tinfo_t::create_forward_decl`), without a body. `decl_type` is a `type_t` \
                  (`BTF_STRUCT`/`BTF_UNION`/`BTF_ENUM`) selecting the aggregate kind. `code` is the \
                  raw `tinfo_code_t` (`0` = ok); no `IDAKIT_TEDIT_*` pre-failure, since there is no \
                  existing type to load first.",
        },
        FnSpec {
            name: "func_set_rettype",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "recipe",
                    ty: ArgTy::Bytes,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Replace the return type of the function type at `ea` with the recipe type, then \
                  rebuild and re-apply. See the `IDAKIT_SIG_*` codes.",
        },
        FnSpec {
            name: "func_set_argtype",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "idx",
                    ty: ArgTy::Usize,
                },
                Arg {
                    name: "recipe",
                    ty: ArgTy::Bytes,
                },
            ],
            ret: RetKind::Shared("SigWriteResult"),
            body: BodyKind::Custom,
            doc: "Replace parameter `idx`'s type with the recipe type, then rebuild and re-apply. \
                  `arity` reports the current parameter count; `IDAKIT_SIG_ARG_RANGE` when `idx` \
                  is past it.",
        },
        FnSpec {
            name: "func_rename_arg",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "idx",
                    ty: ArgTy::Usize,
                },
                Arg {
                    name: "name",
                    ty: ArgTy::Str,
                },
            ],
            ret: RetKind::Shared("SigWriteResult"),
            body: BodyKind::Custom,
            doc: "Rename parameter `idx` to `name`, then rebuild and re-apply. `arity` reports the \
                  current parameter count; `IDAKIT_SIG_ARG_RANGE` when `idx` is past it.",
        },
        FnSpec {
            name: "func_set_cc",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "cc",
                    ty: ArgTy::I32,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Set the calling convention of the function type at `ea` to the raw `CM_CC_*` \
                  code `cc`, then rebuild and re-apply.",
        },
        FnSpec {
            name: "func_prepend_this",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "recipe",
                    ty: ArgTy::Bytes,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Insert an implicit `this` parameter of the recipe type at index 0, then rebuild \
                  and re-apply.",
        },
        FnSpec {
            name: "udt_add_member",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "recipe",
                    ty: ArgTy::Bytes,
                },
                Arg {
                    name: "member_bit",
                    ty: ArgTy::U64,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Add a member of the recipe type to the named struct/union `type_name` at bit \
                  offset `member_bit` (or appended when it is `IDAKIT_MEMBER_APPEND`). An empty \
                  `member_name` adds an anonymous member. See the `IDAKIT_TEDIT_*` codes.",
        },
        FnSpec {
            name: "udt_set_member_type",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_bit",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "recipe",
                    ty: ArgTy::Bytes,
                },
                Arg {
                    name: "etf_flags",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Replace the type of the member selected by `member_name` (or, when it is empty, \
                  by bit offset `member_bit`) in `type_name` with the recipe type, passing \
                  `etf_flags` (`etf_flag_t`, e.g. `ETF_COMPATIBLE`) to `set_udm_type`.",
        },
        FnSpec {
            name: "udt_rename_member",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_bit",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "new_name",
                    ty: ArgTy::Str,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Rename the member selected by `member_name` (or, when it is empty, by bit offset \
                  `member_bit`) in `type_name` to `new_name`.",
        },
        FnSpec {
            name: "udt_set_member_comment",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_bit",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "comment",
                    ty: ArgTy::Str,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Set the comment on the member selected by `member_name` (or, when it is empty, \
                  by bit offset `member_bit`) in `type_name` to `comment`, a plain member comment \
                  (`is_regcmt=false`).",
        },
        FnSpec {
            name: "udt_set_member_repr",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_bit",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "vtype",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "is_signed",
                    ty: ArgTy::Bool,
                },
                Arg {
                    name: "leading_zeros",
                    ty: ArgTy::Bool,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Set the value representation on the member selected by `member_name` (or, when \
                  it is empty, by bit offset `member_bit`) in `type_name`. `vtype` is a \
                  `value_repr_t` FRB_* value-type nibble; `is_signed`/`leading_zeros` set \
                  FRB_SIGNED/FRB_LZERO.",
        },
        FnSpec {
            name: "udt_del_member",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_bit",
                    ty: ArgTy::U64,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Delete the member selected by `member_name` (or, when it is empty, by bit offset \
                  `member_bit`) from `type_name`.",
        },
        FnSpec {
            name: "enum_add_member",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "value",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "bmask",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "etf_flags",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Add an enum constant named `member_name` with `value` to the named enum \
                  `type_name`, in the explicit bitmask group `bmask` (`DEFMASK64` lets a bitmask \
                  enum use `value` itself as the group mask; ignored by an ordinary enum), passing \
                  `etf_flags` (`etf_flag_t`, e.g. `ETF_FORCENAME`) to `add_edm`. Same \
                  `IDAKIT_TEDIT_*` codes as the `udt_*` fns.",
        },
        FnSpec {
            name: "enum_set_bitmask",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "on",
                    ty: ArgTy::Bool,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Set whether the named enum `type_name` is a bitmask (flag) enum \
                  (`tinfo_t::set_enum_is_bitmask`). Same `IDAKIT_TEDIT_*` codes as the \
                  `udt_*`/`enum_*` fns.",
        },
        FnSpec {
            name: "enum_set_repr",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "vtype",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "is_signed",
                    ty: ArgTy::Bool,
                },
                Arg {
                    name: "leading_zeros",
                    ty: ArgTy::Bool,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Set the value representation on the named enum `type_name` \
                  (`tinfo_t::set_enum_repr`), the enum-level twin of \
                  [`udt_set_member_repr`]. `vtype` is a `value_repr_t` FRB_* value-type nibble; \
                  `is_signed`/`leading_zeros` set FRB_SIGNED/FRB_LZERO.",
        },
        FnSpec {
            name: "enum_set_width",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "nbytes",
                    ty: ArgTy::I32,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Set the storage width in bytes of the named enum `type_name`'s underlying type \
                  (`tinfo_t::set_enum_width`); `0` means unspecified.",
        },
        FnSpec {
            name: "enum_set_member_value",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "value",
                    ty: ArgTy::U64,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Set the value of the enum constant `member_name` in the named enum `type_name`.",
        },
        FnSpec {
            name: "enum_rename_member",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "new_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "etf_flags",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Rename the enum constant `member_name` in the named enum `type_name` to \
                  `new_name`, passing `etf_flags` (`etf_flag_t`, e.g. `ETF_FORCENAME`) to \
                  `rename_edm`.",
        },
        FnSpec {
            name: "enum_del_member",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "member_name",
                    ty: ArgTy::Str,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Delete the enum constant `member_name` from the named enum `type_name`.",
        },
        FnSpec {
            name: "enum_del_member_by_value",
            receiver: None,
            args: &[
                Arg {
                    name: "type_name",
                    ty: ArgTy::Str,
                },
                Arg {
                    name: "value",
                    ty: ArgTy::U64,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Delete the enum constant carrying `value` from the named enum `type_name` \
                  (`tinfo_t::del_edm_by_value`), the value-keyed sibling of [`enum_del_member`]. \
                  Uses the default bitmask (`DEFMASK64`) and serial (`0`), so it targets the plain \
                  value match, not a specific bitmask group or serial. `TERR_NOT_FOUND` \
                  (`TypeEditCode::NotFound`) when no constant carries `value`.",
        },
        FnSpec {
            name: "tinfo_void",
            receiver: None,
            args: &[],
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "The `void` type as a fresh [`UniquePtr`](cxx::UniquePtr) handle, freed by the \
                  cxx deleter (`~tinfo_t`) on drop.",
        },
        FnSpec {
            name: "tinfo_bool",
            receiver: None,
            args: &[],
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "The boolean type as a fresh [`UniquePtr`](cxx::UniquePtr) handle.",
        },
        FnSpec {
            name: "tinfo_int",
            receiver: None,
            args: &[
                Arg {
                    name: "bytes",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "is_signed",
                    ty: ArgTy::Bool,
                },
            ],
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "A `bytes`-wide integer (1/2/4/8/16), signed when `is_signed`, as a fresh handle; \
                  a null handle when the width is unsupported.",
        },
        FnSpec {
            name: "tinfo_float",
            receiver: None,
            args: &[Arg {
                name: "bytes",
                ty: ArgTy::U32,
            }],
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "A `bytes`-wide float (4 or 8) as a fresh handle; a null handle when the width is \
                  not 4 or 8.",
        },
        FnSpec {
            name: "tinfo_named",
            receiver: None,
            args: &[Arg {
                name: "name",
                ty: ArgTy::Str,
            }],
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "The named type `name` as a fresh handle, an unresolved typedef ref. Builds a \
                  non-null forward reference even for a name absent from the local til, so the \
                  caller checks existence separately.",
        },
        FnSpec {
            name: "tinfo_decl",
            receiver: None,
            args: &[Arg {
                name: "decl",
                ty: ArgTy::Str,
            }],
            ret: RetKind::ResultUniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "The type `decl` parses to against the local til, as a fresh handle; `Err` (with \
                  the captured parse diagnostic) on a parse failure.",
        },
        FnSpec {
            name: "tinfo_ptr",
            receiver: None,
            args: &[Arg {
                name: "inner",
                ty: ArgTy::ExternRef("TInfo"),
            }],
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "A pointer to `inner` as a fresh handle. `inner` is copied, not consumed; a null \
                  handle if the pointer type cannot be built.",
        },
        FnSpec {
            name: "tinfo_array",
            receiver: None,
            args: &[
                Arg {
                    name: "inner",
                    ty: ArgTy::ExternRef("TInfo"),
                },
                Arg {
                    name: "nelems",
                    ty: ArgTy::U64,
                },
            ],
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "An `nelems`-element array of `inner` as a fresh handle. `inner` is copied, not \
                  consumed; a null handle when `nelems` exceeds `u32` or the array cannot be built.",
        },
        FnSpec {
            name: "tinfo_const",
            receiver: None,
            args: &[Arg {
                name: "inner",
                ty: ArgTy::ExternRef("TInfo"),
            }],
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "A `const`-qualified copy of `inner` as a fresh handle. `inner` is not consumed.",
        },
        FnSpec {
            name: "tinfo_volatile",
            receiver: None,
            args: &[Arg {
                name: "inner",
                ty: ArgTy::ExternRef("TInfo"),
            }],
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "A `volatile`-qualified copy of `inner` as a fresh handle. `inner` is not \
                  consumed.",
        },
        FnSpec {
            name: "tinfo_apply",
            receiver: None,
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "handle",
                    ty: ArgTy::ExternRef("TInfo"),
                },
                Arg {
                    name: "flags",
                    ty: ArgTy::I32,
                },
            ],
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Apply the built `handle` at `ea` (`apply_tinfo`, `TINFO_DEFINITE | flags`). \
                  `code` is `IDAKIT_TYPE_OK`/`_ERR_APPLY`; the handle is not consumed.",
        },
    ],
};

/// The local-type read domain: render a function's prototype and enumerate the local type library.
///
/// The mirror of the write side (`type_build`); the string bodies are hand-written in
/// `facade/ty_custom.cc`, the ordinal-limit passthrough templated.
pub const TY: Domain = Domain {
    name: "ty",
    sdk_includes: &["<typeinf.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    custom_tu: Some("facade/ty_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "func_type",
            receiver: None,
            args: &[Arg {
                name: "ea",
                ty: ArgTy::U64,
            }],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "The prototype of the function at `ea` (one line, `PRTYPE_1LINE`); `Err` when it \
                  has no type.",
        },
        FnSpec {
            name: "type_ordinal_limit",
            receiver: None,
            args: &[],
            ret: RetKind::U32,
            body: BodyKind::ScalarCall {
                call: "get_ordinal_limit(get_idati())",
            },
            doc: "Exclusive upper bound on local-type ordinals: valid ordinals run `1..limit`.",
        },
        FnSpec {
            name: "type_name_at",
            receiver: None,
            args: &[Arg {
                name: "ordinal",
                ty: ArgTy::U32,
            }],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Name of the local type at `ordinal` (empty for an anonymous type); `Err` when \
                  the ordinal holds no type.",
        },
    ],
};

/// The netnode domain: IDA's persistent per-database key/value + blob store. A `netnode` is a value
/// type over a single `nodeidx_t` id, so every function is keyed by a bare `node: u64` (the id) with
/// no opaque handle; the bodies reconstruct a `netnode` on the C++ side and call its inline methods.
/// Tags are the SDK's 8-bit array selectors (`atag`/`stag`/`htag`/`vtag`, or a user tag), passed as
/// `u32` and narrowed. Covers node lifecycle, the node value, the alt/sup/hash/char/blob arrays,
/// their `_ea`/`_idx8` conveniences, the array shifts, and the ranged/bulk deletes; only `altadjust`
/// is deferred. All bodies are hand-written in `facade/netnode_custom.cc`.
// TODO: netnode_altadjust -- needs a cxx extern "Rust" visitor sink, not a raw C callback
/// Every domain fed into the unified bridge, in emission order.
///
/// The hand-written domains are `const`; the netnode domain is built (and leaked to `'static`) by
/// [`netnode::domain`] on first use, so this aggregation is a memoized function, not a `const`.
pub fn domains() -> &'static [&'static Domain] {
    static DOMAINS: OnceLock<Vec<&'static Domain>> = OnceLock::new();
    DOMAINS.get_or_init(|| {
        vec![
            &SEGMENT,
            &IMPORT,
            &RANGE,
            &FUNCTION,
            &EXPORT,
            &META,
            &NAME,
            &STRINGS,
            &CFG,
            &REFERENCE,
            &BYTES,
            &INSTRUCTION,
            &HEXRAYS,
            &TYPE_BUILD,
            &TY,
            netnode::domain(),
        ]
    })
}
