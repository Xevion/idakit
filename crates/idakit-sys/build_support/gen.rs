//! Spec-driven `cxx` bridge generation via `cxx-gen`.
//!
//! `cxx_build::bridge()` parses bridge source textually with `syn`, so a `macro_rules!` can never
//! author a `#[cxx::bridge] mod`: its symbols would be invisible to the parser and undefined at
//! link. `cxx-gen` is the escape hatch. `generate_header_and_cc` takes a `TokenStream` that already
//! contains a `#[cxx::bridge] mod` and returns the C++ header + impl, so build.rs can build the
//! module's tokens from a declarative spec and drive every face off it.
//!
//! One [`Domain`] is one slice of the facade (segment, function, ...). Every domain feeds one
//! unified `#[cxx::bridge] mod ffi` (namespace `idakit_gen`): the generator emits all three
//! declaration faces from the spec (the Rust bridge decl, the C++ header decl, the `cxx` glue),
//! and the function *bodies* stay hand-written in per-domain `.cc` translation units, exactly as
//! the raw facade's bodies are. A handful of trivial scalar/string bodies are templated from their
//! [`BodyKind`] as a convenience; everything else is [`BodyKind::Custom`] and hand-written.
//!
//! Files written to `$OUT_DIR`:
//!
//! * `gen_bridge.rs` -- the `#[cxx::bridge] mod` Rust source, `include!`d by `src/bridge_gen.rs`.
//! * `gen_bridge.cc` / `gen_bridge.h` -- the `cxx` shim glue from `cxx-gen`.
//! * `gen_<name>.h` -- one per domain: the real C++ declarations the bodies define.
//! * `gen_<name>_bodies.cc` -- one per domain with any templated bodies (omitted when all Custom).
//! * `rust/cxx.h` -- the `cxx` support header (`cxx_gen::HEADER`) for the body TUs.

use std::path::{Path, PathBuf};

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

/// The C++ namespace every generated bridge function lives in.
const NAMESPACE: &str = "idakit_gen";

/// One slice of the facade: its own C++ header and body TU, the SDK types it binds, the shared
/// structs it returns, and its functions. All domains feed one unified bridge module.
pub struct Domain {
    /// Short identifier, e.g. `"seg"`. Names the generated `gen_<name>.h` / `gen_<name>_bodies.cc`.
    pub name: &'static str,
    /// SDK headers the body TU must include (e.g. `"<segment.hpp>"`), plus `<stdexcept>` when a
    /// body throws. `<pro.h>`/`<ida.hpp>` are always included.
    pub sdk_includes: &'static [&'static str],
    /// SDK types this domain binds as `cxx` `ExternType`s (POD by value, or opaque behind a handle).
    pub externs: &'static [ExternTy],
    /// `cxx` shared structs this domain declares and returns by value.
    pub structs: &'static [SharedStruct],
    /// The domain's functions.
    pub fns: &'static [FnSpec],
    /// A hand-written TU defining this domain's [`BodyKind::Custom`] bodies, if any.
    pub custom_tu: Option<&'static str>,
}

impl Domain {
    fn header(&self) -> String {
        format!("gen_{}.h", self.name)
    }
    fn bodies_file(&self) -> String {
        format!("gen_{}_bodies.cc", self.name)
    }
    fn has_templated_body(&self) -> bool {
        self.fns.iter().any(|f| body_source(f).is_some())
    }
}

/// An SDK type bound as a `cxx` [`ExternType`](cxx::ExternType), so `cxx` glue can pass it without
/// redeclaring it: the impl names the real C++ symbol by `type_id!`.
// TODO: unused until a structural domain (range/cfg/import) is folded in -- allow until then.
#[allow(dead_code)]
pub struct ExternTy {
    /// The Rust-side name (e.g. `"RangeT"`).
    pub rust_name: &'static str,
    /// The real C++ symbol (e.g. `"range_t"`), emitted as `::range_t` and used in `type_id!`.
    pub cxx_name: &'static str,
    /// Trivial (crosses by value) or Opaque (only behind a reference or `UniquePtr`).
    pub kind: ExternKind,
    /// One-line summary for the generated Rust type's doc comment.
    pub doc: &'static str,
    /// The `// SAFETY:` justification for the `unsafe impl ExternType`.
    pub safety: &'static str,
}

/// Whether an [`ExternTy`] is trivially relocatable (crosses by value) or opaque.
#[allow(dead_code)]
pub enum ExternKind {
    /// `#[repr(C)]` mirror crossing by value; the fields mirror the SDK POD's layout.
    Trivial(&'static [Field]),
    /// Zero-sized opaque body; only ever behind `&T` / `UniquePtr<T>`.
    Opaque,
}

/// A `cxx` shared struct: one POD declared once, generated into both languages, crossed by value.
#[allow(dead_code)]
pub struct SharedStruct {
    /// The struct's name (e.g. `"ChunkInfo"`).
    pub name: &'static str,
    /// One-line summary for its doc comment.
    pub doc: &'static str,
    /// Its fields, in declaration order.
    pub fields: &'static [Field],
}

/// One field of a [`SharedStruct`] or a `Trivial` [`ExternTy`] mirror.
#[allow(dead_code)]
pub struct Field {
    /// Field name.
    pub name: &'static str,
    /// Field type.
    pub ty: FieldTy,
    /// Terse noun-phrase doc fragment (renders in a generated table).
    pub doc: &'static str,
}

/// The field types a shared struct or POD mirror may carry.
// TODO: some variants land as structural/write domains are folded in (Stage 2) -- allow until then.
#[allow(dead_code)]
pub enum FieldTy {
    U64,
    Usize,
    I32,
    U32,
    /// An owned string (`String` in Rust, `rust::String` in C++).
    Str,
    /// A by-value `Trivial` `ExternType`, named by its Rust name (e.g. `"RangeT"`).
    Extern(&'static str),
}

/// One facade function: its shared name, optional `self:` receiver, arguments, return shape, and
/// how its C++ body is produced. `name` is used verbatim for the Rust bridge fn and the C++ symbol.
pub struct FnSpec {
    pub name: &'static str,
    /// `Some(extern rust_name)` for a `self: &T` member call; `None` for a free function.
    pub receiver: Option<&'static str>,
    pub args: &'static [Arg],
    pub ret: RetKind,
    pub body: BodyKind,
    pub doc: &'static str,
}

/// A bridge-function argument.
pub struct Arg {
    pub name: &'static str,
    pub ty: ArgTy,
}

/// The argument shapes the spec can express. Each is a (Rust type, C++ type) pair.
// TODO: non-scalar variants land as their domains are folded in (Stage 2) -- allow until then.
#[allow(dead_code)]
pub enum ArgTy {
    I32,
    U32,
    U64,
    Usize,
    Bool,
    /// A borrowed string (`&str` / `rust::Str`).
    Str,
    /// A borrowed byte slice (`&[u8]` / `rust::Slice<const uint8_t>`).
    Bytes,
    /// A by-value `Trivial` `ExternType`, by Rust name.
    Extern(&'static str),
    /// A borrowed `ExternType` (`&T` / `const ::cxx_name&`), by Rust name.
    ExternRef(&'static str),
}

/// The return shapes the spec can express. `Result<T>` variants surface a thrown C++ exception as
/// a Rust `Err`; the non-`Result` twins are for infallible calls.
// TODO: structural/vec variants land as their domains are folded in (Stage 2) -- allow until then.
#[allow(dead_code)]
pub enum RetKind {
    Unit,
    Bool,
    I32,
    U32,
    U64,
    Usize,
    String,
    ResultString,
    /// A by-value `Trivial` `ExternType`, by Rust name.
    Extern(&'static str),
    ResultExtern(&'static str),
    /// A shared struct by value, by name.
    Shared(&'static str),
    ResultShared(&'static str),
    /// `UniquePtr<T>` over an opaque `ExternType`, by Rust name.
    UniquePtr(&'static str),
    ResultUniquePtr(&'static str),
    /// An owned `Vec` of a `Trivial` `ExternType` or a shared struct, by name.
    Vec(&'static str),
    ResultVec(&'static str),
    /// An owned `Vec` of a scalar (`u32`).
    VecU32,
    ResultVecU32,
}

/// How a function's C++ body is produced. The templated variants exist for segment's trivial
/// scalar/string shapes; every other body is [`Custom`](BodyKind::Custom) and hand-written in the
/// domain's `custom_tu`.
pub enum BodyKind {
    /// Nullary scalar passthrough: `return (ret)CALL;`.
    ScalarCall { call: &'static str },
    /// `getnseg(n)`, then read scalar `s->ACCESSOR`, returning `SENTINEL` when null.
    SegScalar {
        accessor: &'static str,
        null_sentinel: &'static str,
    },
    /// `getnseg(n)`, then fill a `qstring` via `GETTER(&out, s)`; throw when null, and (when
    /// `require_positive`) throw when the getter returns `<= 0`.
    SegString {
        getter: &'static str,
        require_positive: bool,
    },
    /// Declaration only; the body is hand-written in the domain's `custom_tu`.
    Custom,
}

const N: &[Arg] = &[Arg {
    name: "n",
    ty: ArgTy::I32,
}];

/// The segment domain: mirrors the hand-written `idakit_cxx::seg_*` bridge one-for-one, plus a
/// `Custom` proof. Templated bodies live in the generated `gen_seg_bodies.cc`; the one `Custom`
/// body is hand-written in `facade/gen_custom.cc`.
pub const SEGMENT: Domain = Domain {
    name: "seg",
    sdk_includes: &["<segment.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    custom_tu: Some("facade/gen_custom.cc"),
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
        // whole table), so the spec declares only the signature; facade/gen_custom.cc defines it.
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
/// `facade/gen_import.cc` (a callback walk over every module's `enum_import_names`).
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
    custom_tu: Some("facade/gen_import.cc"),
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
/// bodies are hand-written in `facade/gen_range.cc` (they iterate a `func_tail_iterator_t`).
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
    custom_tu: Some("facade/gen_range.cc"),
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
/// templated passthrough; the lookup accessors are hand-written in `facade/gen_function.cc`.
pub const FUNCTION: Domain = Domain {
    name: "function",
    sdk_includes: &["<funcs.hpp>", "<name.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    custom_tu: Some("facade/gen_function.cc"),
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
/// hand-written in `facade/gen_export.cc` (a forwarder-less export legitimately `Err`s).
pub const EXPORT: Domain = Domain {
    name: "export",
    sdk_includes: &["<entry.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    custom_tu: Some("facade/gen_export.cc"),
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
/// `facade/gen_meta.cc`; the string getters throw when the SDK has no value.
pub const META: Domain = Domain {
    name: "meta",
    sdk_includes: &["<nalt.hpp>", "<loader.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    custom_tu: Some("facade/gen_meta.cc"),
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
/// three flags-word name classifiers. Every body is hand-written in `facade/gen_name.cc` (the
/// getters throw on no-name, and SDK calls are `::`-qualified to avoid recursing on the shared
/// symbol spellings).
pub const NAME: Domain = Domain {
    name: "name",
    sdk_includes: &["<name.hpp>", "<bytes.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    custom_tu: Some("facade/gen_name.cc"),
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
/// undecodable). All bodies are hand-written in `facade/gen_strings.cc`.
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
    custom_tu: Some("facade/gen_strings.cc"),
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

/// Every domain fed into the unified bridge, in emission order.
pub const DOMAINS: &[&Domain] = &[
    &SEGMENT, &IMPORT, &RANGE, &FUNCTION, &EXPORT, &META, &NAME, &STRINGS,
];

impl FieldTy {
    fn rust(&self) -> TokenStream {
        match self {
            FieldTy::U64 => quote!(u64),
            FieldTy::Usize => quote!(usize),
            FieldTy::I32 => quote!(i32),
            FieldTy::U32 => quote!(u32),
            FieldTy::Str => quote!(String),
            FieldTy::Extern(name) => {
                let id = format_ident!("{name}");
                quote!(#id)
            }
        }
    }
}

impl ArgTy {
    fn rust(&self) -> TokenStream {
        match self {
            ArgTy::I32 => quote!(i32),
            ArgTy::U32 => quote!(u32),
            ArgTy::U64 => quote!(u64),
            ArgTy::Usize => quote!(usize),
            ArgTy::Bool => quote!(bool),
            ArgTy::Str => quote!(&str),
            ArgTy::Bytes => quote!(&[u8]),
            ArgTy::Extern(name) => {
                let id = format_ident!("{name}");
                quote!(#id)
            }
            ArgTy::ExternRef(name) => {
                let id = format_ident!("{name}");
                quote!(&#id)
            }
        }
    }
    fn cxx(&self, arg_name: &str) -> String {
        let ty = match self {
            ArgTy::I32 => "int32_t".into(),
            ArgTy::U32 => "uint32_t".into(),
            ArgTy::U64 => "uint64_t".into(),
            ArgTy::Usize => "size_t".into(),
            ArgTy::Bool => "bool".into(),
            ArgTy::Str => "rust::Str".into(),
            ArgTy::Bytes => "rust::Slice<const uint8_t>".into(),
            ArgTy::Extern(name) => format!("::{}", extern_cxx_name(name)),
            ArgTy::ExternRef(name) => format!("const ::{}&", extern_cxx_name(name)),
        };
        format!("{ty} {arg_name}")
    }
}

impl RetKind {
    fn rust(&self) -> TokenStream {
        fn named(name: &str) -> TokenStream {
            let id = format_ident!("{name}");
            quote!(#id)
        }
        match self {
            RetKind::Unit => quote!(),
            RetKind::Bool => quote!(-> bool),
            RetKind::I32 => quote!(-> i32),
            RetKind::U32 => quote!(-> u32),
            RetKind::U64 => quote!(-> u64),
            RetKind::Usize => quote!(-> usize),
            RetKind::String => quote!(-> String),
            RetKind::ResultString => quote!(-> Result<String>),
            RetKind::Extern(n) => {
                let t = named(n);
                quote!(-> #t)
            }
            RetKind::ResultExtern(n) => {
                let t = named(n);
                quote!(-> Result<#t>)
            }
            RetKind::Shared(n) => {
                let t = named(n);
                quote!(-> #t)
            }
            RetKind::ResultShared(n) => {
                let t = named(n);
                quote!(-> Result<#t>)
            }
            RetKind::UniquePtr(n) => {
                let t = named(n);
                quote!(-> UniquePtr<#t>)
            }
            RetKind::ResultUniquePtr(n) => {
                let t = named(n);
                quote!(-> Result<UniquePtr<#t>>)
            }
            RetKind::Vec(n) => {
                let t = named(n);
                quote!(-> Vec<#t>)
            }
            RetKind::ResultVec(n) => {
                let t = named(n);
                quote!(-> Result<Vec<#t>>)
            }
            RetKind::VecU32 => quote!(-> Vec<u32>),
            RetKind::ResultVecU32 => quote!(-> Result<Vec<u32>>),
        }
    }
    /// The C++ return type. `cxx` maps a `Result<T>` to a C++ function returning `T` that throws,
    /// so both twins share one C++ type.
    fn cxx(&self) -> String {
        match self {
            RetKind::Unit => "void".into(),
            RetKind::Bool => "bool".into(),
            RetKind::I32 => "int32_t".into(),
            RetKind::U32 => "uint32_t".into(),
            RetKind::U64 => "uint64_t".into(),
            RetKind::Usize => "size_t".into(),
            RetKind::String | RetKind::ResultString => "rust::String".into(),
            RetKind::Extern(n) | RetKind::ResultExtern(n) => format!("::{}", extern_cxx_name(n)),
            RetKind::Shared(n) | RetKind::ResultShared(n) => (*n).into(),
            RetKind::UniquePtr(n) | RetKind::ResultUniquePtr(n) => {
                format!("std::unique_ptr<::{}>", extern_cxx_name(n))
            }
            RetKind::Vec(n) | RetKind::ResultVec(n) => format!("rust::Vec<{}>", vec_elem_cxx(n)),
            RetKind::VecU32 | RetKind::ResultVecU32 => "rust::Vec<uint32_t>".into(),
        }
    }
}

/// Resolve a `Vec<Name>` element's C++ spelling: a `Trivial` `ExternType` becomes `::cxx_name`, a
/// shared struct keeps its own name.
fn vec_elem_cxx(name: &str) -> String {
    if is_extern(name) {
        format!("::{}", extern_cxx_name(name))
    } else {
        name.to_string()
    }
}

/// The C++ symbol behind an `ExternType`'s Rust name, e.g. `RangeT` -> `range_t`.
fn extern_cxx_name(rust_name: &str) -> &'static str {
    for d in DOMAINS {
        for e in d.externs {
            if e.rust_name == rust_name {
                return e.cxx_name;
            }
        }
    }
    panic!("unknown ExternType `{rust_name}` referenced in a spec");
}

fn is_extern(rust_name: &str) -> bool {
    DOMAINS
        .iter()
        .any(|d| d.externs.iter().any(|e| e.rust_name == rust_name))
}

/// The module-level `#[repr(C)]` mirror + `unsafe impl ExternType` for one `Trivial`/`Opaque`
/// `ExternType`. These sit outside `mod ffi`, in the same file `bridge_gen.rs` `include!`s.
fn extern_type_tokens(e: &ExternTy) -> TokenStream {
    let rust_id = format_ident!("{}", e.rust_name);
    let type_id_str = e.cxx_name;
    let doc = e.doc;
    let safety = e.safety;
    match &e.kind {
        ExternKind::Trivial(fields) => {
            let field_decls = fields.iter().map(|f| {
                let fid = format_ident!("{}", f.name);
                let fty = f.ty.rust();
                let fdoc = f.doc;
                quote! { #[doc = #fdoc] pub #fid: #fty, }
            });
            quote! {
                #[doc = #doc]
                #[repr(C)]
                #[derive(Clone, Copy, PartialEq, Eq, Debug)]
                pub struct #rust_id {
                    #(#field_decls)*
                }
                #[doc = #safety]
                unsafe impl cxx::ExternType for #rust_id {
                    type Id = cxx::type_id!(#type_id_str);
                    type Kind = cxx::kind::Trivial;
                }
            }
        }
        ExternKind::Opaque => quote! {
            #[doc = #doc]
            #[repr(C)]
            pub struct #rust_id {
                _private: ::cxx::private::Opaque,
            }
            #[doc = #safety]
            unsafe impl cxx::ExternType for #rust_id {
                type Id = cxx::type_id!(#type_id_str);
                type Kind = cxx::kind::Opaque;
            }
        },
    }
}

/// One domain's items inside `mod ffi`: its shared structs, extern-type aliases, its `extern "C++"`
/// block (including the domain header + its fn decls), and any container `impl` blocks.
fn domain_ffi_tokens(d: &Domain) -> TokenStream {
    let structs = d.structs.iter().map(|s| {
        let sid = format_ident!("{}", s.name);
        let doc = s.doc;
        let fields = s.fields.iter().map(|f| {
            let fid = format_ident!("{}", f.name);
            let fty = f.ty.rust();
            let fdoc = f.doc;
            quote! { #[doc = #fdoc] #fid: #fty, }
        });
        quote! {
            #[doc = #doc]
            struct #sid {
                #(#fields)*
            }
        }
    });

    let extern_aliases = d.externs.iter().map(|e| {
        let rust_id = format_ident!("{}", e.rust_name);
        let cxx_name = e.cxx_name;
        quote! {
            #[namespace = ""]
            #[cxx_name = #cxx_name]
            type #rust_id = super::#rust_id;
        }
    });

    let header = d.header();
    let fns = d.fns.iter().map(|f| {
        let name = format_ident!("{}", f.name);
        let recv = f.receiver.map(|r| {
            let rid = format_ident!("{r}");
            quote!(self: &#rid,)
        });
        let args = f.args.iter().map(|a| {
            let an = format_ident!("{}", a.name);
            let at = a.ty.rust();
            quote!(#an: #at)
        });
        let ret = f.ret.rust();
        let doc = f.doc;
        quote! {
            #[doc = #doc]
            fn #name(#recv #(#args),*) #ret;
        }
    });

    // Container glue for hand-written ExternTypes: cxx auto-generates UniquePtr/Vec support only
    // for an in-bridge `type X;`, so force it for each opaque/trivial extern this domain returns.
    let impls = container_impls(d);

    quote! {
        #(#structs)*
        unsafe extern "C++" {
            include!(#header);
            #(#extern_aliases)*
            #(#fns)*
        }
        #impls
    }
}

/// The `impl UniquePtr<T> {}` / `impl Vec<T> {}` blocks a domain needs to force `cxx` to
/// instantiate container glue for its hand-written `ExternType`s.
fn container_impls(d: &Domain) -> TokenStream {
    let mut unique = Vec::new();
    let mut vecs = Vec::new();
    for f in d.fns {
        match &f.ret {
            RetKind::UniquePtr(n) | RetKind::ResultUniquePtr(n) => unique.push(*n),
            RetKind::Vec(n) | RetKind::ResultVec(n) if is_extern(n) => vecs.push(*n),
            _ => {}
        }
    }
    unique.sort_unstable();
    unique.dedup();
    vecs.sort_unstable();
    vecs.dedup();
    let unique = unique.into_iter().map(|n| {
        let id = format_ident!("{n}");
        quote!(impl UniquePtr<#id> {})
    });
    let vecs = vecs.into_iter().map(|n| {
        let id = format_ident!("{n}");
        quote!(impl Vec<#id> {})
    });
    quote! { #(#unique)* #(#vecs)* }
}

/// Build the whole `#[cxx::bridge] mod` token stream from every domain. Fed to both the Rust side
/// (written out and `include!`d) and `cxx-gen` (C++ side), so the two stay in lockstep.
fn bridge_tokens() -> TokenStream {
    let extern_types = DOMAINS
        .iter()
        .flat_map(|d| d.externs.iter())
        .map(extern_type_tokens);
    let domains = DOMAINS.iter().map(|d| domain_ffi_tokens(d));
    quote! {
        #(#extern_types)*

        #[cxx::bridge(namespace = #NAMESPACE)]
        mod ffi {
            #(#domains)*
        }
    }
}

/// The C++ signature `RET name(ARGS)` shared by a domain header decl and a templated body.
fn cxx_signature(f: &FnSpec) -> String {
    let mut args: Vec<String> = Vec::new();
    if let Some(recv) = f.receiver {
        args.push(format!("const ::{}& self", extern_cxx_name(recv)));
    }
    for a in f.args {
        args.push(a.ty.cxx(a.name));
    }
    format!("{} {}({})", f.ret.cxx(), f.name, args.join(", "))
}

/// One domain's C++ header: SDK includes, forward decls for its shared structs, and every function
/// declaration (all body kinds contribute a decl).
fn header_source(d: &Domain) -> String {
    let mut s = String::new();
    s.push_str("#pragma once\n\n");
    s.push_str("#include <cstddef>\n#include <cstdint>\n#include <memory>\n\n");
    s.push_str("#include <pro.h>\n#include <ida.hpp>\n");
    for inc in d.sdk_includes {
        s.push_str(&format!("#include {inc}\n"));
    }
    s.push_str("\n#include \"rust/cxx.h\"\n\n");
    s.push_str(&format!("namespace {NAMESPACE} {{\n\n"));
    // Shared structs are defined by the cxx-generated header; forward-declare so a decl may name
    // one by value (the body TU includes the generated header for the full definition).
    for st in d.structs {
        s.push_str(&format!("struct {};\n", st.name));
    }
    if !d.structs.is_empty() {
        s.push('\n');
    }
    for f in d.fns {
        s.push_str(&cxx_signature(f));
        s.push_str(";\n");
    }
    s.push_str(&format!("\n}} // namespace {NAMESPACE}\n"));
    s
}

/// The C++ body for one templated (non-`Custom`) spec, or `None` for `Custom`.
fn body_source(f: &FnSpec) -> Option<String> {
    let sig = cxx_signature(f);
    let body = match &f.body {
        BodyKind::ScalarCall { call } => format!("  return ({}){};\n", f.ret.cxx(), call),
        BodyKind::SegScalar {
            accessor,
            null_sentinel,
        } => {
            let cast = f.ret.cxx();
            format!(
                "  segment_t *s = getnseg(n);\n  \
                 return s != nullptr ? ({cast})s->{accessor} : ({cast}){null_sentinel};\n"
            )
        }
        BodyKind::SegString {
            getter,
            require_positive,
        } => {
            let mut b = String::from(
                "  segment_t *s = getnseg(n);\n  \
                 if (s == nullptr)\n    throw std::out_of_range(\"no segment at index\");\n  \
                 qstring out;\n",
            );
            if *require_positive {
                b.push_str(&format!(
                    "  if ({getter}(&out, s) <= 0)\n    \
                     throw std::runtime_error(\"segment has no class\");\n"
                ));
            } else {
                b.push_str(&format!("  {getter}(&out, s);\n"));
            }
            b.push_str("  return rust::String(out.c_str(), out.length());\n");
            b
        }
        BodyKind::Custom => return None,
    };
    Some(format!("{sig} {{\n{body}}}\n\n"))
}

/// One domain's templated-bodies TU: SDK includes, the shared header, and every templated body.
/// Returns `None` when the domain has no templated bodies (all `Custom`).
fn bodies_source(d: &Domain) -> Option<String> {
    if !d.has_templated_body() {
        return None;
    }
    let mut s = String::new();
    s.push_str(&format!(
        "// GENERATED from build_support/gen.rs {} -- do not edit.\n",
        d.name
    ));
    s.push_str("#include <pro.h>\n#include <ida.hpp>\n");
    for inc in d.sdk_includes {
        s.push_str(&format!("#include {inc}\n"));
    }
    s.push_str(&format!("\n#include \"{}\"\n\n", d.header()));
    s.push_str(&format!("namespace {NAMESPACE} {{\n\n"));
    for f in d.fns {
        if let Some(body) = body_source(f) {
            s.push_str(&body);
        }
    }
    s.push_str(&format!("}} // namespace {NAMESPACE}\n"));
    Some(s)
}

/// The generated body TUs (the `cxx-gen` glue plus each domain's templated bodies) that build.rs
/// must compile.
pub fn body_tus(out_dir: &Path) -> Vec<PathBuf> {
    let mut tus = vec![out_dir.join("gen_bridge.cc")];
    for d in DOMAINS {
        if d.has_templated_body() {
            tus.push(out_dir.join(d.bodies_file()));
        }
    }
    tus
}

/// The hand-written `Custom`-body TUs build.rs must compile alongside the generated ones.
pub fn custom_tus() -> Vec<&'static str> {
    DOMAINS.iter().filter_map(|d| d.custom_tu).collect()
}

/// Generate every artifact into `$OUT_DIR` from [`DOMAINS`].
///
/// # Panics
///
/// Panics if `cxx-gen` rejects the generated tokens, a spec references an unknown `ExternType`, or
/// any file write fails -- all are build bugs, not recoverable conditions.
pub fn generate(out_dir: &Path) {
    let tokens = bridge_tokens();

    // Rust side: the proc-macro expands this on `include!`. `TokenStream`'s Display is valid (if
    // unformatted) Rust; OUT_DIR files are never formatted, so that is fine.
    std::fs::write(out_dir.join("gen_bridge.rs"), tokens.to_string()).expect("write gen_bridge.rs");

    // C++ side: same tokens => matching shim symbol names on both sides.
    let opt = cxx_gen::Opt::default();
    let code = cxx_gen::generate_header_and_cc(tokens, &opt)
        .expect("cxx-gen rejected the generated bridge tokens");
    std::fs::write(out_dir.join("gen_bridge.h"), &code.header).expect("write gen_bridge.h");
    std::fs::write(out_dir.join("gen_bridge.cc"), &code.implementation)
        .expect("write gen_bridge.cc");

    for d in DOMAINS {
        std::fs::write(out_dir.join(d.header()), header_source(d))
            .unwrap_or_else(|e| panic!("write {}: {e}", d.header()));
        if let Some(bodies) = bodies_source(d) {
            std::fs::write(out_dir.join(d.bodies_file()), bodies)
                .unwrap_or_else(|e| panic!("write {}: {e}", d.bodies_file()));
        }
    }

    let rust_dir = out_dir.join("rust");
    std::fs::create_dir_all(&rust_dir).expect("create OUT_DIR/rust");
    std::fs::write(rust_dir.join("cxx.h"), cxx_gen::HEADER).expect("write rust/cxx.h");
}
