use super::super::model::*;
use super::EA;

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
            args: args!(n: Usize),
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
