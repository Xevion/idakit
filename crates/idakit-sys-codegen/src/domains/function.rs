use super::super::model::*;

/// The function domain: per-function scalar accessors and the name string. Function *chunks* are
/// the `range` domain (`range_all_chunks`), so no chunk accessor lives here. `func_qty` is a
/// templated passthrough; the lookup accessors are hand-written in `facade/function_custom.cc`.
pub const FUNCTION: Domain = Domain {
    name: "function",
    sdk_includes: &["<funcs.hpp>", "<name.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    consts: &[],
    custom_tu: Some("facade/function_custom.cc"),
    body_helpers: None,
    fns: fns! {
        "Number of functions in the database (`get_func_qty`)."
            func_qty() -> Usize = scalar("get_func_qty()");
        "Entry address of the `n`-th function, or `BADADDR` when `n` is out of range."
            func_ea(n: Usize) -> U64;
        "Entry address of the function containing `ea`, or `BADADDR` when there is none."
            func_start(ea: U64) -> U64;
        "Entry-chunk end address of the function at `ea`, or `BADADDR` when not a function."
            func_end(ea: U64) -> U64;
        "`func_t::flags` of the function at `ea`, or `0` when `ea` is not a function."
            func_flags(ea: U64) -> U64;
        "Number of chunks (entry plus tails) of the function at `ea`, or `0`."
            func_chunk_qty(ea: U64) -> I32;
        "Name of the function at `ea`; `Err` when it has none."
            func_name(ea: U64) -> ResultString;
    },
};
