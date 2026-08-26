use super::super::model::*;

/// The function domain: per-function scalar accessors and the name string. Function *chunks* are
/// the `range` domain (`range_all_chunks`), so no chunk accessor lives here. `func_qty` is a
/// templated passthrough; the lookup accessors are hand-written in `facade/function.cpp`.
pub const FUNCTION: Domain = Domain {
    name: "function",
    // compat.h supplies func_entry_info_t and the GFI_* selector under 9.3.
    sdk_includes: &["<funcs.hpp>", "<name.hpp>", "<stdexcept>", "\"compat.h\""],
    externs: &[],
    structs: &[SharedStruct {
        name: "FunctionEntryInfo",
        doc: "One function entry chunk's scalars, plus the strings the caller asked for, returned \
              by value from [`func_entry_info`]. An unrequested or absent string is empty.",
        fields: fields! {
            start: U64 = "Entry address.";
            end: U64 = "Entry-chunk end address, exclusive.";
            flags: U64 = "Raw `func_t::flags` bits (`FUNC_*`).";
            frame_id: U64 = "Netnode id of the frame structure, `BADNODE` when there is none.";
            locals_size: U64 = "Size in bytes of the frame's local-variable part (`frsize`).";
            saved_regs_size: U32 = "Size in bytes of the saved-registers part of the frame.";
            purged_bytes: U64 = "Bytes purged from the stack on return.";
            frame_pointer_delta: U64 = "Frame pointer delta, usually 0.";
            color: U32 = "User-defined function color, `DEFCOLOR` when unset.";
            name: Str = "Function name, empty when not requested.";
            cmt: Str = "Regular comment, empty when not requested or absent.";
            cmt_rpt: Str = "Repeatable comment, empty when not requested or absent.";
        },
    }],
    consts: &[],
    custom_tus: &["facade/function.cpp"],
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
        "Comment of the function at `ea` (repeatable if `repeatable`); `Err` when there is none."
            func_cmt(ea: U64, repeatable: Bool) -> ResultString;
        "Whether the function at `callee` is known to return (`func_does_return`)."
            func_does_return(callee: U64) -> Bool = scalar("::func_does_return(static_cast<ea_t>(callee))");
        "Addressing width in bits of the function at `ea`: 16, 32, or 64, or 0 when not a function."
            func_bitness(ea: U64) -> I32;
        "Entry-chunk scalars of the function at `ea`, plus each string `fields` selects (a \
         `GFI_*` mask); `Err` when `ea` is not a function."
            func_entry_info(ea: U64, fields: I32) -> ResultShared("FunctionEntryInfo");
    },
};
