use super::super::model::*;

/// The control-flow-graph domain: the SDK's `qflow_chart_t` bound as an `Opaque` `ExternType`
/// (`FlowChart`) owned by [`UniquePtr`](cxx::UniquePtr), so its C++ deleter handles cleanup without
/// a manual free function or a hand-written `Drop` impl. `size` is a `self:`-member call bound straight to
/// `qflow_chart_t::size()` (no facade body); every other accessor is a free function over a
/// `&FlowChart`, hand-written in `facade/cfg.cpp`. Block bounds return by value as a `BlockInfo`
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
        fields: fields! {
            start: U64 = "Start address of the block.";
            end: U64 = "End address (exclusive) of the block.";
            kind: I32 = "Raw `fc_block_type_t` discriminant (`fcb_normal`, `fcb_ret`, ...).";
        },
    }],
    consts: &[],
    custom_tus: &["facade/cfg.cpp"],
    fns: fns! {
        "Build the flow chart for the function containing `ea`; `Err` when no function is there. \
         Runs analysis, so it can also fail from a thrown SDK exception."
            cfg_build(ea: U64, flags: I32) -> ResultUniquePtr("FlowChart");
        "Number of basic blocks, bound to `qflow_chart_t::size()` directly (the `self:` receiver). \
         The return is `i32` to match the member's exact `int` signature."
            size(self: FlowChart) -> I32;
        "Total number of basic blocks (external blocks included)."
            cfg_nblocks(fc: ExternRef("FlowChart")) -> Usize;
        "Number of blocks belonging to the function's own range."
            cfg_nproper(fc: ExternRef("FlowChart")) -> Usize;
        "Bounds and kind of block `n`; `Err` when `n` is out of range."
            cfg_block(fc: ExternRef("FlowChart"), n: Usize) -> ResultShared("BlockInfo");
        "Number of successors of block `n` (`0` when `n` is out of range)."
            cfg_nsucc(fc: ExternRef("FlowChart"), n: Usize) -> Usize;
        "The `i`-th successor block index of block `n`; `Err` when `n`/`i` is out of range."
            cfg_succ(fc: ExternRef("FlowChart"), n: Usize, i: Usize) -> ResultUsize;
        "Number of predecessors of block `n` (`0` when `n` is out of range)."
            cfg_npred(fc: ExternRef("FlowChart"), n: Usize) -> Usize;
        "The `i`-th predecessor block index of block `n`; `Err` when `n`/`i` is out of range."
            cfg_pred(fc: ExternRef("FlowChart"), n: Usize, i: Usize) -> ResultUsize;
        "The whole successor edge list of block `n` as one owned `Vec<u32>`; `Err` when `n` is out \
         of range."
            cfg_succs(fc: ExternRef("FlowChart"), n: Usize) -> ResultVecU32;
        "The whole predecessor edge list of block `n` as one owned `Vec<u32>`; `Err` when `n` is \
         out of range."
            cfg_preds(fc: ExternRef("FlowChart"), n: Usize) -> ResultVecU32;
    },
};
