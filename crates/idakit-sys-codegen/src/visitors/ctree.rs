//! The ctree walk's sink and its private shared struct.

use super::super::model::*;

pub(super) const LOC_PIECE: SharedStruct = SharedStruct {
    name: "LocPiece",
    doc: "One fragment of a scattered (`ALOC_DIST`) local's location. `atype` is the fragment's \
          own `ALOC_*` (a register or stack slot); `off`/`size` give the byte range of the whole \
          value this fragment covers.",
    fields: fields! {
        atype: U32 = "The fragment's own `ALOC_*` discriminant.";
        reg: U32 = "Register number, meaningful only for a register fragment.";
        sval: I64 = "Stack offset or static address, meaningful only for a stack/static fragment.";
        off: U32 = "Byte offset of this fragment within the whole scattered value.";
        size: U32 = "Byte size of this fragment.";
    },
};

/// The ctree walk's sink: one method per expression, statement, and local variable kind, driven
/// depth-first (children before parents) by `facade/ctree_bridge.cpp`'s `walker_t`.
pub(super) const CTREE_SINK: VisitorSink = VisitorSink {
    sink_name: "CtreeSink",
    sink_doc: "A ctree walk target the visitor drives inline, one method per expression, \
               statement, and local variable kind.\n\nThe consumer (`idakit`) implements it over \
               its own node builder, and [`CtreeVisitor`] forwards every C++ call straight into \
               it. Expression/statement methods mint and return the walk-local handle the parent \
               will reference; children are visited before parents (post-order), so a method's \
               array/slice arguments are already-minted handles. [`l_lvar`](Self::l_lvar) is void \
               and appended in index order, the order [`e_var`](Self::e_var)'s `idx` refers to. \
               Names, string literals, and comments cross as owned `String`, decoded leniently \
               facade-side (IDA emits UTF-8; any undecodable unit is U+FFFD).",
    visitor_name: "CtreeVisitor",
    visitor_doc: "The `cxx` `extern \"Rust\"` opaque the C++ ctree walk drives by calling its \
                  `&mut self` methods, each forwarding into the [`CtreeSink`] it was built over.\n\n\
                  `cxx` generates a C++ class with a member function per method below; \
                  `facade/ctree_bridge.cpp` receives a `CtreeVisitor&` and calls them. The visitor \
                  holds the sink as a lifetime-erased raw pointer: [`CtreeVisitor::from_raw`] is \
                  its only constructor, and the caller keeps the borrowed sink alive across the one \
                  synchronous walk, so the pointer is always valid and unaliased when a method \
                  reborrows it.",
    methods: methods! {
        "A numeric literal; returns its handle."
            e_num(ea: U64, value: U64, ty: U32);
        "A floating-point literal; returns its handle."
            e_fnum(ea: U64, value: F64, ty: U32);
        "A reference to the global object at `target`, named `name`; returns its handle."
            e_obj(ea: U64, target: U64, name: String, ty: U32);
        "A reference to local variable `idx` (the [`l_lvar`](Self::l_lvar) append order); returns \
         its handle."
            e_var(ea: U64, idx: U32, ty: U32);
        "A string literal, as IDA's escaped display form (`e->string`, already C-escaped); returns \
         its handle."
            e_str(ea: U64, text: String, ty: U32);
        "A decompiler-synthesized helper name; returns its handle."
            e_helper(ea: U64, name: String, ty: U32);
        "A call to the already-visited `callee` with the already-visited `args`; returns its \
         handle."
            e_call(ea: U64, callee: U32, args: SliceU32, ty: U32);
        "A `.` member reference into the already-visited `obj` at bit `offset`; returns its handle."
            e_memref(ea: U64, obj: U32, offset: U32, ty: U32);
        "A `->` member pointer into the already-visited `obj` at bit `offset`; returns its handle."
            e_memptr(ea: U64, obj: U32, offset: U32, ty: U32);
        "A pointer dereference of the already-visited `x`, `size` bytes; returns its handle."
            e_deref(ea: U64, x: U32, size: U32, ty: U32);
        "A generic operator node (binary/assign/unary/ternary/cast/index/sizeof/empty/type/insn); \
         the raw `ctype_t` is passed for the sink to classify, absent operands as `NONE`; \
         returns its handle."
            e_op(ea: U64, ctype: U32, x: U32, y: U32, z: U32, ty: U32);
        "A `{ ... }` block of the already-visited `kids`; returns its handle."
            s_block(ea: U64, kids: SliceU32);
        "An expression statement wrapping the already-visited `e`; returns its handle."
            s_expr(ea: U64, e: U32);
        "An `if`/`then`/`else` (else is `NONE` when absent); returns its handle."
            s_if(ea: U64, cond: U32, then_s: U32, else_s: U32);
        "A `for` loop; any of `init`/`cond`/`step` may be `NONE`; returns its handle."
            s_for(ea: U64, init: U32, cond: U32, step: U32, body: U32);
        "A `while` loop; returns its handle."
            s_while(ea: U64, cond: U32, body: U32);
        "A `do`/`while` loop; returns its handle."
            s_do(ea: U64, body: U32, cond: U32);
        "A `switch`, as parallel flat arrays: `bodies[i]` is case `i`'s body handle, \
         `value_counts[i]` is how many `u64` values case `i` has, and `values` is all case values \
         concatenated in order (case 0's values, then case 1's, ...). An empty values run is the \
         default case. Returns its handle."
            s_switch(ea: U64, expr: U32, bodies: SliceU32, value_counts: SliceU32, values: SliceU64);
        "A `break`; returns its handle."
            s_break(ea: U64);
        "A `continue`; returns its handle."
            s_continue(ea: U64);
        "A `return`, or a bare `return;` when `e` is `NONE`; returns its handle."
            s_return(ea: U64, e: U32);
        "A `goto` to `label`; returns its handle."
            s_goto(ea: U64, label: I32);
        "An inline-asm block, one already-computed address per line; returns its handle."
            s_asm(ea: U64, addrs: SliceU64);
        "A `try`/`catch`, the already-visited guarded `body` and each `catches` block; returns its \
         handle."
            s_try(ea: U64, body: U32, catches: SliceU32);
        "A `throw`, or a bare `throw;` when `e` is `NONE`; returns its handle."
            s_throw(ea: U64, e: U32);
        "An empty statement (or any statement kind the walk doesn't otherwise model); returns its \
         handle."
            s_empty(ea: U64);
        "One local variable, appended in index order, the index [`e_var`](Self::e_var)'s `idx` \
         refers to. `flags`: bit0 `is_arg`, bit1 `is_result`, bit2 `is_byref`. \
         `atype`/`reg1`/`reg2`/`sval` are the flattened `argloc_t` scalars; `pieces` is the \
         scattered-location fragments, empty unless `atype` marks a scattered (`ALOC_DIST`) \
         location."
            l_lvar(name: String, ty: U32, flags: U32, width: U32, comment: String, atype: U32,
                   reg1: U32, reg2: U32, sval: I64, pieces: SliceStruct("LocPiece")) -> Unit;
    },
};
