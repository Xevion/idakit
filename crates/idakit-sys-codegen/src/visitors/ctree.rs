//! The ctree walk's sink and its private shared struct.

use super::super::model::*;

pub(super) const LOC_PIECE: SharedStruct = SharedStruct {
    name: "LocPiece",
    doc: "One fragment of a scattered (`ALOC_DIST`) location. `atype` is the fragment's own \
          `ALOC_*` (a register or stack slot); `off`/`size` give the byte range of the whole \
          value this fragment covers.",
    fields: fields! {
        atype: U32 = "The fragment's own `ALOC_*` discriminant.";
        reg: U32 = "Register number, meaningful only for a register fragment.";
        regoff: U16 = "Byte offset within the register, meaningful only for a register fragment.";
        sval: I64 = "Stack offset or static address, meaningful only for a stack/static fragment.";
        off: U32 = "Byte offset of this fragment within the whole scattered value.";
        size: U32 = "Byte size of this fragment.";
    },
};

pub(super) const CALL_ARG: SharedStruct = SharedStruct {
    name: "CallArg",
    doc: "One `carg_t` of a call, crossed inside a slice for one `e_call`.",
    fields: fields! {
        expr: U32 = "Handle of the already-visited argument expression.";
        is_vararg: Bool = "Whether the argument matches the `...` tail.";
        formal_type: U32 = "Walk-local handle of the formal parameter type, or `NONE` when the \
                            SDK reports none.";
    },
};

pub(super) const NUM_LITERAL: SharedStruct = SharedStruct {
    name: "NumLiteral",
    doc: "A `cot_num`'s value and its `number_format_t`, the kind decoded by the SDK's own \
          predicates (`is_enum`, `is_char`, `is_stroff`).",
    fields: fields! {
        value: U64 = "The literal's value, read under the node's type.";
        kind: U32 = "`LITERAL_NUMBER`, `LITERAL_CHAR`, `LITERAL_ENUM`, or \
                     `LITERAL_STRUCT_OFFSET`.";
        radix: U32 = "`get_radix()`: 2, 8, 10, or 16.";
        type_name: Str = "The enum (`LITERAL_ENUM`) or struct (`LITERAL_STRUCT_OFFSET`) name; empty \
                          otherwise.";
        serial: U8 = "An enum constant's serial number.";
        properties: U8 = "Raw `number_format_t::props` (`NF_*`).";
        original_size: U8 = "`org_nbytes`, the original byte size; 0 when unknown.";
        operand: U8 = "`opnum`, the operand `representation`'s bits describe.";
        representation: U64 = "Raw `number_format_t::flags`, the database flags for `operand`.";
    },
};

pub(super) const CAUGHT_EXPR: SharedStruct = SharedStruct {
    name: "CaughtExpr",
    doc: "One `catchexpr_t` of a catch clause.",
    fields: fields! {
        object: U32 = "Handle of the caught object, or `NONE` when the clause names none.";
        fake_type: Str = "The caught type's name when the object's own type is not enough; empty \
                          otherwise.";
    },
};

pub(super) const CATCH_CLAUSE: SharedStruct = SharedStruct {
    name: "CatchClause",
    doc: "One `ccatch_t`: its body and what it catches, empty for `catch (...)`.",
    fields: fields! {
        body: U32 = "Handle of the already-visited body block.";
        caught: VecStruct("CaughtExpr") = "The caught objects.";
    },
};

pub(super) const ARG_LOC: SharedStruct = SharedStruct {
    name: "ArgLoc",
    doc: "A flattened `argloc_t` (or a decompiler local's `vdloc_t`). `atype` selects which of the \
          other scalars are meaningful, the way the SDK's union does; `pieces` is filled only for \
          a scattered (`ALOC_DIST`) location.",
    fields: fields! {
        atype: U32 = "The `ALOC_*` discriminant.";
        reg1: U32 = "The register (`ALOC_REG1`), low register (`ALOC_REG2`), or base register \
                     (`ALOC_RREL`).";
        reg2: U32 = "The high register of an `ALOC_REG2` pair.";
        regoff: U16 = "Byte offset within an `ALOC_REG1` register; always 0 for a decompiler \
                       local.";
        sval: I64 = "Stack offset (`ALOC_STACK`), static address (`ALOC_STATIC`), or \
                     register-relative offset (`ALOC_RREL`).";
        pieces: VecStruct("LocPiece") = "The fragments of a scattered location.";
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
            e_num(ea: Address, literal: StructRef("NumLiteral"), ty: U32);
        "A floating-point literal; returns its handle."
            e_fnum(ea: Address, value: F64, ty: U32);
        "A reference to the global object at `target`, named `name`; returns its handle."
            e_obj(ea: Address, target: Address, name: String, ty: U32);
        "A reference to local variable `idx` (the [`l_lvar`](Self::l_lvar) append order); returns \
         its handle."
            e_var(ea: Address, idx: U32, ty: U32);
        "A string literal, as IDA's escaped display form (`e->string`, already C-escaped); returns \
         its handle."
            e_str(ea: Address, text: String, ty: U32);
        "A decompiler-synthesized helper name; returns its handle."
            e_helper(ea: Address, name: String, ty: U32);
        "A call to the already-visited `callee` with the already-visited `args`; returns its \
         handle."
            e_call(ea: Address, callee: U32, args: SliceStruct("CallArg"), ty: U32);
        "A `.` member reference into the already-visited `obj` at bit `offset`; returns its handle."
            e_memref(ea: Address, obj: U32, offset: U32, ty: U32);
        "A `->` member pointer into the already-visited `obj` at bit `offset`; returns its handle."
            e_memptr(ea: Address, obj: U32, offset: U32, ty: U32);
        "A pointer dereference of the already-visited `x`, `size` bytes; returns its handle."
            e_deref(ea: Address, x: U32, size: U32, ty: U32);
        "A generic operator node (binary/assign/unary/ternary/cast/index/sizeof/empty/type/insn); \
         the raw `ctype_t` is passed for the sink to classify, absent operands as `NONE`; \
         returns its handle."
            e_op(ea: Address, ctype: U32, x: U32, y: U32, z: U32, ty: U32);
        "A `{ ... }` block of the already-visited `kids`; returns its handle."
            s_block(ea: Address, kids: SliceU32);
        "An expression statement wrapping the already-visited `e`; returns its handle."
            s_expr(ea: Address, e: U32);
        "An `if`/`then`/`else` (else is `NONE` when absent); returns its handle."
            s_if(ea: Address, cond: U32, then_s: U32, else_s: U32);
        "A `for` loop; any of `init`/`cond`/`step` may be `NONE`; returns its handle."
            s_for(ea: Address, init: U32, cond: U32, step: U32, body: U32);
        "A `while` loop; returns its handle."
            s_while(ea: Address, cond: U32, body: U32);
        "A `do`/`while` loop; returns its handle."
            s_do(ea: Address, body: U32, cond: U32);
        "A `switch`, as parallel flat arrays: `bodies[i]` is case `i`'s body handle, \
         `value_counts[i]` is how many `u64` values case `i` has, and `values` is all case values \
         concatenated in order (case 0's values, then case 1's, ...). An empty values run is the \
         default case. Returns its handle."
            s_switch(ea: Address, expr: U32, bodies: SliceU32, value_counts: SliceU32, values: SliceU64);
        "A `break`; returns its handle."
            s_break(ea: Address);
        "A `continue`; returns its handle."
            s_continue(ea: Address);
        "A `return`, or a bare `return;` when `e` is `NONE`; returns its handle."
            s_return(ea: Address, e: U32);
        "A `goto` to `label`; returns its handle."
            s_goto(ea: Address, label: I32);
        "An inline-asm block, one already-computed address per line; returns its handle."
            s_asm(ea: Address, addrs: SliceU64);
        "A `try`/`catch`, the already-visited guarded `body` and each `catches` block; returns its \
         handle."
            s_try(ea: Address, body: U32, catches: SliceStruct("CatchClause"));
        "A `throw`, or a bare `throw;` when `e` is `NONE`; returns its handle."
            s_throw(ea: Address, e: U32);
        "An empty statement (`cit_empty`); returns its handle."
            s_empty(ea: Address);
        "A statement kind the walk doesn't model, carrying its raw `ctype_t`; the sink rejects \
         the walk. Returns a placeholder handle so the parent can still be built."
            s_unknown(ea: Address, tag: U32);
        "Sets the raw `EXFL_*` word on the already-minted expression `id`; sent only when the \
         word is non-zero."
            e_flags(id: U32, flags: U32) -> Unit;
        "One local variable, appended in index order, the index [`e_var`](Self::e_var)'s `idx` \
         refers to. `flags` is the raw `CVAR_*` word. `location` is \
         the variable's flattened `vdloc_t`."
            l_lvar(name: String, ty: U32, flags: U32, width: U32, comment: String,
                   location: StructRef("ArgLoc")) -> Unit;
    },
};
