//! The declarative manifest for the ctree/tinfo `extern "Rust"` opaque-visitor bridge.
//!
//! [`VISITOR_BRIDGE`] pairs the ctree walk's [`CtreeSink`](VisitorSink)-shaped spec with the tinfo
//! type walk's, plus the shared `extern "C++"` driver block both are called through. The engine
//! that turns this into the Rust bridge and the C++ shim glue lives in the sibling `gen.rs`; the
//! hand-written C++ drivers stay in `facade/ctree_cxx.cc` / `facade/typewalk_cxx.cc`.
//!
//! The `args!` / `fields!` / `methods!` DSL macros used below are defined in the parent `gen.rs`
//! (they author every spec's arg and field slices, not just this one).

use super::{
    Arg, ArgTy, Field, FieldTy, RetKind, SharedStruct, VisitorBridge, VisitorDriverFn,
    VisitorMethod, VisitorSink,
};

const LOC_PIECE: SharedStruct = SharedStruct {
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

const MEMBER_INFO: SharedStruct = SharedStruct {
    name: "MemberInfo",
    doc: "One struct/union member, crossed inside a slice for one `fill_struct` call. `name` is an \
          owned `String`: the sink interns members into its own table, so the transient owned copy \
          the walk allocates is copied on anyway.",
    fields: fields! {
        name: Str = "The member's name.";
        bit_offset: U64 = "Offset from the aggregate start, in bits.";
        ty: U32 = "Walk-local handle of the member's type.";
        bitfield_width: U32 = "Bit width for a bitfield member (0 for an ordinary field).";
        repr_vtype: U32 = "`value_repr_t` FRB_* value-type nibble, or 0 (`FRB_UNK`) when unset or \
                           outside the numeric subset idakit models.";
        repr_signed: Bool = "`FRB_SIGNED`; meaningless when `repr_vtype` is 0.";
        repr_leading_zeros: Bool = "`FRB_LZERO`; meaningless when `repr_vtype` is 0.";
    },
};

const ENUM_CONST_INFO: SharedStruct = SharedStruct {
    name: "EnumConstInfo",
    doc: "One enum constant, the enum twin of [`MemberInfo`].",
    fields: fields! {
        name: Str = "The constant's name.";
        value: U64 = "The constant's value.";
    },
};

const FRAME_VAR: SharedStruct = SharedStruct {
    name: "FrameVar",
    doc: "One stack-frame variable, an owned shared struct returned in a [`FrameWalk`].",
    fields: fields! {
        name: Str = "The variable's name.";
        offset: I64 = "Frame-pointer-relative byte offset.";
        size: U64 = "Size in bytes.";
        flags: U32 = "Reserved-slot flags (return address / saved registers); 0 for an ordinary \
                      variable.";
        ty: U32 = "Walk-local handle of the variable's type, or `IDAKIT_NONE` for a \
                   reserved/untyped slot.";
    },
};

const FRAME_WALK: SharedStruct = SharedStruct {
    name: "FrameWalk",
    doc: "A walked stack frame: its total byte size and its variables, returned by \
          `frame_type_walk_visit`.",
    fields: fields! {
        size: U64 = "Total frame size in bytes.";
        vars: VecStruct("FrameVar") = "The frame's variables, in frame order.";
    },
};

/// The ctree walk's sink: one method per expression, statement, and local variable kind, driven
/// depth-first (children before parents) by `facade/ctree_cxx.cc`'s `walker_t`.
const CTREE_SINK: VisitorSink = VisitorSink {
    sink_name: "CtreeSink",
    sink_doc: "A ctree walk target the visitor drives inline, one method per expression, \
               statement, and local variable kind.\n\nThe consumer (`idakit`) implements it over \
               its own node builder, and [`CtreeVisitor`] forwards every C++ call straight into \
               it. Expression/statement methods mint and return the walk-local handle the parent \
               will reference; children are visited before parents (post-order), so a method's \
               array/slice arguments are already-minted handles. [`l_lvar`](Self::l_lvar) is void \
               and appended in index order, the order [`e_var`](Self::e_var)'s `idx` refers to. \
               Byte slices (names, string literals, comments) are borrowed for the one call only.",
    visitor_name: "CtreeVisitor",
    visitor_doc: "The `cxx` `extern \"Rust\"` opaque the C++ ctree walk drives by calling its \
                  `&mut self` methods, each forwarding into the [`CtreeSink`] it was built over.\n\n\
                  `cxx` generates a C++ class with a member function per method below; \
                  `facade/ctree_cxx.cc` receives a `CtreeVisitor&` and calls them. The visitor \
                  holds the sink as a lifetime-erased raw pointer: [`ctree_visitor`] is its only \
                  constructor, and the caller keeps the borrowed sink alive across the one \
                  synchronous walk, so the pointer is always valid and unaliased when a method \
                  reborrows it.",
    methods: methods! {
        "A numeric literal; returns its handle."
            e_num(ea: U64, value: U64, ty: U32);
        "A floating-point literal; returns its handle."
            e_fnum(ea: U64, value: F64, ty: U32);
        "A reference to the global object at `target`, named `name`; returns its handle."
            e_obj(ea: U64, target: U64, name: Bytes, ty: U32);
        "A reference to local variable `idx` (the [`l_lvar`](Self::l_lvar) append order); returns \
         its handle."
            e_var(ea: U64, idx: U32, ty: U32);
        "A string literal; returns its handle."
            e_str(ea: U64, bytes: Bytes, ty: U32);
        "A decompiler-synthesized helper name; returns its handle."
            e_helper(ea: U64, bytes: Bytes, ty: U32);
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
         the raw `ctype_t` is passed for the sink to classify, absent operands as `IDAKIT_NONE`; \
         returns its handle."
            e_op(ea: U64, ctype: U32, x: U32, y: U32, z: U32, ty: U32);
        "A `{ ... }` block of the already-visited `kids`; returns its handle."
            s_block(ea: U64, kids: SliceU32);
        "An expression statement wrapping the already-visited `e`; returns its handle."
            s_expr(ea: U64, e: U32);
        "An `if`/`then`/`else` (else is `IDAKIT_NONE` when absent); returns its handle."
            s_if(ea: U64, cond: U32, then_s: U32, else_s: U32);
        "A `for` loop; any of `init`/`cond`/`step` may be `IDAKIT_NONE`; returns its handle."
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
        "A `return`, or a bare `return;` when `e` is `IDAKIT_NONE`; returns its handle."
            s_return(ea: U64, e: U32);
        "A `goto` to `label`; returns its handle."
            s_goto(ea: U64, label: I32);
        "An inline-asm block, one already-computed address per line; returns its handle."
            s_asm(ea: U64, addrs: SliceU64);
        "A `try`/`catch`, the already-visited guarded `body` and each `catches` block; returns its \
         handle."
            s_try(ea: U64, body: U32, catches: SliceU32);
        "A `throw`, or a bare `throw;` when `e` is `IDAKIT_NONE`; returns its handle."
            s_throw(ea: U64, e: U32);
        "An empty statement (or any statement kind the walk doesn't otherwise model); returns its \
         handle."
            s_empty(ea: U64);
        "One local variable, appended in index order, the index [`e_var`](Self::e_var)'s `idx` \
         refers to. `flags`: bit0 `is_arg`, bit1 `is_result`, bit2 `is_byref`. \
         `atype`/`reg1`/`reg2`/`sval` are the flattened `argloc_t` scalars; `pieces` is the \
         scattered-location fragments, empty unless `atype` marks a scattered (`ALOC_DIST`) \
         location."
            l_lvar(name: Bytes, ty: U32, flags: U32, width: U32, comment: Bytes, atype: U32,
                   reg1: U32, reg2: U32, sval: I64, pieces: SliceStruct("LocPiece")) -> Unit;
    },
};

/// The tinfo type walk's sink: one method per node kind, driven depth-first by
/// `facade/typewalk_cxx.cc`'s `visit_walker_t`.
const TYPE_WALK_SINK: VisitorSink = VisitorSink {
    sink_name: "TypeWalkSink",
    sink_doc: "A walk target the type visitor drives inline, one method per tinfo node kind.\n\n\
               The consumer (`idakit`) implements it over its own interned type table, and \
               [`TypeWalkVisitor`] forwards every C++ call straight into it. Handle-returning \
               methods mint and return the walk-local id the parent will reference (children are \
               visited before parents); the `fill_*` methods complete a placeholder minted \
               earlier by [`named_ref`](Self::named_ref)/[`anon`](Self::anon). Names and slices \
               are borrowed for the one call only.",
    visitor_name: "TypeWalkVisitor",
    visitor_doc: "The `cxx` `extern \"Rust\"` opaque the C++ type walk drives by calling its \
                  `&mut self` methods, each forwarding into the [`TypeWalkSink`] it was built \
                  over.\n\n`cxx` generates a C++ class with a member function per method below; \
                  `facade/typewalk_cxx.cc` receives a `TypeWalkVisitor&` and calls them. The \
                  visitor holds the sink as a lifetime-erased raw pointer: the \
                  [`walk_type_named`]/[`walk_type_ordinal`]/[`walk_func_type`] drivers are its \
                  only constructors, and each keeps the borrowed sink alive across the one \
                  synchronous walk, so the pointer is always valid and unaliased when a method \
                  reborrows it.",
    methods: methods! {
        "A scalar leaf (`kind`: 0 unknown, 1 void, 2 bool, 3 integral, 4 float); returns its \
         handle."
            scalar(kind: U32, bytes: U32, is_signed: U32, size: U64, has_size: U32);
        "A pointer to the already-visited `target`; returns its handle."
            ptr(target: U32, size: U64, has_size: U32);
        "An array of `nelems` of the already-visited `elem`; returns its handle."
            array(elem: U32, nelems: U64, size: U64, has_size: U32);
        "A function of the already-visited `ret` and `params`; returns its handle."
            func(ret: U32, params: SliceU32, vararg: U32);
        "A named-but-bodyless / unresolved leaf carrying its resolved `name`; returns its handle."
            opaque(name: Str);
        "A by-name placeholder for a named aggregate/typedef; returns its handle."
            named_ref(name: Str);
        "An anonymous-aggregate placeholder; returns its handle."
            anon();
        "Fills the struct/union placeholder `id` with its `members`."
            fill_struct(id: U32, is_union: Bool, members: SliceStruct("MemberInfo"), size: U64,
                        has_size: U32) -> Unit;
        "Fills the enum placeholder `id` with its `consts` over the already-visited `underlying`. \
         `repr_vtype`/`repr_signed`/`repr_leading_zeros` are the enum's own `value_repr_t`, the \
         same shape [`MemberInfo`](ffi::MemberInfo) carries per-member (0 = `FRB_UNK`/unmodeled)."
            fill_enum(id: U32, underlying: U32, consts: SliceStruct("EnumConstInfo"), size: U64,
                      has_size: U32, is_bitmask: Bool, repr_vtype: U32, repr_signed: Bool,
                      repr_leading_zeros: Bool) -> Unit;
        "Fills the typedef placeholder `id` with its already-visited `underlying`."
            fill_typedef(id: U32, underlying: U32) -> Unit;
    },
};

/// The visitor bridge's `extern "C++"` driver block: the four standalone type-walk entry points
/// plus the ctree walk's `cfunc_walk_ctree`, all hand-written in `facade/ctree_cxx.cc` /
/// `facade/typewalk_cxx.cc`.
const DRIVERS: &[VisitorDriverFn] = &[
    VisitorDriverFn {
        name: "cfunc_walk_ctree",
        doc: "Walk `cfunc`'s ctree, minting nodes and locals through `nodes` and node types \
              through the tinfo walker whose pointer is passed as an integer address in \
              `type_visitor` (`cxx` has no `c_void`; the C++ side reinterprets it back to `void*` \
              for the shared type walker). Returns the root statement handle.\n\n# Safety\n\
              `type_visitor` must be a live `TypeWalkVisitor*`, cast to `usize`, that outlives \
              the call.",
        args: args!(cfunc: ExternRef("CFunc"), nodes: VisitorMut("CtreeVisitor"), type_visitor: Usize),
        ret: RetKind::U32,
        unsafe_: true,
    },
    VisitorDriverFn {
        name: "type_walk_visit_named",
        doc: "Walk the local type named `name`, driving `visitor`'s methods per node; returns the \
              root handle. `Err` when no such type exists (or a thrown SDK error).",
        args: args!(name: Str, visitor: VisitorMut("TypeWalkVisitor")),
        ret: RetKind::ResultU32,
        unsafe_: false,
    },
    VisitorDriverFn {
        name: "type_walk_visit_ordinal",
        doc: "Walk the local type at `ordinal`, driving `visitor`'s methods per node; returns the \
              root handle. `Err` when no type occupies the ordinal (or a thrown SDK error).",
        args: args!(ordinal: U32, visitor: VisitorMut("TypeWalkVisitor")),
        ret: RetKind::ResultU32,
        unsafe_: false,
    },
    VisitorDriverFn {
        name: "func_type_walk_visit",
        doc: "Walk the stored prototype of the function at `ea`, driving `visitor`; returns the \
              root handle. `Err` when the function has no type info.",
        args: args!(ea: U64, visitor: VisitorMut("TypeWalkVisitor")),
        ret: RetKind::ResultU32,
        unsafe_: false,
    },
    VisitorDriverFn {
        name: "frame_type_walk_visit",
        doc: "Walk the stack frame of the function at `ea`: each variable's type through \
              `visitor`, returning the frame size and variables. `Err` when there is no function \
              or frame at `ea`.",
        args: args!(ea: U64, visitor: VisitorMut("TypeWalkVisitor")),
        ret: RetKind::ResultShared("FrameWalk"),
        unsafe_: false,
    },
];

/// The whole visitor bridge, built once: the five shared structs, the ctree and tinfo sink pairs,
/// and the shared driver block.
pub const VISITOR_BRIDGE: VisitorBridge = VisitorBridge {
    structs: &[
        LOC_PIECE,
        MEMBER_INFO,
        ENUM_CONST_INFO,
        FRAME_VAR,
        FRAME_WALK,
    ],
    sinks: &[CTREE_SINK, TYPE_WALK_SINK],
    drivers: DRIVERS,
};
