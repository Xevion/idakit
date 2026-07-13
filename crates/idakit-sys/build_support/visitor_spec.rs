//! The declarative manifest for the ctree/tinfo `extern "Rust"` opaque-visitor bridge.
//!
//! [`VISITOR_BRIDGE`] pairs the ctree walk's [`CtreeSink`](VisitorSink)-shaped spec with the tinfo
//! type walk's, plus the shared `extern "C++"` driver block both are called through. The engine
//! that turns this into the Rust bridge and the C++ shim glue lives in the sibling `gen.rs`; the
//! hand-written C++ drivers stay in `facade/ctree_cxx.cc` / `facade/typewalk_cxx.cc`.

use super::{
    Arg, ArgTy, Field, FieldTy, RetKind, SharedStruct, VisitorBridge, VisitorDriverFn,
    VisitorMethod, VisitorSink,
};

const LOC_PIECE: SharedStruct = SharedStruct {
    name: "LocPiece",
    doc: "One fragment of a scattered (`ALOC_DIST`) local's location. `atype` is the fragment's \
          own `ALOC_*` (a register or stack slot); `off`/`size` give the byte range of the whole \
          value this fragment covers.",
    fields: &[
        Field {
            name: "atype",
            ty: FieldTy::U32,
            doc: "The fragment's own `ALOC_*` discriminant.",
        },
        Field {
            name: "reg",
            ty: FieldTy::U32,
            doc: "Register number, meaningful only for a register fragment.",
        },
        Field {
            name: "sval",
            ty: FieldTy::I64,
            doc: "Stack offset or static address, meaningful only for a stack/static fragment.",
        },
        Field {
            name: "off",
            ty: FieldTy::U32,
            doc: "Byte offset of this fragment within the whole scattered value.",
        },
        Field {
            name: "size",
            ty: FieldTy::U32,
            doc: "Byte size of this fragment.",
        },
    ],
};

const MEMBER_INFO: SharedStruct = SharedStruct {
    name: "MemberInfo",
    doc: "One struct/union member, crossed inside a slice for one `fill_struct` call. `name` is an \
          owned `String`: the sink interns members into its own table, so the transient owned copy \
          the walk allocates is copied on anyway.",
    fields: &[
        Field {
            name: "name",
            ty: FieldTy::Str,
            doc: "The member's name.",
        },
        Field {
            name: "bit_offset",
            ty: FieldTy::U64,
            doc: "Offset from the aggregate start, in bits.",
        },
        Field {
            name: "ty",
            ty: FieldTy::U32,
            doc: "Walk-local handle of the member's type.",
        },
        Field {
            name: "bitfield_width",
            ty: FieldTy::U32,
            doc: "Bit width for a bitfield member (0 for an ordinary field).",
        },
        Field {
            name: "repr_vtype",
            ty: FieldTy::U32,
            doc: "`value_repr_t` FRB_* value-type nibble, or 0 (`FRB_UNK`) when unset or outside \
                  the numeric subset idakit models.",
        },
        Field {
            name: "repr_signed",
            ty: FieldTy::Bool,
            doc: "`FRB_SIGNED`; meaningless when `repr_vtype` is 0.",
        },
        Field {
            name: "repr_leading_zeros",
            ty: FieldTy::Bool,
            doc: "`FRB_LZERO`; meaningless when `repr_vtype` is 0.",
        },
    ],
};

const ENUM_CONST_INFO: SharedStruct = SharedStruct {
    name: "EnumConstInfo",
    doc: "One enum constant, the enum twin of [`MemberInfo`].",
    fields: &[
        Field {
            name: "name",
            ty: FieldTy::Str,
            doc: "The constant's name.",
        },
        Field {
            name: "value",
            ty: FieldTy::U64,
            doc: "The constant's value.",
        },
    ],
};

const FRAME_VAR: SharedStruct = SharedStruct {
    name: "FrameVar",
    doc: "One stack-frame variable, an owned shared struct returned in a [`FrameWalk`].",
    fields: &[
        Field {
            name: "name",
            ty: FieldTy::Str,
            doc: "The variable's name.",
        },
        Field {
            name: "offset",
            ty: FieldTy::I64,
            doc: "Frame-pointer-relative byte offset.",
        },
        Field {
            name: "size",
            ty: FieldTy::U64,
            doc: "Size in bytes.",
        },
        Field {
            name: "flags",
            ty: FieldTy::U32,
            doc: "Reserved-slot flags (return address / saved registers); 0 for an ordinary \
                  variable.",
        },
        Field {
            name: "ty",
            ty: FieldTy::U32,
            doc: "Walk-local handle of the variable's type, or `IDAKIT_NONE` for a \
                  reserved/untyped slot.",
        },
    ],
};

const FRAME_WALK: SharedStruct = SharedStruct {
    name: "FrameWalk",
    doc: "A walked stack frame: its total byte size and its variables, returned by \
          `frame_type_walk_visit`.",
    fields: &[
        Field {
            name: "size",
            ty: FieldTy::U64,
            doc: "Total frame size in bytes.",
        },
        Field {
            name: "vars",
            ty: FieldTy::VecStruct("FrameVar"),
            doc: "The frame's variables, in frame order.",
        },
    ],
};

const EA: &[Arg] = &[Arg {
    name: "ea",
    ty: ArgTy::U64,
}];

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
    methods: &[
        VisitorMethod {
            name: "e_num",
            doc: "A numeric literal; returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "value",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "ty",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "e_fnum",
            doc: "A floating-point literal; returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "value",
                    ty: ArgTy::F64,
                },
                Arg {
                    name: "ty",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "e_obj",
            doc: "A reference to the global object at `target`, named `name`; returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "target",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "name",
                    ty: ArgTy::Bytes,
                },
                Arg {
                    name: "ty",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "e_var",
            doc: "A reference to local variable `idx` (the [`l_lvar`](Self::l_lvar) append \
                  order); returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "idx",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "ty",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "e_str",
            doc: "A string literal; returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "bytes",
                    ty: ArgTy::Bytes,
                },
                Arg {
                    name: "ty",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "e_helper",
            doc: "A decompiler-synthesized helper name; returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "bytes",
                    ty: ArgTy::Bytes,
                },
                Arg {
                    name: "ty",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "e_call",
            doc: "A call to the already-visited `callee` with the already-visited `args`; returns \
                  its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "callee",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "args",
                    ty: ArgTy::SliceU32,
                },
                Arg {
                    name: "ty",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "e_memref",
            doc: "A `.` member reference into the already-visited `obj` at bit `offset`; returns \
                  its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "obj",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "offset",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "ty",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "e_memptr",
            doc: "A `->` member pointer into the already-visited `obj` at bit `offset`; returns \
                  its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "obj",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "offset",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "ty",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "e_deref",
            doc: "A pointer dereference of the already-visited `x`, `size` bytes; returns its \
                  handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "x",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "size",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "ty",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "e_op",
            doc: "A generic operator node (binary/assign/unary/ternary/cast/index/sizeof/empty/\
                  type/insn); the raw `ctype_t` is passed for the sink to classify, absent \
                  operands as `IDAKIT_NONE`; returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "ctype",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "x",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "y",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "z",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "ty",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_block",
            doc: "A `{ ... }` block of the already-visited `kids`; returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "kids",
                    ty: ArgTy::SliceU32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_expr",
            doc: "An expression statement wrapping the already-visited `e`; returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "e",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_if",
            doc: "An `if`/`then`/`else` (else is `IDAKIT_NONE` when absent); returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "cond",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "then_s",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "else_s",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_for",
            doc: "A `for` loop; any of `init`/`cond`/`step` may be `IDAKIT_NONE`; returns its \
                  handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "init",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "cond",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "step",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "body",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_while",
            doc: "A `while` loop; returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "cond",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "body",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_do",
            doc: "A `do`/`while` loop; returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "body",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "cond",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_switch",
            doc: "A `switch`, as parallel flat arrays: `bodies[i]` is case `i`'s body handle, \
                  `value_counts[i]` is how many `u64` values case `i` has, and `values` is all \
                  case values concatenated in order (case 0's values, then case 1's, ...). An \
                  empty values run is the default case. Returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "expr",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "bodies",
                    ty: ArgTy::SliceU32,
                },
                Arg {
                    name: "value_counts",
                    ty: ArgTy::SliceU32,
                },
                Arg {
                    name: "values",
                    ty: ArgTy::SliceU64,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_break",
            doc: "A `break`; returns its handle.",
            args: EA,
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_continue",
            doc: "A `continue`; returns its handle.",
            args: EA,
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_return",
            doc: "A `return`, or a bare `return;` when `e` is `IDAKIT_NONE`; returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "e",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_goto",
            doc: "A `goto` to `label`; returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "label",
                    ty: ArgTy::I32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_asm",
            doc: "An inline-asm block, one already-computed address per line; returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "addrs",
                    ty: ArgTy::SliceU64,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_try",
            doc: "A `try`/`catch`, the already-visited guarded `body` and each `catches` block; \
                  returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "body",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "catches",
                    ty: ArgTy::SliceU32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_throw",
            doc: "A `throw`, or a bare `throw;` when `e` is `IDAKIT_NONE`; returns its handle.",
            args: &[
                Arg {
                    name: "ea",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "e",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "s_empty",
            doc: "An empty statement (or any statement kind the walk doesn't otherwise model); \
                  returns its handle.",
            args: EA,
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "l_lvar",
            doc: "One local variable, appended in index order, the index \
                  [`e_var`](Self::e_var)'s `idx` refers to. `flags`: bit0 `is_arg`, bit1 \
                  `is_result`, bit2 `is_byref`. `atype`/`reg1`/`reg2`/`sval` are the flattened \
                  `argloc_t` scalars; `pieces` is the scattered-location fragments, empty unless \
                  `atype` marks a scattered (`ALOC_DIST`) location.",
            args: &[
                Arg {
                    name: "name",
                    ty: ArgTy::Bytes,
                },
                Arg {
                    name: "ty",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "flags",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "width",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "comment",
                    ty: ArgTy::Bytes,
                },
                Arg {
                    name: "atype",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "reg1",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "reg2",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "sval",
                    ty: ArgTy::I64,
                },
                Arg {
                    name: "pieces",
                    ty: ArgTy::SliceStruct("LocPiece"),
                },
            ],
            ret: RetKind::Unit,
            too_many_args: true,
        },
    ],
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
    methods: &[
        VisitorMethod {
            name: "scalar",
            doc: "A scalar leaf (`kind`: 0 unknown, 1 void, 2 bool, 3 integral, 4 float); returns \
                  its handle.",
            args: &[
                Arg {
                    name: "kind",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "bytes",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "is_signed",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "size",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "has_size",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "ptr",
            doc: "A pointer to the already-visited `target`; returns its handle.",
            args: &[
                Arg {
                    name: "target",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "size",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "has_size",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "array",
            doc: "An array of `nelems` of the already-visited `elem`; returns its handle.",
            args: &[
                Arg {
                    name: "elem",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "nelems",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "size",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "has_size",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "func",
            doc: "A function of the already-visited `ret` and `params`; returns its handle.",
            args: &[
                Arg {
                    name: "ret",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "params",
                    ty: ArgTy::SliceU32,
                },
                Arg {
                    name: "vararg",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "opaque",
            doc: "A named-but-bodyless / unresolved leaf carrying its resolved `name`; returns \
                  its handle.",
            args: &[Arg {
                name: "name",
                ty: ArgTy::Str,
            }],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "named_ref",
            doc: "A by-name placeholder for a named aggregate/typedef; returns its handle.",
            args: &[Arg {
                name: "name",
                ty: ArgTy::Str,
            }],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "anon",
            doc: "An anonymous-aggregate placeholder; returns its handle.",
            args: &[],
            ret: RetKind::U32,
            too_many_args: false,
        },
        VisitorMethod {
            name: "fill_struct",
            doc: "Fills the struct/union placeholder `id` with its `members`.",
            args: &[
                Arg {
                    name: "id",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "is_union",
                    ty: ArgTy::Bool,
                },
                Arg {
                    name: "members",
                    ty: ArgTy::SliceStruct("MemberInfo"),
                },
                Arg {
                    name: "size",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "has_size",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::Unit,
            too_many_args: false,
        },
        VisitorMethod {
            name: "fill_enum",
            doc: "Fills the enum placeholder `id` with its `consts` over the already-visited \
                  `underlying`. `repr_vtype`/`repr_signed`/`repr_leading_zeros` are the enum's \
                  own `value_repr_t`, the same shape [`MemberInfo`](ffi::MemberInfo) carries \
                  per-member (0 = `FRB_UNK`/unmodeled).",
            args: &[
                Arg {
                    name: "id",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "underlying",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "consts",
                    ty: ArgTy::SliceStruct("EnumConstInfo"),
                },
                Arg {
                    name: "size",
                    ty: ArgTy::U64,
                },
                Arg {
                    name: "has_size",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "is_bitmask",
                    ty: ArgTy::Bool,
                },
                Arg {
                    name: "repr_vtype",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "repr_signed",
                    ty: ArgTy::Bool,
                },
                Arg {
                    name: "repr_leading_zeros",
                    ty: ArgTy::Bool,
                },
            ],
            ret: RetKind::Unit,
            too_many_args: true,
        },
        VisitorMethod {
            name: "fill_typedef",
            doc: "Fills the typedef placeholder `id` with its already-visited `underlying`.",
            args: &[
                Arg {
                    name: "id",
                    ty: ArgTy::U32,
                },
                Arg {
                    name: "underlying",
                    ty: ArgTy::U32,
                },
            ],
            ret: RetKind::Unit,
            too_many_args: false,
        },
    ],
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
        args: &[
            Arg {
                name: "cfunc",
                ty: ArgTy::ExternRef("CFunc"),
            },
            Arg {
                name: "nodes",
                ty: ArgTy::VisitorMut("CtreeVisitor"),
            },
            Arg {
                name: "type_visitor",
                ty: ArgTy::Usize,
            },
        ],
        ret: RetKind::U32,
        unsafe_: true,
    },
    VisitorDriverFn {
        name: "type_walk_visit_named",
        doc: "Walk the local type named `name`, driving `visitor`'s methods per node; returns the \
              root handle. `Err` when no such type exists (or a thrown SDK error).",
        args: &[
            Arg {
                name: "name",
                ty: ArgTy::Str,
            },
            Arg {
                name: "visitor",
                ty: ArgTy::VisitorMut("TypeWalkVisitor"),
            },
        ],
        ret: RetKind::ResultU32,
        unsafe_: false,
    },
    VisitorDriverFn {
        name: "type_walk_visit_ordinal",
        doc: "Walk the local type at `ordinal`, driving `visitor`'s methods per node; returns the \
              root handle. `Err` when no type occupies the ordinal (or a thrown SDK error).",
        args: &[
            Arg {
                name: "ordinal",
                ty: ArgTy::U32,
            },
            Arg {
                name: "visitor",
                ty: ArgTy::VisitorMut("TypeWalkVisitor"),
            },
        ],
        ret: RetKind::ResultU32,
        unsafe_: false,
    },
    VisitorDriverFn {
        name: "func_type_walk_visit",
        doc: "Walk the stored prototype of the function at `ea`, driving `visitor`; returns the \
              root handle. `Err` when the function has no type info.",
        args: &[
            Arg {
                name: "ea",
                ty: ArgTy::U64,
            },
            Arg {
                name: "visitor",
                ty: ArgTy::VisitorMut("TypeWalkVisitor"),
            },
        ],
        ret: RetKind::ResultU32,
        unsafe_: false,
    },
    VisitorDriverFn {
        name: "frame_type_walk_visit",
        doc: "Walk the stack frame of the function at `ea`: each variable's type through \
              `visitor`, returning the frame size and variables. `Err` when there is no function \
              or frame at `ea`.",
        args: &[
            Arg {
                name: "ea",
                ty: ArgTy::U64,
            },
            Arg {
                name: "visitor",
                ty: ArgTy::VisitorMut("TypeWalkVisitor"),
            },
        ],
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
