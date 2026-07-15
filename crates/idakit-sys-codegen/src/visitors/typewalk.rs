//! The tinfo type walk's sink and its private shared structs.

use super::super::model::*;

pub(super) const MEMBER_INFO: SharedStruct = SharedStruct {
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

pub(super) const ENUM_CONST_INFO: SharedStruct = SharedStruct {
    name: "EnumConstInfo",
    doc: "One enum constant, the enum twin of [`MemberInfo`].",
    fields: fields! {
        name: Str = "The constant's name.";
        value: U64 = "The constant's value.";
    },
};

pub(super) const FRAME_VAR: SharedStruct = SharedStruct {
    name: "FrameVar",
    doc: "One stack-frame variable, an owned shared struct returned in a [`FrameWalk`].",
    fields: fields! {
        name: Str = "The variable's name.";
        offset: I64 = "Frame-pointer-relative byte offset.";
        size: U64 = "Size in bytes.";
        flags: U32 = "Reserved-slot flags (return address / saved registers); 0 for an ordinary \
                      variable.";
        ty: U32 = "Walk-local handle of the variable's type, or `NONE` for a \
                   reserved/untyped slot.";
    },
};

pub(super) const FRAME_WALK: SharedStruct = SharedStruct {
    name: "FrameWalk",
    doc: "A walked stack frame: its total byte size and its variables, returned by \
          `frame_type_walk_visit`.",
    fields: fields! {
        size: U64 = "Total frame size in bytes.";
        vars: VecStruct("FrameVar") = "The frame's variables, in frame order.";
    },
};

/// The tinfo type walk's sink: one method per node kind, driven depth-first by
/// `facade/typewalk_cxx.cc`'s `visit_walker_t`.
pub(super) const TYPE_WALK_SINK: VisitorSink = VisitorSink {
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
