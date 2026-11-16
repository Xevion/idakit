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
        attributes: U32 = "Raw `udm_t::tafld_bits`.";
        has_comment: Bool = "Whether the member carries a comment.";
        comment: Str = "The member's comment; empty when `has_comment` is false.";
    },
};

pub(super) const ENUM_CONST_INFO: SharedStruct = SharedStruct {
    name: "EnumConstInfo",
    doc: "One enum constant, the enum twin of [`MemberInfo`].",
    fields: fields! {
        name: Str = "The constant's name.";
        value: U64 = "The constant's value.";
        has_comment: Bool = "Whether the constant carries a comment.";
        comment: Str = "The constant's (always repeatable) comment; empty when `has_comment` is \
                        false.";
    },
};

pub(super) const FRAME_VAR: SharedStruct = SharedStruct {
    name: "FrameVar",
    doc: "One stack-frame variable, an owned shared struct returned in a [`FrameWalk`].",
    fields: fields! {
        name: Str = "The variable's name.";
        offset: I64 = "Frame-pointer-relative byte offset.";
        size: U64 = "Size in bytes.";
        attributes: U32 = "Raw `udm_t::tafld_bits`; `TAFLD_FRAME_R`/`TAFLD_FRAME_S` mark the \
                           reserved return-address and saved-registers slots.";
        has_comment: Bool = "Whether the slot carries a comment.";
        comment: Str = "The slot's comment; empty when `has_comment` is false.";
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

pub(super) const FUNC_ARG: SharedStruct = SharedStruct {
    name: "FuncArg",
    doc: "One `funcarg_t`, crossed inside a slice for one `func` call.",
    fields: fields! {
        name: Str = "The parameter's name; empty when unnamed.";
        comment: Str = "The parameter's comment; empty when it has none.";
        ty: U32 = "Walk-local handle of the parameter's type.";
        flags: U32 = "Raw `funcarg_t::flags` (`FAI_*`).";
        location: Struct("ArgLoc") = "The parameter's location.";
    },
};

pub(super) const SPOILED_REG: SharedStruct = SharedStruct {
    name: "SpoiledReg",
    doc: "One `reg_info_t` of a prototype's spoiled-register list.",
    fields: fields! {
        reg: U32 = "Register number.";
        size: U32 = "Size in bytes of the spoiled part.";
    },
};

/// The tinfo type walk's sink: one method per node kind, driven depth-first by
/// `facade/typewalk_bridge.cpp`'s `visit_walker_t`.
pub(super) const TYPE_WALK_SINK: VisitorSink = VisitorSink {
    sink_name: "TypeWalkSink",
    sink_doc: "A walk target the type visitor drives inline, one method per tinfo node kind.\n\n\
               The consumer (`idakit`) implements it over its own interned type table, and \
               [`TypeWalkVisitor`] forwards every C++ call straight into it. Handle-returning \
               methods mint and return the walk-local id the parent will reference (children are \
               visited before parents); the `fill_*` methods complete a placeholder minted \
               earlier by [`named_ref`](Self::named_ref)/[`anon`](Self::anon). A type name crosses \
               as an owned `String`, decoded leniently facade-side; slices are borrowed for the \
               one call only.",
    visitor_name: "TypeWalkVisitor",
    visitor_doc: "The `cxx` `extern \"Rust\"` opaque the C++ type walk drives by calling its \
                  `&mut self` methods, each forwarding into the [`TypeWalkSink`] it was built \
                  over.\n\n`cxx` generates a C++ class with a member function per method below; \
                  `facade/typewalk_bridge.cpp` receives a `TypeWalkVisitor&` and calls them. The \
                  visitor holds the sink as a lifetime-erased raw pointer: the \
                  [`walk_type_named`]/[`walk_type_ordinal`]/[`walk_func_type`] drivers are its \
                  only constructors, and each keeps the borrowed sink alive across the one \
                  synchronous walk, so the pointer is always valid and unaliased when a method \
                  reborrows it.",
    methods: methods! {
        "A scalar leaf (`kind`: 0 unknown, 1 void, 2 bool, 3 integral, 4 float); returns its \
         handle."
            scalar(kind: U32, bytes: U32, is_signed: U32, size: U64, has_size: U32);
        "A pointer to the already-visited `target`, with its raw `taptr_bits`; returns its \
         handle. A `__shifted` pointer names its already-visited `parent` struct and `delta` into \
         it; `parent` is `NONE` otherwise."
            ptr(target: U32, size: U64, has_size: U32, attributes: U32, parent: U32, delta: I32);
        "An array of `nelems` of the already-visited `elem`; returns its handle."
            array(elem: U32, nelems: U64, size: U64, has_size: U32);
        "A function of the already-visited `ret` and `params`, with the raw `callcnv_t` `cc` (0, \
         `CM_CC_INVALID`, when the SDK reports no details), the raw `FTI_*` `flags`, and \
         `func_type_data_t`'s `retloc`, `stkargs`, and `spoiled`; returns its handle."
            func(ret: U32, params: SliceStruct("FuncArg"), cc: U32, flags: U32,
                 retloc: StructRef("ArgLoc"), stkargs: U64, spoiled: SliceStruct("SpoiledReg"));
        "A `const`/`volatile` qualification of the already-visited `inner`, with the raw \
         `type_t` modifier bits; returns its handle. `size` is the qualified type's own size."
            qualified(inner: U32, qualifiers: U8, size: U64, has_size: U32);
        "A named-but-bodyless / unresolved leaf carrying its resolved `name`; returns its handle."
            opaque(name: String);
        "A by-name placeholder for a named aggregate/typedef; returns its handle."
            named_ref(name: String);
        "An anonymous-aggregate placeholder; returns its handle."
            anon();
        "Fills the struct/union placeholder `id` with its `members`, raw `taudt_bits`, and \
         layout. `size` is `total_size`; `declared_alignment_shift` is `sda` (shift + 1, 0 when \
         unspecified) and `pack` is the raw `#pragma pack` value (0 when unset)."
            fill_struct(id: U32, is_union: Bool, members: SliceStruct("MemberInfo"), size: U64,
                        has_size: U32, attributes: U32, unpadded_size: U64,
                        effective_alignment: U32, declared_alignment_shift: U32,
                        pack: U32) -> Unit;
        "Fills the enum placeholder `id` with its `consts` over the already-visited `underlying`, \
         its raw `taenum_bits`, and its bitmask `group_sizes` (empty when the SDK reports none). \
         `repr_vtype`/`repr_signed`/`repr_leading_zeros` are the enum's own `value_repr_t`, the \
         same shape [`MemberInfo`](ffi::MemberInfo) carries per-member (0 = `FRB_UNK`/unmodeled)."
            fill_enum(id: U32, underlying: U32, consts: SliceStruct("EnumConstInfo"), size: U64,
                      has_size: U32, is_bitmask: Bool, repr_vtype: U32, repr_signed: Bool,
                      repr_leading_zeros: Bool, attributes: U32, group_sizes: SliceU32) -> Unit;
        "Fills the typedef placeholder `id` with its already-visited `underlying`."
            fill_typedef(id: U32, underlying: U32) -> Unit;
    },
};
