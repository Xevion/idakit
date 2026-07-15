use super::super::model::*;

/// The type-write domain: parse, resolve, build, and apply `tinfo`s, define/delete/rename types in
/// the local til, and edit UDT/enum members. Every call returns a [`TypeWriteResult`] (or [`SigWriteResult`]
/// for the two signature-surgery fns that also report the parameter count) in place of the raw
/// facade's `int` code plus error-buffer out-param: the struct's `code` carries the same return
/// value and `reason` the captured diagnostic. Bodies are hand-written in `facade/type_build_custom.cc`.
pub const TYPE_BUILD: Domain = Domain {
    name: "type_build",
    sdk_includes: &["<kernwin.hpp>", "<nalt.hpp>", "<typeinf.hpp>"],
    externs: &[ExternTy {
        rust_name: "TInfo",
        cxx_name: "tinfo_t",
        kind: ExternKind::Opaque,
        doc: "The SDK's `tinfo_t`, an opaque type-info handle handled only behind indirection \
              (`&TInfo` or `UniquePtr<TInfo>`).",
        safety: "The type id names the real SDK class tinfo_t; Opaque is correct because tinfo_t \
                 has a nontrivial copy-ctor and destructor, so it may only cross the bridge behind \
                 a reference or UniquePtr, never by value. The UniquePtr's cxx deleter runs \
                 ~tinfo_t, matching the raw handle's free.",
    }],
    structs: &[
        SharedStruct {
            name: "TypeWriteResult",
            doc: "The outcome of a type-write call, returned by value from every type-write \
                  function except the two signature-surgery fns.",
            fields: fields! {
                code: I32 = "Raw facade code: an `TYPE_*`/`TEDIT_*` sentinel, a negative \
                          `tinfo_code_t`, or `define_type`'s parse-error count.";
                reason: Str = "Captured IDA diagnostic, empty when the call has no error channel.";
            },
        },
        SharedStruct {
            name: "SigWriteResult",
            doc: "The outcome of a signature-surgery call that also reports the function's \
                  parameter count.",
            fields: fields! {
                code: I32 = "Raw facade `SIG_*` code.";
                arity: Usize = "Parameter count of the edited function type (`0` when it has no type).";
                reason: Str = "Captured IDA diagnostic, empty when none.";
            },
        },
    ],
    consts: &[
        ConstDef {
            name: "TYPE_OK",
            ty: ConstTy::I32,
            value: 0,
            doc: "Result of a successful type apply.",
        },
        ConstDef {
            name: "TYPE_ERR_INPUT",
            ty: ConstTy::I32,
            value: 1,
            doc: "A bad input to a type apply: an unparseable declaration, a named type that does \
                  not exist, or a malformed recipe.",
        },
        ConstDef {
            name: "TYPE_ERR_APPLY",
            ty: ConstTy::I32,
            value: 2,
            doc: "`apply_tinfo` rejected the parsed/resolved/built type at the address.",
        },
        ConstDef {
            name: "SIG_OK",
            ty: ConstTy::I32,
            value: 0,
            doc: "A prototype-surgery edit succeeded.",
        },
        ConstDef {
            name: "SIG_NO_PROTOTYPE",
            ty: ConstTy::I32,
            value: 1,
            doc: "The address carries no function type to edit.",
        },
        ConstDef {
            name: "SIG_ARG_RANGE",
            ty: ConstTy::I32,
            value: 2,
            doc: "A parameter index was past the last parameter.",
        },
        ConstDef {
            name: "SIG_BUILD",
            ty: ConstTy::I32,
            value: 3,
            doc: "A replacement-type recipe did not build.",
        },
        ConstDef {
            name: "SIG_APPLY",
            ty: ConstTy::I32,
            value: 4,
            doc: "`create_func` or `apply_tinfo` rejected the rebuilt signature.",
        },
        ConstDef {
            name: "TEDIT_NO_TYPE",
            ty: ConstTy::I32,
            value: 1,
            doc: "Member-edit pre-failure: no such named type in the local til.",
        },
        ConstDef {
            name: "TEDIT_NO_MEMBER",
            ty: ConstTy::I32,
            value: 2,
            doc: "Member-edit pre-failure: the member (by name or bit offset) did not resolve.",
        },
        ConstDef {
            name: "TEDIT_BUILD",
            ty: ConstTy::I32,
            value: 3,
            doc: "Member-edit pre-failure: a member-type recipe did not build.",
        },
        ConstDef {
            name: "MEMBER_APPEND",
            ty: ConstTy::U64,
            value: u64::MAX as i128,
            doc: "`member_bit` value that appends a new member at the end rather than a fixed \
                  offset.",
        },
        ConstDef {
            name: "RECIPE_VOID",
            ty: ConstTy::U8,
            value: 0,
            doc: "Recipe opcode: push the `void` type.",
        },
        ConstDef {
            name: "RECIPE_BOOL",
            ty: ConstTy::U8,
            value: 1,
            doc: "Recipe opcode: push the boolean type.",
        },
        ConstDef {
            name: "RECIPE_INT",
            ty: ConstTy::U8,
            value: 2,
            doc: "Recipe opcode: push an integer, followed by a `u8` width in bytes and a `u8` \
                  signedness flag.",
        },
        ConstDef {
            name: "RECIPE_FLOAT",
            ty: ConstTy::U8,
            value: 3,
            doc: "Recipe opcode: push a float, followed by a `u8` width in bytes.",
        },
        ConstDef {
            name: "RECIPE_NAMED",
            ty: ConstTy::U8,
            value: 4,
            doc: "Recipe opcode: push a named-type reference, followed by a `u32` length and that \
                  many name bytes.",
        },
        ConstDef {
            name: "RECIPE_DECL",
            ty: ConstTy::U8,
            value: 5,
            doc: "Recipe opcode: push a parsed declaration, followed by a `u32` length and that \
                  many decl bytes.",
        },
        ConstDef {
            name: "RECIPE_PTR",
            ty: ConstTy::U8,
            value: 6,
            doc: "Recipe opcode: pop one type, push a pointer to it.",
        },
        ConstDef {
            name: "RECIPE_ARRAY",
            ty: ConstTy::U8,
            value: 7,
            doc: "Recipe opcode: pop one type, push an array of it, followed by a `u64` element \
                  count.",
        },
        ConstDef {
            name: "RECIPE_CONST",
            ty: ConstTy::U8,
            value: 8,
            doc: "Recipe opcode: pop one type, push its `const`-qualified form.",
        },
        ConstDef {
            name: "RECIPE_VOLATILE",
            ty: ConstTy::U8,
            value: 9,
            doc: "Recipe opcode: pop one type, push its `volatile`-qualified form.",
        },
        ConstDef {
            name: "RECIPE_FUNCTION",
            ty: ConstTy::U8,
            value: 10,
            doc: "Recipe opcode: build a function type (`u32` param count, `u8` varargs, `u16` cc, \
                  then that many `u32`-length-prefixed param names; pops the params then the \
                  return type, pushes the function).",
        },
        ConstDef {
            name: "RECIPE_BITFIELD",
            ty: ConstTy::U8,
            value: 11,
            doc: "Recipe opcode: build a bitfield member type (`u8` container width in bytes, `u8` \
                  field width in bits, `u8` signedness); struct-member-only, rejected in a union.",
        },
    ],
    custom_tu: Some("facade/type_build_custom.cc"),
    body_helpers: None,
    fns: fns! {
        "Parse `decl` against the local til and apply it at `ea`. `code` is `TYPE_OK`, \
         `_ERR_INPUT` (parse failed), or `_ERR_APPLY`."
            apply_type_decl(ea: U64, decl: Str, flags: I32) -> Shared("TypeWriteResult");
        "Resolve the existing named type `name` and apply it at `ea`. `code` distinguishes \
         not-found (`_ERR_INPUT`) from an apply rejection (`_ERR_APPLY`); `reason` is empty (no \
         error channel)."
            apply_named_type(ea: U64, name: Str) -> Shared("TypeWriteResult");
        "Clear any type applied at `ea`. Idempotent: `code` is `TYPE_OK` when there was \
         nothing to clear; `reason` is empty (no error channel)."
            clear_type(ea: U64) -> Shared("TypeWriteResult");
        "Build the `tinfo` the postfix recipe encodes and apply it at `ea`. Same codes as \
         [`apply_type_decl`]; `_ERR_INPUT` is a malformed buffer or an unparseable embedded decl. \
         An unknown named leaf builds a forward reference that fails later at apply, not here."
            apply_type_recipe(ea: U64, recipe: Bytes, flags: I32) -> Shared("TypeWriteResult");
        "Parse the C declaration(s) in `input` into the local til. `code` is the parse-error count \
         (`0` = ok)."
            define_type(input: Str) -> Shared("TypeWriteResult");
        "Delete the named type `type_name` from the local til, the inverse of [`define_type`]. See \
         the `TEDIT_*` codes."
            delete_type(type_name: Str) -> Shared("TypeWriteResult");
        "Rename the named type `type_name` to `new_name` in place, preserving its ordinal. Same \
         `TEDIT_*` codes as the `udt_*`/`enum_*` fns."
            rename_type(type_name: Str, new_name: Str) -> Shared("TypeWriteResult");
        "Reserve `type_name` in the local til as an incomplete aggregate \
         (`tinfo_t::create_forward_decl`), without a body. `decl_type` is a `type_t` \
         (`BTF_STRUCT`/`BTF_UNION`/`BTF_ENUM`) selecting the aggregate kind. `code` is the raw \
         `tinfo_code_t` (`0` = ok); no `TEDIT_*` pre-failure, since there is no existing \
         type to load first."
            forward_declare_type(type_name: Str, decl_type: U32) -> Shared("TypeWriteResult");
        "Replace the return type of the function type at `ea` with the recipe type, then rebuild \
         and re-apply. See the `SIG_*` codes."
            func_set_rettype(ea: U64, recipe: Bytes) -> Shared("TypeWriteResult");
        "Replace parameter `idx`'s type with the recipe type, then rebuild and re-apply. `arity` \
         reports the current parameter count; `SIG_ARG_RANGE` when `idx` is past it."
            func_set_argtype(ea: U64, idx: Usize, recipe: Bytes) -> Shared("SigWriteResult");
        "Rename parameter `idx` to `name`, then rebuild and re-apply. `arity` reports the current \
         parameter count; `SIG_ARG_RANGE` when `idx` is past it."
            func_rename_arg(ea: U64, idx: Usize, name: Str) -> Shared("SigWriteResult");
        "Set the calling convention of the function type at `ea` to the raw `CM_CC_*` code `cc`, \
         then rebuild and re-apply."
            func_set_cc(ea: U64, cc: I32) -> Shared("TypeWriteResult");
        "Insert an implicit `this` parameter of the recipe type at index 0, then rebuild and \
         re-apply."
            func_prepend_this(ea: U64, recipe: Bytes) -> Shared("TypeWriteResult");
        "Add a member of the recipe type to the named struct/union `type_name` at bit offset \
         `member_bit` (or appended when it is `MEMBER_APPEND`). An empty `member_name` adds \
         an anonymous member. See the `TEDIT_*` codes."
            udt_add_member(type_name: Str, member_name: Str, recipe: Bytes, member_bit: U64)
                -> Shared("TypeWriteResult");
        "Replace the type of the member selected by `member_name` (or, when it is empty, by bit \
         offset `member_bit`) in `type_name` with the recipe type, passing `etf_flags` \
         (`etf_flag_t`, e.g. `ETF_COMPATIBLE`) to `set_udm_type`."
            udt_set_member_type(type_name: Str, member_name: Str, member_bit: U64, recipe: Bytes,
                etf_flags: U32) -> Shared("TypeWriteResult");
        "Rename the member selected by `member_name` (or, when it is empty, by bit offset \
         `member_bit`) in `type_name` to `new_name`."
            udt_rename_member(type_name: Str, member_name: Str, member_bit: U64, new_name: Str)
                -> Shared("TypeWriteResult");
        "Set the comment on the member selected by `member_name` (or, when it is empty, by bit \
         offset `member_bit`) in `type_name` to `comment`, a plain member comment \
         (`is_regcmt=false`)."
            udt_set_member_comment(type_name: Str, member_name: Str, member_bit: U64, comment: Str)
                -> Shared("TypeWriteResult");
        "Set the value representation on the member selected by `member_name` (or, when it is \
         empty, by bit offset `member_bit`) in `type_name`. `vtype` is a `value_repr_t` FRB_* \
         value-type nibble; `is_signed`/`leading_zeros` set FRB_SIGNED/FRB_LZERO."
            udt_set_member_repr(type_name: Str, member_name: Str, member_bit: U64, vtype: U32,
                is_signed: Bool, leading_zeros: Bool) -> Shared("TypeWriteResult");
        "Delete the member selected by `member_name` (or, when it is empty, by bit offset \
         `member_bit`) from `type_name`."
            udt_del_member(type_name: Str, member_name: Str, member_bit: U64)
                -> Shared("TypeWriteResult");
        "Add an enum constant named `member_name` with `value` to the named enum `type_name`, in \
         the explicit bitmask group `bmask` (`DEFMASK64` lets a bitmask enum use `value` itself as \
         the group mask; ignored by an ordinary enum), passing `etf_flags` (`etf_flag_t`, e.g. \
         `ETF_FORCENAME`) to `add_edm`. Same `TEDIT_*` codes as the `udt_*` fns."
            enum_add_member(type_name: Str, member_name: Str, value: U64, bmask: U64, etf_flags: U32)
                -> Shared("TypeWriteResult");
        "Set whether the named enum `type_name` is a bitmask (flag) enum \
         (`tinfo_t::set_enum_is_bitmask`). Same `TEDIT_*` codes as the `udt_*`/`enum_*` fns."
            enum_set_bitmask(type_name: Str, on: Bool) -> Shared("TypeWriteResult");
        "Set the value representation on the named enum `type_name` (`tinfo_t::set_enum_repr`), the \
         enum-level twin of [`udt_set_member_repr`]. `vtype` is a `value_repr_t` FRB_* value-type \
         nibble; `is_signed`/`leading_zeros` set FRB_SIGNED/FRB_LZERO."
            enum_set_repr(type_name: Str, vtype: U32, is_signed: Bool, leading_zeros: Bool)
                -> Shared("TypeWriteResult");
        "Set the storage width in bytes of the named enum `type_name`'s underlying type \
         (`tinfo_t::set_enum_width`); `0` means unspecified."
            enum_set_width(type_name: Str, nbytes: I32) -> Shared("TypeWriteResult");
        "Set the value of the enum constant `member_name` in the named enum `type_name`."
            enum_set_member_value(type_name: Str, member_name: Str, value: U64)
                -> Shared("TypeWriteResult");
        "Rename the enum constant `member_name` in the named enum `type_name` to `new_name`, \
         passing `etf_flags` (`etf_flag_t`, e.g. `ETF_FORCENAME`) to `rename_edm`."
            enum_rename_member(type_name: Str, member_name: Str, new_name: Str, etf_flags: U32)
                -> Shared("TypeWriteResult");
        "Delete the enum constant `member_name` from the named enum `type_name`."
            enum_del_member(type_name: Str, member_name: Str) -> Shared("TypeWriteResult");
        "Delete the enum constant carrying `value` from the named enum `type_name` \
         (`tinfo_t::del_edm_by_value`), the value-keyed sibling of [`enum_del_member`]. Uses the \
         default bitmask (`DEFMASK64`) and serial (`0`), so it targets the plain value match, not a \
         specific bitmask group or serial. `TERR_NOT_FOUND` (`TypeEditCode::NotFound`) when no \
         constant carries `value`."
            enum_del_member_by_value(type_name: Str, value: U64) -> Shared("TypeWriteResult");
        "The `void` type as a fresh [`UniquePtr`](cxx::UniquePtr) handle, freed by the cxx deleter \
         (`~tinfo_t`) on drop."
            tinfo_void() -> UniquePtr("TInfo");
        "The boolean type as a fresh [`UniquePtr`](cxx::UniquePtr) handle."
            tinfo_bool() -> UniquePtr("TInfo");
        "A `bytes`-wide integer (1/2/4/8/16), signed when `is_signed`, as a fresh handle; a null \
         handle when the width is unsupported."
            tinfo_int(bytes: U32, is_signed: Bool) -> UniquePtr("TInfo");
        "A `bytes`-wide float (4 or 8) as a fresh handle; a null handle when the width is not 4 or \
         8."
            tinfo_float(bytes: U32) -> UniquePtr("TInfo");
        "The named type `name` as a fresh handle, an unresolved typedef ref. Builds a non-null \
         forward reference even for a name absent from the local til, so the caller checks \
         existence separately."
            tinfo_named(name: Str) -> UniquePtr("TInfo");
        "The type `decl` parses to against the local til, as a fresh handle; `Err` (with the \
         captured parse diagnostic) on a parse failure."
            tinfo_decl(decl: Str) -> ResultUniquePtr("TInfo");
        "A pointer to `inner` as a fresh handle. `inner` is copied, not consumed; a null handle if \
         the pointer type cannot be built."
            tinfo_ptr(inner: ExternRef("TInfo")) -> UniquePtr("TInfo");
        "An `nelems`-element array of `inner` as a fresh handle. `inner` is copied, not consumed; \
         a null handle when `nelems` exceeds `u32` or the array cannot be built."
            tinfo_array(inner: ExternRef("TInfo"), nelems: U64) -> UniquePtr("TInfo");
        "A `const`-qualified copy of `inner` as a fresh handle. `inner` is not consumed."
            tinfo_const(inner: ExternRef("TInfo")) -> UniquePtr("TInfo");
        "A `volatile`-qualified copy of `inner` as a fresh handle. `inner` is not consumed."
            tinfo_volatile(inner: ExternRef("TInfo")) -> UniquePtr("TInfo");
        "Apply the built `handle` at `ea` (`apply_tinfo`, `TINFO_DEFINITE | flags`). `code` is \
         `TYPE_OK`/`_ERR_APPLY`; the handle is not consumed."
            tinfo_apply(ea: U64, handle: ExternRef("TInfo"), flags: I32) -> Shared("TypeWriteResult");
    },
};
