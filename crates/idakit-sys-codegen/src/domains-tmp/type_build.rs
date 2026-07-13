use super::super::model::*;
use super::{EA, INNER};

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
                code: I32 = "Raw facade code: an `IDAKIT_TYPE_*`/`IDAKIT_TEDIT_*` sentinel, a negative \
                          `tinfo_code_t`, or `define_type`'s parse-error count.";
                reason: Str = "Captured IDA diagnostic, empty when the call has no error channel.";
            },
        },
        SharedStruct {
            name: "SigWriteResult",
            doc: "The outcome of a signature-surgery call that also reports the function's \
                  parameter count.",
            fields: fields! {
                code: I32 = "Raw facade `IDAKIT_SIG_*` code.";
                arity: Usize = "Parameter count of the edited function type (`0` when it has no type).";
                reason: Str = "Captured IDA diagnostic, empty when none.";
            },
        },
    ],
    custom_tu: Some("facade/type_build_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "apply_type_decl",
            receiver: None,
            args: args!(ea: U64, decl: Str, flags: I32),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Parse `decl` against the local til and apply it at `ea`. `code` is \
                  `IDAKIT_TYPE_OK`, `_ERR_INPUT` (parse failed), or `_ERR_APPLY`.",
        },
        FnSpec {
            name: "apply_named_type",
            receiver: None,
            args: args!(ea: U64, name: Str),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Resolve the existing named type `name` and apply it at `ea`. `code` \
                  distinguishes not-found (`_ERR_INPUT`) from an apply rejection (`_ERR_APPLY`); \
                  `reason` is empty (no error channel).",
        },
        FnSpec {
            name: "clear_type",
            receiver: None,
            args: EA,
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Clear any type applied at `ea`. Idempotent: `code` is `IDAKIT_TYPE_OK` when \
                  there was nothing to clear; `reason` is empty (no error channel).",
        },
        FnSpec {
            name: "apply_type_recipe",
            receiver: None,
            args: args!(ea: U64, recipe: Bytes, flags: I32),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Build the `tinfo` the postfix recipe encodes and apply it at `ea`. Same codes as \
                  [`apply_type_decl`]; `_ERR_INPUT` is a malformed buffer or an unparseable \
                  embedded decl. An unknown named leaf builds a forward reference that fails later \
                  at apply, not here.",
        },
        FnSpec {
            name: "define_type",
            receiver: None,
            args: args!(input: Str),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Parse the C declaration(s) in `input` into the local til. `code` is the \
                  parse-error count (`0` = ok).",
        },
        FnSpec {
            name: "delete_type",
            receiver: None,
            args: args!(type_name: Str),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Delete the named type `type_name` from the local til, the inverse of \
                  [`define_type`]. See the `IDAKIT_TEDIT_*` codes.",
        },
        FnSpec {
            name: "rename_type",
            receiver: None,
            args: args!(type_name: Str, new_name: Str),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Rename the named type `type_name` to `new_name` in place, preserving its \
                  ordinal. Same `IDAKIT_TEDIT_*` codes as the `udt_*`/`enum_*` fns.",
        },
        FnSpec {
            name: "forward_declare_type",
            receiver: None,
            args: args!(type_name: Str, decl_type: U32),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Reserve `type_name` in the local til as an incomplete aggregate \
                  (`tinfo_t::create_forward_decl`), without a body. `decl_type` is a `type_t` \
                  (`BTF_STRUCT`/`BTF_UNION`/`BTF_ENUM`) selecting the aggregate kind. `code` is the \
                  raw `tinfo_code_t` (`0` = ok); no `IDAKIT_TEDIT_*` pre-failure, since there is no \
                  existing type to load first.",
        },
        FnSpec {
            name: "func_set_rettype",
            receiver: None,
            args: args!(ea: U64, recipe: Bytes),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Replace the return type of the function type at `ea` with the recipe type, then \
                  rebuild and re-apply. See the `IDAKIT_SIG_*` codes.",
        },
        FnSpec {
            name: "func_set_argtype",
            receiver: None,
            args: args!(ea: U64, idx: Usize, recipe: Bytes),
            ret: RetKind::Shared("SigWriteResult"),
            body: BodyKind::Custom,
            doc: "Replace parameter `idx`'s type with the recipe type, then rebuild and re-apply. \
                  `arity` reports the current parameter count; `IDAKIT_SIG_ARG_RANGE` when `idx` \
                  is past it.",
        },
        FnSpec {
            name: "func_rename_arg",
            receiver: None,
            args: args!(ea: U64, idx: Usize, name: Str),
            ret: RetKind::Shared("SigWriteResult"),
            body: BodyKind::Custom,
            doc: "Rename parameter `idx` to `name`, then rebuild and re-apply. `arity` reports the \
                  current parameter count; `IDAKIT_SIG_ARG_RANGE` when `idx` is past it.",
        },
        FnSpec {
            name: "func_set_cc",
            receiver: None,
            args: args!(ea: U64, cc: I32),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Set the calling convention of the function type at `ea` to the raw `CM_CC_*` \
                  code `cc`, then rebuild and re-apply.",
        },
        FnSpec {
            name: "func_prepend_this",
            receiver: None,
            args: args!(ea: U64, recipe: Bytes),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Insert an implicit `this` parameter of the recipe type at index 0, then rebuild \
                  and re-apply.",
        },
        FnSpec {
            name: "udt_add_member",
            receiver: None,
            args: args!(type_name: Str, member_name: Str, recipe: Bytes, member_bit: U64),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Add a member of the recipe type to the named struct/union `type_name` at bit \
                  offset `member_bit` (or appended when it is `IDAKIT_MEMBER_APPEND`). An empty \
                  `member_name` adds an anonymous member. See the `IDAKIT_TEDIT_*` codes.",
        },
        FnSpec {
            name: "udt_set_member_type",
            receiver: None,
            args: args!(type_name: Str, member_name: Str, member_bit: U64, recipe: Bytes, etf_flags: U32),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Replace the type of the member selected by `member_name` (or, when it is empty, \
                  by bit offset `member_bit`) in `type_name` with the recipe type, passing \
                  `etf_flags` (`etf_flag_t`, e.g. `ETF_COMPATIBLE`) to `set_udm_type`.",
        },
        FnSpec {
            name: "udt_rename_member",
            receiver: None,
            args: args!(type_name: Str, member_name: Str, member_bit: U64, new_name: Str),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Rename the member selected by `member_name` (or, when it is empty, by bit offset \
                  `member_bit`) in `type_name` to `new_name`.",
        },
        FnSpec {
            name: "udt_set_member_comment",
            receiver: None,
            args: args!(type_name: Str, member_name: Str, member_bit: U64, comment: Str),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Set the comment on the member selected by `member_name` (or, when it is empty, \
                  by bit offset `member_bit`) in `type_name` to `comment`, a plain member comment \
                  (`is_regcmt=false`).",
        },
        FnSpec {
            name: "udt_set_member_repr",
            receiver: None,
            args: args!(type_name: Str, member_name: Str, member_bit: U64, vtype: U32, is_signed: Bool, leading_zeros: Bool),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Set the value representation on the member selected by `member_name` (or, when \
                  it is empty, by bit offset `member_bit`) in `type_name`. `vtype` is a \
                  `value_repr_t` FRB_* value-type nibble; `is_signed`/`leading_zeros` set \
                  FRB_SIGNED/FRB_LZERO.",
        },
        FnSpec {
            name: "udt_del_member",
            receiver: None,
            args: args!(type_name: Str, member_name: Str, member_bit: U64),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Delete the member selected by `member_name` (or, when it is empty, by bit offset \
                  `member_bit`) from `type_name`.",
        },
        FnSpec {
            name: "enum_add_member",
            receiver: None,
            args: args!(type_name: Str, member_name: Str, value: U64, bmask: U64, etf_flags: U32),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Add an enum constant named `member_name` with `value` to the named enum \
                  `type_name`, in the explicit bitmask group `bmask` (`DEFMASK64` lets a bitmask \
                  enum use `value` itself as the group mask; ignored by an ordinary enum), passing \
                  `etf_flags` (`etf_flag_t`, e.g. `ETF_FORCENAME`) to `add_edm`. Same \
                  `IDAKIT_TEDIT_*` codes as the `udt_*` fns.",
        },
        FnSpec {
            name: "enum_set_bitmask",
            receiver: None,
            args: args!(type_name: Str, on: Bool),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Set whether the named enum `type_name` is a bitmask (flag) enum \
                  (`tinfo_t::set_enum_is_bitmask`). Same `IDAKIT_TEDIT_*` codes as the \
                  `udt_*`/`enum_*` fns.",
        },
        FnSpec {
            name: "enum_set_repr",
            receiver: None,
            args: args!(type_name: Str, vtype: U32, is_signed: Bool, leading_zeros: Bool),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Set the value representation on the named enum `type_name` \
                  (`tinfo_t::set_enum_repr`), the enum-level twin of \
                  [`udt_set_member_repr`]. `vtype` is a `value_repr_t` FRB_* value-type nibble; \
                  `is_signed`/`leading_zeros` set FRB_SIGNED/FRB_LZERO.",
        },
        FnSpec {
            name: "enum_set_width",
            receiver: None,
            args: args!(type_name: Str, nbytes: I32),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Set the storage width in bytes of the named enum `type_name`'s underlying type \
                  (`tinfo_t::set_enum_width`); `0` means unspecified.",
        },
        FnSpec {
            name: "enum_set_member_value",
            receiver: None,
            args: args!(type_name: Str, member_name: Str, value: U64),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Set the value of the enum constant `member_name` in the named enum `type_name`.",
        },
        FnSpec {
            name: "enum_rename_member",
            receiver: None,
            args: args!(type_name: Str, member_name: Str, new_name: Str, etf_flags: U32),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Rename the enum constant `member_name` in the named enum `type_name` to \
                  `new_name`, passing `etf_flags` (`etf_flag_t`, e.g. `ETF_FORCENAME`) to \
                  `rename_edm`.",
        },
        FnSpec {
            name: "enum_del_member",
            receiver: None,
            args: args!(type_name: Str, member_name: Str),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Delete the enum constant `member_name` from the named enum `type_name`.",
        },
        FnSpec {
            name: "enum_del_member_by_value",
            receiver: None,
            args: args!(type_name: Str, value: U64),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Delete the enum constant carrying `value` from the named enum `type_name` \
                  (`tinfo_t::del_edm_by_value`), the value-keyed sibling of [`enum_del_member`]. \
                  Uses the default bitmask (`DEFMASK64`) and serial (`0`), so it targets the plain \
                  value match, not a specific bitmask group or serial. `TERR_NOT_FOUND` \
                  (`TypeEditCode::NotFound`) when no constant carries `value`.",
        },
        FnSpec {
            name: "tinfo_void",
            receiver: None,
            args: &[],
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "The `void` type as a fresh [`UniquePtr`](cxx::UniquePtr) handle, freed by the \
                  cxx deleter (`~tinfo_t`) on drop.",
        },
        FnSpec {
            name: "tinfo_bool",
            receiver: None,
            args: &[],
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "The boolean type as a fresh [`UniquePtr`](cxx::UniquePtr) handle.",
        },
        FnSpec {
            name: "tinfo_int",
            receiver: None,
            args: args!(bytes: U32, is_signed: Bool),
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "A `bytes`-wide integer (1/2/4/8/16), signed when `is_signed`, as a fresh handle; \
                  a null handle when the width is unsupported.",
        },
        FnSpec {
            name: "tinfo_float",
            receiver: None,
            args: args!(bytes: U32),
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "A `bytes`-wide float (4 or 8) as a fresh handle; a null handle when the width is \
                  not 4 or 8.",
        },
        FnSpec {
            name: "tinfo_named",
            receiver: None,
            args: args!(name: Str),
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "The named type `name` as a fresh handle, an unresolved typedef ref. Builds a \
                  non-null forward reference even for a name absent from the local til, so the \
                  caller checks existence separately.",
        },
        FnSpec {
            name: "tinfo_decl",
            receiver: None,
            args: args!(decl: Str),
            ret: RetKind::ResultUniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "The type `decl` parses to against the local til, as a fresh handle; `Err` (with \
                  the captured parse diagnostic) on a parse failure.",
        },
        FnSpec {
            name: "tinfo_ptr",
            receiver: None,
            args: INNER,
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "A pointer to `inner` as a fresh handle. `inner` is copied, not consumed; a null \
                  handle if the pointer type cannot be built.",
        },
        FnSpec {
            name: "tinfo_array",
            receiver: None,
            args: args!(inner: ExternRef("TInfo"), nelems: U64),
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "An `nelems`-element array of `inner` as a fresh handle. `inner` is copied, not \
                  consumed; a null handle when `nelems` exceeds `u32` or the array cannot be built.",
        },
        FnSpec {
            name: "tinfo_const",
            receiver: None,
            args: INNER,
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "A `const`-qualified copy of `inner` as a fresh handle. `inner` is not consumed.",
        },
        FnSpec {
            name: "tinfo_volatile",
            receiver: None,
            args: INNER,
            ret: RetKind::UniquePtr("TInfo"),
            body: BodyKind::Custom,
            doc: "A `volatile`-qualified copy of `inner` as a fresh handle. `inner` is not \
                  consumed.",
        },
        FnSpec {
            name: "tinfo_apply",
            receiver: None,
            args: args!(ea: U64, handle: ExternRef("TInfo"), flags: I32),
            ret: RetKind::Shared("TypeWriteResult"),
            body: BodyKind::Custom,
            doc: "Apply the built `handle` at `ea` (`apply_tinfo`, `TINFO_DEFINITE | flags`). \
                  `code` is `IDAKIT_TYPE_OK`/`_ERR_APPLY`; the handle is not consumed.",
        },
    ],
};
