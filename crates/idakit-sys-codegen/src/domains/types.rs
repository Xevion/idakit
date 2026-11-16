use super::super::model::*;

/// The local-type read domain: render a function's prototype and enumerate the local type library.
///
/// The mirror of the write side (`type_build`); the string bodies are hand-written in
/// `facade/local_types.cpp`, the ordinal-limit passthrough templated.
pub const TY: Domain = Domain {
    name: "ty",
    sdk_includes: &["<typeinf.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    consts: &[],
    custom_tus: &["facade/local_types.cpp"],
    fns: fns! {
        "The prototype of the function at `ea` (one line, `PRTYPE_1LINE`); `Err` when it has no type."
            func_type(ea: U64) -> Result(String);
        "Exclusive upper bound on local-type ordinals: valid ordinals run `1..limit`."
            type_ordinal_limit() -> U32 = scalar("get_ordinal_limit(get_idati())");
        "Name of the local type at `ordinal` (empty for an anonymous type); `Err` when the ordinal \
         holds no type."
            type_name_at(ordinal: U32) -> Result(String);
        "Alignment source: every `TAUDT_*` bit, in `StructAttributes`'s declaration order. Header \
         constants only, no kernel needed."
            struct_attribute_ids() -> Vec(U32);
        "Alignment source: every `TAFLD_*` bit, in `MemberAttributes`'s declaration order."
            member_attribute_ids() -> Vec(U32);
        "Alignment source: every `TAENUM_*` bit, in `EnumAttributes`'s declaration order."
            enum_attribute_ids() -> Vec(U32);
        "Alignment source: the `TAPTR_*` flag bits, in `PointerAttributes`'s declaration order."
            pointer_attribute_ids() -> Vec(U32);
        "Alignment source: the `TAPTR_*` modifier values, in `PointerModifier`'s discriminant \
         order."
            pointer_modifier_ids() -> Vec(U32);
    },
};
