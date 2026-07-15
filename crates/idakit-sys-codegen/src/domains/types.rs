use super::super::model::*;

/// The local-type read domain: render a function's prototype and enumerate the local type library.
///
/// The mirror of the write side (`type_build`); the string bodies are hand-written in
/// `facade/ty_custom.cc`, the ordinal-limit passthrough templated.
pub const TY: Domain = Domain {
    name: "ty",
    sdk_includes: &["<typeinf.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    consts: &[],
    custom_tu: Some("facade/ty_custom.cc"),
    fns: fns! {
        "The prototype of the function at `ea` (one line, `PRTYPE_1LINE`); `Err` when it has no type."
            func_type(ea: U64) -> ResultString;
        "Exclusive upper bound on local-type ordinals: valid ordinals run `1..limit`."
            type_ordinal_limit() -> U32 = scalar("get_ordinal_limit(get_idati())");
        "Name of the local type at `ordinal` (empty for an anonymous type); `Err` when the ordinal \
         holds no type."
            type_name_at(ordinal: U32) -> ResultString;
    },
};
