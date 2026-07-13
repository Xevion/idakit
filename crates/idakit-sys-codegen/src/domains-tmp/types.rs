use super::super::model::*;
use super::EA;

/// The local-type read domain: render a function's prototype and enumerate the local type library.
///
/// The mirror of the write side (`type_build`); the string bodies are hand-written in
/// `facade/ty_custom.cc`, the ordinal-limit passthrough templated.
pub const TY: Domain = Domain {
    name: "ty",
    sdk_includes: &["<typeinf.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    custom_tu: Some("facade/ty_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "func_type",
            receiver: None,
            args: EA,
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "The prototype of the function at `ea` (one line, `PRTYPE_1LINE`); `Err` when it \
                  has no type.",
        },
        FnSpec {
            name: "type_ordinal_limit",
            receiver: None,
            args: &[],
            ret: RetKind::U32,
            body: BodyKind::ScalarCall {
                call: "get_ordinal_limit(get_idati())",
            },
            doc: "Exclusive upper bound on local-type ordinals: valid ordinals run `1..limit`.",
        },
        FnSpec {
            name: "type_name_at",
            receiver: None,
            args: args!(ordinal: U32),
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Name of the local type at `ordinal` (empty for an anonymous type); `Err` when \
                  the ordinal holds no type.",
        },
    ],
};
