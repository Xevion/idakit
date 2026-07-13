use super::super::model::*;
use super::{EA, FLAGS, IDX};

/// The name domain: name lookups (address<->name, demangle), the name-list accessors, and the
/// three flags-word name classifiers. Every body is hand-written in `facade/name_custom.cc` (the
/// getters throw on no-name, and SDK calls are `::`-qualified to avoid recursing on the shared
/// symbol spellings).
pub const NAME: Domain = Domain {
    name: "name",
    sdk_includes: &["<name.hpp>", "<bytes.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    custom_tu: Some("facade/name_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "get_ea_name",
            receiver: None,
            args: EA,
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Name at address `ea`; `Err` when the address has none.",
        },
        FnSpec {
            name: "get_name_ea",
            receiver: None,
            args: args!(name: Str),
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Address the symbol `name` resolves to, or `BADADDR` when it is unknown.",
        },
        FnSpec {
            name: "demangle_name",
            receiver: None,
            args: args!(name: Str),
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Fully demangled form of `name`; `Err` when `name` is not mangled.",
        },
        FnSpec {
            name: "nlist_size",
            receiver: None,
            args: &[],
            ret: RetKind::Usize,
            body: BodyKind::Custom,
            doc: "Number of entries in the sorted name list (`get_nlist_size`).",
        },
        FnSpec {
            name: "nlist_ea",
            receiver: None,
            args: IDX,
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Address of name-list entry `idx`.",
        },
        FnSpec {
            name: "nlist_name",
            receiver: None,
            args: IDX,
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Name of name-list entry `idx`; `Err` when `idx` is out of range.",
        },
        FnSpec {
            name: "has_user_name",
            receiver: None,
            args: FLAGS,
            ret: RetKind::Bool,
            body: BodyKind::Custom,
            doc: "Whether a flags word marks a user-given (explicit) name.",
        },
        FnSpec {
            name: "has_auto_name",
            receiver: None,
            args: FLAGS,
            ret: RetKind::Bool,
            body: BodyKind::Custom,
            doc: "Whether a flags word marks an IDA-generated (auto) name.",
        },
        FnSpec {
            name: "has_dummy_name",
            receiver: None,
            args: FLAGS,
            ret: RetKind::Bool,
            body: BodyKind::Custom,
            doc: "Whether a flags word marks a dummy (address-derived) name.",
        },
    ],
};
