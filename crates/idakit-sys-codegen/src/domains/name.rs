use super::super::model::*;

/// The name domain: name lookups (address<->name, demangle), the name-list accessors, and the
/// three flags-word name classifiers. Every body is hand-written in `facade/name.cpp` (the
/// getters throw on no-name, and SDK calls are `::`-qualified to avoid recursing on the shared
/// symbol spellings).
pub const NAME: Domain = Domain {
    name: "name",
    sdk_includes: &["<name.hpp>", "<bytes.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    consts: &[],
    custom_tus: &["facade/name.cpp"],
    fns: fns! {
        "Name at address `ea`; `Err` when the address has none."
            get_ea_name(ea: U64) -> ResultString;
        "Address the symbol `name` resolves to, or `BADADDR` when it is unknown."
            get_name_ea(name: Str) -> U64;
        "Fully demangled form of `name`; `Err` when `name` is not mangled."
            demangle_name(name: Str) -> ResultString;
        "Number of entries in the sorted name list (`get_nlist_size`)."
            nlist_size() -> Usize;
        "Address of name-list entry `idx`."
            nlist_ea(idx: Usize) -> U64;
        "Name of name-list entry `idx`; `Err` when `idx` is out of range."
            nlist_name(idx: Usize) -> ResultString;
        "Whether a flags word marks a user-given (explicit) name."
            has_user_name(flags: U64) -> Bool;
        "Whether a flags word marks an IDA-generated (auto) name."
            has_auto_name(flags: U64) -> Bool;
        "Whether a flags word marks a dummy (address-derived) name."
            has_dummy_name(flags: U64) -> Bool;
    },
};
