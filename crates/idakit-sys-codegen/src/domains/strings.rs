use super::super::model::*;

/// The strings domain: IDA's string list plus per-literal decoding. `strlist_build` runs an
/// O(database) scan to (re)build the list; `strlist_item` returns the nth entry as a `StrlistItem`
/// (throws when out of range), and `strlit_contents` decodes one literal to UTF-8 (throws when
/// undecodable). All bodies are hand-written in `facade/strings_custom.cc`.
pub const STRINGS: Domain = Domain {
    name: "strings",
    sdk_includes: &["<strlist.hpp>", "<bytes.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[SharedStruct {
        name: "StrlistItem",
        doc: "One string-list entry: its address, octet length, and `STRTYPE` code.",
        fields: fields! {
            ea: U64 = "Address of the string literal.";
            length: I32 = "Length in octets (raw bytes, not decoded characters).";
            type_: I32 = "`STRTYPE` code describing the encoding.";
        },
    }],
    custom_tu: Some("facade/strings_custom.cc"),
    body_helpers: None,
    fns: fns! {
        "(Re)build IDA's string list, an O(database) scan of the whole image."
            strlist_build();
        "Number of entries in the current string list (`get_strlist_qty`)."
            strlist_qty() -> Usize;
        "The `n`-th string-list entry as a `StrlistItem`; `Err` when `n` is out of range."
            strlist_item(n: Usize) -> ResultShared("StrlistItem");
        "Decode the string literal at `ea` (given octet length and `STRTYPE`) to UTF-8; `Err` when \
         it cannot be decoded."
            strlit_contents(ea: U64, len: Usize, strtype: I32) -> ResultString;
    },
};
