use super::super::model::*;

/// The strings domain: IDA's string list plus per-literal decoding. `strlist_build` runs an
/// O(database) scan to (re)build the list; `strlist_item` returns the nth entry as a `StrlistItem`
/// (throws when out of range). `strlit_contents` decodes one literal semantically (`STRCONV_REPLCHAR`,
/// undecodable units to U+FFFD) and `strlit_escaped` to its display form (`STRCONV_ESCAPE`, C-escaped
/// as in the pseudocode); both throw only when the literal cannot be read. All bodies are
/// hand-written in `facade/strings.cpp`.
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
    consts: &[],
    custom_tus: &["facade/strings.cpp"],
    fns: fns! {
        "(Re)build IDA's string list, an O(database) scan of the whole image."
            strlist_build();
        "Number of entries in the current string list (`get_strlist_qty`)."
            strlist_qty() -> Usize;
        "The `n`-th string-list entry as a `StrlistItem`; `Err` when `n` is out of range."
            strlist_item(n: Usize) -> ResultShared("StrlistItem");
        "Decode the string literal at `ea` (given octet length and `STRTYPE`) semantically \
         (`STRCONV_REPLCHAR`: undecodable units become U+FFFD); `Err` when it cannot be read."
            strlit_contents(ea: U64, len: Usize, strtype: I32) -> ResultString;
        "Decode the string literal at `ea` to its C-escaped display form (`STRCONV_ESCAPE`, as the \
         decompiler renders it); `Err` when it cannot be read."
            strlit_escaped(ea: U64, len: Usize, strtype: I32) -> ResultString;
    },
};
