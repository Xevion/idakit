use super::super::model::*;

/// The import-table domain: the whole table returned as one owned `Vec<ImportRec>` snapshot,
/// retiring the raw handle/index/free dance. The single body is hand-written in
/// `facade/import_custom.cc` (a callback walk over every module's `enum_import_names`).
pub const IMPORT: Domain = Domain {
    name: "import",
    sdk_includes: &["<nalt.hpp>"],
    externs: &[],
    structs: &[SharedStruct {
        name: "ImportRec",
        doc: "One import-table row, returned inside the [`imports_build`] snapshot.",
        fields: fields! {
            ea: U64 = "Address the import is bound to.";
            ord: U64 = "Ordinal, or `0` when imported by name.";
            name: Str = "Symbol name, empty when imported by ordinal.";
            module: Str = "Owning module (library) name.";
        },
    }],
    custom_tu: Some("facade/import_custom.cc"),
    body_helpers: None,
    fns: fns! {
        "The whole import table as an owned, `Send` snapshot, built in one walk of every module's \
         `enum_import_names`."
            imports_build() -> Vec("ImportRec");
    },
};
