use super::super::model::*;

/// The meta domain: database-wide metadata (bitness, image base) and four identity strings
/// (processor, file-type text, input path, root filename). All bodies are hand-written in
/// `facade/meta.cpp`; the string getters throw when the SDK has no value.
pub const META: Domain = Domain {
    name: "meta",
    sdk_includes: &["<nalt.hpp>", "<loader.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    consts: &[],
    custom_tus: &["facade/meta.cpp"],
    fns: fns! {
        "Application bitness (`inf_get_app_bitness`): 16, 32, or 64."
            bitness() -> I32;
        "Preferred load address of the input (`get_imagebase`)."
            image_base() -> U64;
        "Processor module id, e.g. `metapc`; `Err` when none is set."
            proc_name() -> ResultString;
        "Human-readable input file format text; `Err` when unavailable."
            file_type_name() -> ResultString;
        "Full path of the analyzed input; `Err` when unknown."
            input_path() -> ResultString;
        "Base filename of the input; `Err` when unknown."
            root_filename() -> ResultString;
    },
};
