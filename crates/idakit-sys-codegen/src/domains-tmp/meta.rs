use super::super::model::*;

/// The meta domain: database-wide metadata (bitness, image base) and four identity strings
/// (processor, file-type text, input path, root filename). All bodies are hand-written in
/// `facade/meta_custom.cc`; the string getters throw when the SDK has no value.
pub const META: Domain = Domain {
    name: "meta",
    sdk_includes: &["<nalt.hpp>", "<loader.hpp>", "<stdexcept>"],
    externs: &[],
    structs: &[],
    custom_tu: Some("facade/meta_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "bitness",
            receiver: None,
            args: &[],
            ret: RetKind::I32,
            body: BodyKind::Custom,
            doc: "Application bitness (`inf_get_app_bitness`): 16, 32, or 64.",
        },
        FnSpec {
            name: "image_base",
            receiver: None,
            args: &[],
            ret: RetKind::U64,
            body: BodyKind::Custom,
            doc: "Preferred load address of the input (`get_imagebase`).",
        },
        FnSpec {
            name: "proc_name",
            receiver: None,
            args: &[],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Processor module id, e.g. `metapc`; `Err` when none is set.",
        },
        FnSpec {
            name: "file_type_name",
            receiver: None,
            args: &[],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Human-readable input file format text; `Err` when unavailable.",
        },
        FnSpec {
            name: "input_path",
            receiver: None,
            args: &[],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Full path of the analyzed input; `Err` when unknown.",
        },
        FnSpec {
            name: "root_filename",
            receiver: None,
            args: &[],
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Base filename of the input; `Err` when unknown.",
        },
    ],
};
