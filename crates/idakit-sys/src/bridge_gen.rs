//! The spec-generated `cxx` bridge (`idakit_gen`), covering every folded facade domain.
//!
//! Nothing here is authored by hand: build.rs turns `build_support/gen.rs`'s declarative `DOMAINS`
//! into one `#[cxx::bridge] mod`, writes it to `$OUT_DIR/gen_bridge.rs`, and this `include!`s it so
//! the proc-macro expands it as ordinary source. The same tokens drive the C++ side through
//! `cxx-gen`; the function bodies are hand-written per domain (templated only for segment's trivial
//! scalar/string shapes). Items re-export flat at the crate root per convention.

include!(concat!(env!("OUT_DIR"), "/gen_bridge.rs"));

pub use ffi::{
    ChunkInfo, ImportRec, StrlistItem, bitness, demangle_name, export_ea, export_forwarder,
    export_name, export_ordinal, export_qty, file_type_name, func_chunk_qty, func_ea, func_end,
    func_flags, func_name, func_qty, func_start, gen_seg_bitness, gen_seg_class, gen_seg_end,
    gen_seg_name, gen_seg_perm, gen_seg_qty, gen_seg_span_total, gen_seg_start, get_ea_name,
    get_name_ea, has_auto_name, has_dummy_name, has_user_name, image_base, imports_build,
    input_path, nlist_ea, nlist_name, nlist_size, proc_name, range_all_chunks, range_chunk_info,
    range_entry_chunk, range_size, root_filename, strlist_build, strlist_item, strlist_qty,
    strlit_contents,
};
// RangeT is a module-level `pub` type (from the generated ExternType impl, outside `mod ffi`), so
// it re-exports through the crate-root glob without an explicit `pub use` here.
