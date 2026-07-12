//! The spec-generated `cxx` bridge (`idakit_gen`), covering every folded facade domain.
//!
//! Nothing here is authored by hand: build.rs turns `build_support/gen.rs`'s declarative `DOMAINS`
//! into one `#[cxx::bridge] mod`, writes it to `$OUT_DIR/gen_bridge.rs`, and this `include!`s it so
//! the proc-macro expands it as ordinary source. The same tokens drive the C++ side through
//! `cxx-gen`; the function bodies are hand-written per domain (templated only for segment's trivial
//! scalar/string shapes). Items re-export flat at the crate root per convention.

include!(concat!(env!("OUT_DIR"), "/gen_bridge.rs"));

pub use ffi::{
    BinpatStats, BlockInfo, ChunkInfo, CtreeCounts, ExprGap, ImportRec, InstructionData,
    OperandData, RegisterData, SigWriteResult, StrlistItem, TypeWriteResult, XrefRec,
    apply_named_type, apply_type_decl, apply_type_recipe, bin_search, binpat_compile,
    binpat_from_bytes, binpat_stats, bitness, cfg_block, cfg_build, cfg_nblocks, cfg_npred,
    cfg_nproper, cfg_nsucc, cfg_pred, cfg_preds, cfg_succ, cfg_succs, cfunc_counts, cfunc_expr_gap,
    cfunc_pseudocode, cfunc_refresh_text, clear_type, decode_insn, decompile, define_type,
    delete_type, demangle_name, enum_add_member, enum_del_member, enum_del_member_by_value,
    enum_rename_member, enum_set_bitmask, enum_set_member_value, enum_set_repr, enum_set_width,
    export_ea, export_forwarder, export_name, export_ordinal, export_qty, file_type_name,
    forward_declare_type, func_chunk_qty, func_ea, func_end, func_flags, func_name,
    func_prepend_this, func_qty, func_rename_arg, func_set_argtype, func_set_cc, func_set_rettype,
    func_start, func_type, gen_seg_bitness, gen_seg_class, gen_seg_end, gen_seg_name, gen_seg_perm,
    gen_seg_qty, gen_seg_span_total, gen_seg_start, get_bytes, get_cmt, get_ea_name, get_flags,
    get_item_end, get_item_head, get_name_ea, get_next_head, get_prev_head, get_strlit, get_u8,
    get_u16, get_u32, get_u64, has_auto_name, has_dummy_name, has_user_name, image_base,
    imports_build, input_path, max_ea, min_ea, netnode_altdel, netnode_altfirst, netnode_altlast,
    netnode_altnext, netnode_altprev, netnode_altset, netnode_altval, netnode_blobsize,
    netnode_by_name, netnode_chardel, netnode_charset, netnode_charval, netnode_copyto,
    netnode_del_value, netnode_delblob, netnode_exists, netnode_exists_name, netnode_first,
    netnode_get_name, netnode_getblob, netnode_hashdel, netnode_hashfirst, netnode_hashlast,
    netnode_hashnext, netnode_hashprev, netnode_hashset, netnode_hashset_long, netnode_hashstr,
    netnode_hashval, netnode_hashval_long, netnode_kill, netnode_last, netnode_lower_bound,
    netnode_next, netnode_prev, netnode_rename, netnode_set_value, netnode_setblob, netnode_supdel,
    netnode_supfirst, netnode_suplast, netnode_supnext, netnode_supprev, netnode_supset,
    netnode_supstr, netnode_supval, netnode_value, netnode_value_str, nlist_ea, nlist_name,
    nlist_size, op_dtype_ids, patch_bytes, proc_name, range_all_chunks, range_chunk_info,
    range_entry_chunk, range_size, reg_class_ids, rename_type, root_filename, strlist_build,
    strlist_item, strlist_qty, strlit_contents, tinfo_apply, tinfo_array, tinfo_bool, tinfo_const,
    tinfo_decl, tinfo_float, tinfo_int, tinfo_named, tinfo_ptr, tinfo_void, tinfo_volatile,
    type_name_at, type_ordinal_limit, udt_add_member, udt_del_member, udt_rename_member,
    udt_set_member_comment, udt_set_member_repr, udt_set_member_type, xrefs_build,
};
// RangeT, FlowChart, CFunc, CompiledBinpat, and TInfo are module-level `pub` types (from the
// generated ExternType impls, outside `mod ffi`), so they re-export through the crate-root glob
// without an explicit `pub use` here. `size` is a `self:`-member method on `FlowChart`, reached as
// `fc.size()`, not a free function.
