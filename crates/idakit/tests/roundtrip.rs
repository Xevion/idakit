//! End-to-end cycle against a real database: open, read, write, re-read.
//!
//! A normal `#[test]`: the kernel runs on the thread `Ida::run` spawns (8 MiB stack), so no
//! `harness = false`. The nextest `serial-kernel` group serializes it against the other
//! kernel tests. Runs against the corpus manifest's canonical fixture (see
//! [`common::TestDb`]); skips when no corpus is configured.

mod common;

use assert2::assert;
use idakit::prelude::*;

#[test]
fn roundtrip() {
    common::with_canonical_db(run);
}

fn run(idb: &mut idakit::Database) {
    let func_count = idb.functions().count();
    let seg_count = idb.segments().count();
    assert!(func_count > 0, "expected at least one function");
    assert!(seg_count > 0, "expected at least one segment");

    // Segment domain: idakit's `Segment` view rides the generated seg bridge, so the generated qty
    // must equal the iterator's count, and the `Custom` escape-hatch body (`gen_seg_span_total`,
    // hand-written in facade/gen_custom.cc) must equal the byte span summed over the same iterator.
    {
        use idakit_sys as sys;

        assert_eq!(
            sys::gen_seg_qty(),
            seg_count,
            "generated gen_seg_qty disagrees with the Segments iterator"
        );
        let span_total: u64 = idb
            .segments()
            .map(|s| s.end().map_or(0, u64::from) - s.start().map_or(0, u64::from))
            .sum();
        assert_eq!(
            sys::gen_seg_span_total(),
            span_total,
            "generated custom gen_seg_span_total disagrees with the summed segment spans"
        );
        println!("cxx segment bridge OK: {seg_count} segments, span total agrees");
    }

    // Function domain: idakit's `Function` view rides the generated func bridge. The generated qty
    // must equal the iterator's count, and `func_start` of any entry is that entry.
    {
        use idakit_sys as sys;

        assert_eq!(
            sys::func_qty(),
            func_count,
            "generated func_qty disagrees with the Functions iterator"
        );
        for func in idb.functions() {
            let ea = func.address().get();
            assert_eq!(
                sys::func_start(ea),
                ea,
                "func_start of an entry should be the entry at {ea:#x}"
            );
            assert!(
                sys::func_end(ea) > ea,
                "func_end should be past the entry at {ea:#x}"
            );
            let _ = sys::func_name(ea);
            let _ = sys::func_flags(ea);
        }
        println!("cxx function bridge OK: {func_count} functions");
    }

    // Export domain: idakit's `Exports` iterator rides the generated export bridge, so the generated
    // qty must equal its count; every generated accessor is exercised per entry.
    {
        use idakit_sys as sys;

        assert_eq!(
            sys::export_qty(),
            idb.exports().count(),
            "generated export_qty disagrees with the Exports iterator"
        );
        for e in idb.exports() {
            let _ = (e.address(), e.ordinal(), e.name(), e.forwarder());
        }
        println!("cxx export bridge OK: {} exports", idb.exports().count());
    }

    // Import domain: idakit's `Imports` iterator materializes the generated import snapshot, dropping
    // slots with no usable address, so its count never exceeds the snapshot's row count.
    {
        use idakit_sys as sys;

        let snapshot = sys::imports_build();
        let live = idb.imports().count();
        assert!(
            live <= snapshot.len(),
            "Imports iterator yields more than the import snapshot has rows"
        );
        println!(
            "cxx import bridge OK: {live} imports of {} snapshot rows",
            snapshot.len()
        );
    }

    // Name domain: idakit's `Names` iterator rides the generated nlist bridge (its count never
    // exceeds `nlist_size`, since a `BADADDR` slot is skipped). The generated name accessors and the
    // `has_*_name` predicates (fed each function's flags word) are exercised for consistency: a user
    // name and a dummy name are mutually exclusive by construction.
    {
        use idakit_sys as sys;

        assert!(
            idb.names().count() <= sys::nlist_size(),
            "Names iterator yields more than nlist_size entries"
        );
        for func in idb.functions() {
            let ea = func.address().get();
            let flags = sys::get_flags(ea);
            let (user, dummy) = (sys::has_user_name(flags), sys::has_dummy_name(flags));
            let _ = sys::has_auto_name(flags);
            assert!(
                !(user && dummy),
                "a name cannot be both user-given and dummy at {ea:#x}"
            );
            if let Ok(name) = sys::get_ea_name(ea) {
                let _ = sys::get_name_ea(&name);
                let _ = sys::demangle_name(&name);
            }
        }
        println!("cxx name bridge OK");
    }

    // Meta domain: database-wide metadata through the generated bridge (idakit's meta accessors ride
    // these). Sanity-check the scalars and confirm the string getters resolve.
    {
        use idakit_sys as sys;

        assert!(sys::bitness() > 0, "bitness should be positive");
        assert!(
            sys::proc_name().is_ok_and(|s| !s.is_empty()),
            "a real database names its processor"
        );
        let _ = sys::image_base();
        let _ = sys::file_type_name();
        let _ = sys::input_path();
        let _ = sys::root_filename();
        println!("cxx meta bridge OK: proc={:?}", sys::proc_name().ok());
    }

    // Strings domain: IDA's string list built and walked through the generated bridge. Capped at the
    // first 200 entries so a corpus with a huge string list stays cheap; the walk is uniform per
    // entry, so the cap costs no coverage.
    {
        use idakit_sys as sys;

        sys::strlist_build();
        let qty = sys::strlist_qty().min(200);
        for n in 0..qty {
            let item = sys::strlist_item(n).expect("strlist_item within range");
            let _ = sys::strlit_contents(item.ea, item.length as usize, item.type_);
        }
        assert!(
            sys::strlist_item(sys::strlist_qty()).is_err(),
            "strlist_item should Err past the end"
        );
        println!("cxx strings bridge OK: {qty} string-list entries walked");
    }

    let first = idb.functions().next().expect("a function");
    let address = first.address();
    let original = first.name();
    assert!(!original.is_empty());

    let bytes = idb.bytes(address, 16);
    assert!(!bytes.is_empty(), "expected readable bytes at the entry");

    // cxx opaque-handle bridge: the cxx `FlowChart` path (opaque type owned by UniquePtr, BlockInfo
    // shared struct, Result-shaped bounds) walked through the generated bridge. The per-index
    // accessors are cross-checked against the whole-edge-list copy and the Opaque intvec_t
    // container, the sibling cfg2 bridge, and the `self:`-member `size()`. The
    // `UniquePtr<FlowChart>` frees the qflow_chart_t via cxx's generated deleter glue on drop.
    {
        use idakit_sys as sys;

        let ea = address.get();
        let flags = 0i32;

        let fc = sys::cfg_build(ea, flags).expect("cxx cfg_build on the first function");
        let n = sys::cfg_nblocks(&fc);

        for b in 0..n {
            let info = sys::cfg_block(&fc, b).expect("cxx cfg_block in range");
            assert!(info.end >= info.start, "block {b} end precedes its start");

            let ns = sys::cfg_nsucc(&fc, b);
            let np = sys::cfg_npred(&fc, b);

            // qvector<scalar> -> Vec<u32>: the whole-edge-list cxx path (one copy) must equal the
            // per-index accessors it retires, element for element.
            let succs = sys::cfg_succs(&fc, b).expect("cxx cfg_succs in range");
            assert_eq!(succs.len(), ns, "cfg_succs length disagrees at block {b}");
            for (i, s) in succs.iter().enumerate() {
                assert_eq!(
                    *s as usize,
                    sys::cfg_succ(&fc, b, i).unwrap(),
                    "cfg_succs[{i}] disagrees at block {b}"
                );
            }
            let preds = sys::cfg_preds(&fc, b).expect("cxx cfg_preds in range");
            assert_eq!(preds.len(), np, "cfg_preds length disagrees at block {b}");
            for (i, p) in preds.iter().enumerate() {
                assert_eq!(
                    *p as usize,
                    sys::cfg_pred(&fc, b, i).unwrap(),
                    "cfg_preds[{i}] disagrees at block {b}"
                );
            }

            // Goal A (qvector<int>): the block's successor intvec_t bound as an Opaque cxx
            // container, borrowed out of the live flow chart. Read it BOTH ways (a copying shim to
            // Vec<i32>, and a zero-copy &[i32] borrowed from the container's {array, n}) and cross-
            // check both against the cfg_succs copy and per-index cfg_succ paths.
            let sv = sys::cfg_succ_vec(&fc, b).expect("cxx cfg_succ_vec in range");
            assert_eq!(sys::intvec_len(sv), ns, "intvec_len disagrees at block {b}");
            let copied = sys::intvec_copy(sv);
            let slice = sys::intvec_slice(sv);
            assert_eq!(copied.len(), ns, "intvec_copy len disagrees at block {b}");
            assert_eq!(slice.len(), ns, "intvec_slice len disagrees at block {b}");
            for (i, (c, s)) in copied.iter().zip(slice).enumerate() {
                assert_eq!(
                    *c, *s,
                    "intvec copy vs slice disagree at block {b} elem {i}"
                );
                assert_eq!(
                    *s as usize,
                    sys::cfg_succ(&fc, b, i).unwrap(),
                    "intvec_slice vs cfg_succ disagree at block {b} elem {i}"
                );
                assert_eq!(
                    *s as u32, succs[i],
                    "intvec_slice vs cfg_succs disagree at block {b} elem {i}"
                );
            }
        }

        // Out-of-range bounds surface as `Err` on the cxx path.
        assert!(
            sys::cfg_block(&fc, n).is_err(),
            "cxx cfg_block should Err past the last block"
        );
        assert!(
            sys::cfg_succs(&fc, n).is_err(),
            "cxx cfg_succs should Err past the last block"
        );
        assert!(
            sys::cfg_succ_vec(&fc, n).is_err(),
            "cxx cfg_succ_vec should Err past the last block"
        );

        // Proper (reachable) blocks never exceed the total.
        assert!(
            sys::cfg_nproper(&fc) <= n,
            "cfg_nproper exceeds the total block count"
        );

        // Goal C: a `self:`-receiver method binds to a real C++ *member* (`qflow_chart_t::size`);
        // a free function (`cfg_nblocks`) binds to a namespaced free function. Both count blocks,
        // so they must agree, proving the two accessor shapes map to the two C++ call forms.
        assert_eq!(
            fc.size() as usize,
            n,
            "member-fn size() disagrees with free-fn cfg_nblocks()"
        );

        // Goal B: the sibling `bridge_cfg2` bridge accepts the *same* `&FlowChart` built here (one
        // shared ExternType across two bridges) and sums every block's successor count. Cross-
        // check it against the per-block `cfg_nsucc` totals from this bridge.
        let edge_total: usize = (0..n).map(|b| sys::cfg_nsucc(&fc, b)).sum();
        assert_eq!(
            sys::cfg2_total_edges(&fc),
            edge_total,
            "cross-bridge cfg2_total_edges disagrees with summed cfg_nsucc"
        );

        // `fc` drops here: cxx's UniquePtr glue runs qflow_chart_t's destructor, no manual free.
        println!("cxx cfg bridge cross-check OK: {n} blocks");
    }

    // cxx nested-struct bridge: the generated `decode_insn` returns an owned InstructionData (a
    // right-sized Vec<OperandData> nesting RegisterData by value, `status` standing in for the raw
    // return code). Walk real instructions and validate its internal shape. Skips gracefully off
    // x86 (status -2), since the decoder is x86-only.
    {
        use idakit_sys as sys;

        if sys::decode_insn(address.get()).status == -2 {
            println!("skipping instruction decode: non-x86 processor (status -2)");
        } else {
            let mut ea = address.get();
            let mut decoded = 0u32;
            while decoded < 64 {
                let data = sys::decode_insn(ea);
                if data.status != 0 {
                    break;
                }
                assert!(
                    data.len > 0,
                    "a decoded instruction has non-zero length at {ea:#x}"
                );
                assert_eq!(
                    data.nops as usize,
                    data.ops.len(),
                    "nops vs ops.len() disagree at {ea:#x}"
                );
                ea += data.len as u64;
                decoded += 1;
            }
            assert!(decoded > 0, "decoded no instructions in the first function");
            println!("cxx instruction bridge OK: {decoded} instructions decoded");
        }
    }

    // cxx ExternType bridge (Goal A): the `range_t` Trivial ExternType crosses by value four ways
    // (returned bare, taken by value, a by-value shared-struct field, and a Vec element). Its four
    // shapes are cross-checked against each other, then against the qvector<range_t> Opaque path.
    {
        use idakit_sys as sys;

        let ea = address.get();

        // range_entry_chunk (by-value return).
        let entry =
            sys::range_entry_chunk(ea).expect("cxx range_entry_chunk on the first function");
        assert!(
            entry.end >= entry.start,
            "entry chunk end precedes its start"
        );

        // range_size (by-value argument): a Trivial ExternType passed into C++ by value.
        assert_eq!(
            sys::range_size(entry),
            entry.end - entry.start,
            "range_size disagrees with end - start"
        );

        // range_chunk_info (by-value ExternType field of a shared struct).
        let info = sys::range_chunk_info(ea, 0).expect("cxx range_chunk_info(0)");
        assert_eq!(info.index, 0, "chunk info index");
        assert_eq!(
            info.range, entry,
            "ChunkInfo.range disagrees with range_entry_chunk"
        );

        // range_all_chunks (Vec<RangeT>): a Trivial ExternType as a Vec element, one row per chunk.
        let chunks = sys::range_all_chunks(ea).expect("cxx range_all_chunks");
        assert!(
            !chunks.is_empty(),
            "a real function has at least an entry chunk"
        );
        assert_eq!(
            chunks.first().copied(),
            Some(entry),
            "range_all_chunks[0] should be the entry chunk"
        );

        // Out-of-range chunk index surfaces as Err on the cxx path.
        assert!(
            sys::range_chunk_info(ea, chunks.len()).is_err(),
            "range_chunk_info should Err past the last chunk"
        );

        // Goal B (qvector<range_t>): the recipe generalized from scalar to a Trivial-struct
        // element. rangevec_build_chunks yields a rangevec_t owned by UniquePtr (so the zero-copy
        // borrow ties to a container Rust controls); rangevec_slice borrows it as &[RangeT] with no
        // copy. Cross-check element-for-element against the range_all_chunks Vec<RangeT> copy path.
        let rv = sys::rangevec_build_chunks(ea).expect("cxx rangevec_build_chunks");
        let rvref = rv.as_ref().expect("rangevec UniquePtr is non-null");
        assert_eq!(
            sys::rangevec_len(rvref),
            chunks.len(),
            "rangevec_len disagrees with range_all_chunks"
        );
        let rslice = sys::rangevec_slice(rvref);
        assert_eq!(
            rslice.len(),
            chunks.len(),
            "rangevec_slice len disagrees with range_all_chunks"
        );
        for (i, r) in rslice.iter().enumerate() {
            assert_eq!(
                *r, chunks[i],
                "rangevec_slice[{i}] (zero-copy) disagrees with range_all_chunks (copy)"
            );
        }

        println!(
            "cxx range_t ExternType cross-check OK: {} chunks",
            chunks.len()
        );
    }

    // cxx bytes bridge: the generated bytes accessors (Result-shaped typed reads, the Vec<u8> range
    // read, item navigation, flags, comment) exercised over the first 300 function entries plus the
    // database bounds, each result checked for internal consistency.
    {
        use idakit_sys as sys;

        let (min_ea, max_ea) = (sys::min_ea(), sys::max_ea());
        assert!(min_ea < max_ea, "database bounds are degenerate");

        let sample = sys::func_qty().min(300);
        for n in 0..sample {
            let ea = sys::func_ea(n);
            assert!(
                sys::get_item_head(ea) <= ea,
                "get_item_head past ea at {ea:#x}"
            );
            assert!(
                sys::get_item_end(ea) > ea,
                "get_item_end not past ea at {ea:#x}"
            );
            let _ = sys::get_flags(ea);
            let _ = sys::get_next_head(ea, max_ea);
            let _ = sys::get_prev_head(ea, min_ea);

            // A typed byte read and a 1-byte range read must agree when both succeed.
            if let (Ok(v8), Ok(bytes)) = (sys::get_u8(ea), sys::get_bytes(ea, 1)) {
                assert_eq!(
                    v8, bytes[0],
                    "get_u8 disagrees with get_bytes[0] at {ea:#x}"
                );
            }
            let _ = sys::get_u64(ea);
            let _ = sys::get_cmt(ea, false);
        }
        println!(
            "cxx bytes bridge OK: typed reads, range reads, and navigation over {sample} functions"
        );
    }

    // Best-effort; just exercise the paths (consume the lazy reference cursors).
    let _ = first.xrefs_to().count();
    let _ = first.xrefs_from().count();
    let _ = first.prototype();

    // Structured prototype walk: drive idakit_func_type_walk over real functions. Not every
    // function is typed, so scan for the first that resolves and validate its shape end-to-end.
    {
        let mut typed = 0usize;
        let mut example = None;
        for f in idb.functions().take(2000) {
            if let Some(image) = f.prototype_type().expect("prototype walk") {
                typed += 1;
                if example.is_none() {
                    example = Some((f.address(), image));
                }
            }
        }
        if let Some((ea, image)) = example {
            let TypeShape::Function { ret, params, .. } = image.shape() else {
                panic!("a function prototype's root should be a Function type");
            };
            // Every child handle resolves against the image's own table.
            let _ = image.get(*ret);
            for p in params {
                let _ = image.get(*p);
            }
            println!(
                "prototype at {ea:#x}: {} params, {typed} typed functions in sample",
                params.len()
            );
        } else {
            println!("no typed function prototypes in sample");
        }
    }

    // The cxx opaque-visitor type walk over every named local type: resolve each through the
    // production path (`NamedType::resolve` -> the cxx `TypeWalkVisitor`, names crossing as
    // `rust::Str`, struct members as a `rust::Slice<const MemberInfo>` of a lifetime-generic shared
    // struct with a borrowed `&str` name) and confirm it structures real aggregates, so the
    // borrowed-name-in-array fill_struct/fill_enum path is exercised on the corpus.
    {
        let mut resolved = 0usize;
        let mut saw_struct_member = false;
        let mut saw_named_or_opaque = false;
        for nt in idb.named_types().take(2000) {
            let Ok(ty) = nt.resolve() else { continue };
            resolved += 1;
            for (_, val) in ty.types().iter() {
                match &val.shape {
                    TypeShape::Struct { members, .. } | TypeShape::Union { members, .. } => {
                        if members.iter().any(|m| !m.name.is_empty()) {
                            saw_struct_member = true;
                        }
                    }
                    TypeShape::Opaque(_) | TypeShape::Typedef { .. } => saw_named_or_opaque = true,
                    _ => {}
                }
            }
        }
        // Guard against a vacuous pass: the canonical DB carries named types, so the walk must have
        // structured something for the coverage to mean anything.
        assert!(resolved > 0, "the cxx type walk resolved no named types");
        println!(
            "cxx type walk resolved {resolved} named types (struct-member names seen: \
             {saw_struct_member}, named/opaque refs seen: {saw_named_or_opaque})"
        );
    }

    // cxx opaque-handle bridge: the generated decompile -> UniquePtr<CFunc> + cfunc_* accessors,
    // exercised on the first function. The UniquePtr's cxx deleter runs ~cfuncptr_t on drop.
    {
        use idakit_sys as sys;
        if let Ok(cf) = sys::decompile(address.get()) {
            let cref = cf.as_ref().expect("non-null cxx handle");
            let gc = sys::cfunc_counts(cref);
            assert!(
                gc.insns >= 0 && gc.expressions >= 0 && gc.calls >= 0,
                "ctree counts should be non-negative"
            );
            let gp = sys::cfunc_pseudocode(cref).expect("cxx pseudocode");
            assert!(
                !gp.is_empty(),
                "pseudocode should be non-empty for a decompiled function"
            );
            // `cf` (UniquePtr<CFunc>) drops here, running the cxx deleter (~cfuncptr_t / release()).
            println!(
                "cxx hexrays bridge OK: {} insns, {} expressions, {} calls",
                gc.insns, gc.expressions, gc.calls
            );
        }
    }

    // Exercise the RAII owned-handle path (best-effort).
    match first.decompile() {
        Ok(cf) => {
            let c = cf.counts();
            assert!(c.expressions >= 0 && c.insns >= 0);
            println!(
                "decompiled first fn: {} insns, {} expressions, {} calls",
                c.insns, c.expressions, c.calls
            );

            // Materialize the whole ctree and cross-check it against the
            // independent visitor counts: two separate traversals of the same
            // cfunc must agree, node-for-node.
            use idakit::decompiler::ctree::{ExpressionKind, NodeRef, StatementKind};
            let tree = cf.ctree().expect("ctree extraction");
            let root = tree.root();
            assert!(let StatementKind::Block(_) = &tree.statement(root).kind);
            assert_eq!(
                tree.expressions().count(),
                c.expressions as usize,
                "extracted expression count should match the visitor"
            );
            assert_eq!(
                tree.statements().count(),
                c.insns as usize,
                "extracted statement count should match the visitor"
            );
            // Every allocated node is reachable from the root: confirms the
            // post-order image and parent wiring are sound.
            let reachable = tree.descendants(NodeRef::Statement(root)).count();
            assert_eq!(
                reachable,
                tree.expressions().count() + tree.statements().count(),
                "every node should be reachable from the root"
            );
            println!(
                "ctree extracted: {} expressions, {} statements, {} types; root is a block",
                tree.expressions().count(),
                tree.statements().count(),
                tree.types().count()
            );

            // Round-trip the owned tree back to C-like pseudocode and check it
            // against IDA's own rendering. Exact text won't match (IDA has its own
            // formatting), but every lvar our tree references must appear in IDA's
            // pseudocode: the names come from the same lvar table, so a dropped or
            // misresolved `Var` surfaces here as a missing name.
            let rendered = tree.to_pseudocode();
            if let Some(ida_pc) = cf.pseudocode() {
                let mut referenced: Vec<String> = tree
                    .expressions()
                    .filter_map(|(_, e)| match &e.kind {
                        ExpressionKind::Var(v) => Some(tree.lvar(*v).name.clone()),
                        _ => None,
                    })
                    .collect();
                referenced.sort();
                referenced.dedup();
                let missing: Vec<&String> = referenced
                    .iter()
                    .filter(|name| !ida_pc.contains(name.as_str()))
                    .collect();
                assert!(
                    missing.is_empty(),
                    "lvar names referenced by the tree but absent from IDA's \
                             pseudocode (extraction dropped or misresolved a Var): {missing:?}"
                );
                println!(
                    "round-trip OK: {} referenced lvars all present in IDA's pseudocode",
                    referenced.len()
                );
                println!("--- idakit render ---\n{rendered}\n--- IDA pseudocode ---\n{ida_pc}");
            } else {
                println!("round-trip: IDA pseudocode unavailable; rendered:\n{rendered}");
            }

            // The still-experimental inline moveit value type CfuncVal mirrors cfuncptr_t
            // (qrefcnt_t<cfunc_t>, the decompiler's intrusive-refcounted smart pointer) as a
            // pure-moveit stack value (no cxx): the C++ copy-ctor bumps the intrusive refcount and
            // the C++ destructor releases it. Deltas, not absolutes, since the cfunc_t may be
            // shared/cached.
            {
                use idakit_sys as sys;
                let ea = address.get();

                let [i0, i1, i2] = sys::cfunc_moveit_inline_probe(ea)
                    .expect("moveit inline probe (decompile succeeded above)");
                assert_eq!(
                    i1,
                    i0 + 1,
                    "inline moveit copy-ctor must bump refcount ({i0} -> {i1})"
                );
                assert_eq!(
                    i2, i0,
                    "dropping the inline moveit clone must release ({i1} -> {i2})"
                );
                println!("moveit inline CfuncVal OK: refcnt {i0} -> {i1} (clone) -> {i2} (drop)");
            }
        }
        Err(e) => println!("decompile unavailable ({e})"),
    }

    // Decompile-failure path: an unmapped address has no function, so the
    // kernel returns null and the facade reports the reason. Confirm a real
    // reason (sourced from the facade buffer, not a stale qerrno) propagates.
    let nowhere = Address::new_const(0xffff_ffff_f000);
    match idb.decompile(nowhere) {
        Ok(_) => panic!("expected decompile to fail at unmapped {nowhere:#x}"),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("no function at address"),
                "decompile failure should carry the facade reason, got: {msg}"
            );
            println!("decompile-failure reason propagated: {msg}");
        }
    }

    // cxx real-database-write cross-check (Round 10, Goal B): a mutation crossing the cxx boundary
    // (libida `set_name`/`set_cmt` wrapped as bridge fns) must land and read back through idakit's
    // existing read path. Follows roundtrip.rs's mutate-then-restore discipline exactly: the name is
    // restored to `original` and the DB is closed `save = false`, so the fixture never changes on
    // disk. Rejection surfaces as a Rust `Err` via the custom trycatch, treated as a bare signal.
    {
        use idakit_sys as sys;

        let ea = address.get();
        let cxx_name = "idakit_cxx_write_probe";

        // Write the name THROUGH cxx, read it back through idakit -> the write landed across cxx.
        sys::ext_set_name(ea, cxx_name)
            .expect("cxx ext_set_name should succeed on a real function");
        assert_eq!(
            idb.function(address).name().as_str(),
            cxx_name,
            "cxx set_name did not land (read back through idakit)"
        );

        // Write a comment THROUGH cxx, read it back through idakit.
        let cxx_cmt = "touched by idakit cxx write probe";
        sys::ext_set_cmt(ea, cxx_cmt, false).expect("cxx ext_set_cmt should succeed");
        assert_eq!(
            idb.comment(address, false).as_deref(),
            Some(cxx_cmt),
            "cxx set_cmt did not land (read back through idakit)"
        );

        // The Err path: writing a name at an unmapped address is rejected; cxx surfaces it as Err
        // (a bare failure signal -- idakit re-derives qerrno/reason kernel-side, not from what()).
        assert!(
            sys::ext_set_name(0xffff_ffff_f000, "nope").is_err(),
            "cxx set_name at an unmapped address should Err"
        );

        // Restore the original name through cxx and clear the probe comment; confirm the restore.
        sys::ext_set_name(ea, original.as_str()).expect("cxx restore ext_set_name");
        sys::ext_set_cmt(ea, "", false).expect("cxx clear ext_set_cmt");
        assert_eq!(
            idb.function(address).name().as_str(),
            original.as_str(),
            "name should be restored to the original after the cxx write probe"
        );
        println!("cxx real-DB write cross-check OK: set_name/set_cmt landed and restored via cxx");
    }

    // Rename via the write cursor (first's borrow has ended), then confirm.
    let renamed = "idakit_roundtrip_probe";
    idb.at_mut(address).rename(renamed).expect("rename failed");
    let after = idb.function(address).name();
    assert_eq!(after.as_str(), renamed, "rename did not stick");
    assert!(after.is_user(), "a user rename yields a user name");

    idb.at_mut(address)
        .set_comment("touched by idakit roundtrip", false)
        .expect("set_comment failed");

    // Leave the DB as found.
    idb.at_mut(address)
        .rename(original.as_str())
        .expect("restore rename failed");

    println!("roundtrip OK: {func_count} funcs, {seg_count} segs, rename/comment verified");
}
