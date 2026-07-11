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

    // cxx signature-bridge cross-check: the cxx-bridged `idakit_cxx::seg_*` must agree with the
    // raw facade path on the same open database. idakit's `Segment` view is a thin wrapper over
    // the raw `idakit_seg_*` functions, so comparing the cxx return against it is a genuine
    // cxx-vs-raw check -- and for the string accessors it proves owned `String`/`Result<String>`
    // returns match the raw snprintf-buffer path byte for byte.
    {
        use idakit_sys as sys;

        assert_eq!(
            sys::seg_qty(),
            seg_count,
            "cxx seg_qty disagrees with the raw segment count"
        );
        for seg in idb.segments() {
            let n = seg.index();
            assert_eq!(
                Address::try_new(sys::seg_start(n)),
                seg.start(),
                "cxx seg_start disagrees with raw at segment {n}"
            );
            assert_eq!(
                Address::try_new(sys::seg_end(n)),
                seg.end(),
                "cxx seg_end disagrees with raw at segment {n}"
            );
            assert_eq!(
                sys::seg_name(n).ok(),
                seg.name(),
                "cxx seg_name disagrees with raw at segment {n}"
            );
            // Absent class: cxx throws (mapped to Err -> None here); raw returns None. Both agree.
            assert_eq!(
                sys::seg_class(n).ok(),
                seg.class_name(),
                "cxx seg_class disagrees with raw at segment {n}"
            );

            // Spec-generated bridge (idakit_gen::gen_seg_*): built entirely from the declarative
            // SEGMENT_SPEC via cxx-gen, it must agree with the hand-written cxx bridge byte for
            // byte on every accessor shape (passthrough, lookup+scalar, Result<String>).
            assert_eq!(
                sys::gen_seg_start(n),
                sys::seg_start(n),
                "generated gen_seg_start disagrees with hand-written at segment {n}"
            );
            assert_eq!(
                sys::gen_seg_end(n),
                sys::seg_end(n),
                "generated gen_seg_end disagrees with hand-written at segment {n}"
            );
            assert_eq!(
                sys::gen_seg_perm(n),
                sys::seg_perm(n),
                "generated gen_seg_perm disagrees with hand-written at segment {n}"
            );
            assert_eq!(
                sys::gen_seg_bitness(n),
                sys::seg_bitness(n),
                "generated gen_seg_bitness disagrees with hand-written at segment {n}"
            );
            assert_eq!(
                sys::gen_seg_name(n).ok(),
                sys::seg_name(n).ok(),
                "generated gen_seg_name disagrees with hand-written at segment {n}"
            );
            assert_eq!(
                sys::gen_seg_class(n).ok(),
                sys::seg_class(n).ok(),
                "generated gen_seg_class disagrees with hand-written at segment {n}"
            );
        }
        assert_eq!(
            sys::gen_seg_qty(),
            sys::seg_qty(),
            "generated gen_seg_qty disagrees with hand-written seg_qty"
        );
        // The Custom escape-hatch body (hand-written in facade/gen_custom.cc, declared by the
        // spec) must equal the byte span summed over the raw facade path.
        let raw_span_total: u64 = idb
            .segments()
            .map(|s| s.end().map_or(0, u64::from) - s.start().map_or(0, u64::from))
            .sum();
        assert_eq!(
            sys::gen_seg_span_total(),
            raw_span_total,
            "generated custom gen_seg_span_total disagrees with summed raw spans"
        );
        println!(
            "cxx bridge cross-check OK: {seg_count} segments agree across raw, hand-written, and spec-generated facades"
        );
    }

    let first = idb.functions().next().expect("a function");
    let address = first.address();
    let original = first.name();
    assert!(!original.is_empty());

    let bytes = idb.bytes(address, 16);
    assert!(!bytes.is_empty(), "expected readable bytes at the entry");

    // cxx opaque-handle cross-check: the cxx `FlowChart` path (opaque type owned by UniquePtr,
    // BlockInfo shared struct, Result-shaped bounds) must agree with the raw `idakit_cfg_*`
    // path on the same function. The cxx `UniquePtr<FlowChart>` frees the qflow_chart_t via
    // cxx's generated deleter glue on drop; the raw handle is freed explicitly below.
    {
        use idakit_sys as sys;

        let ea = address.get();
        let flags = 0i32;

        let fc = sys::cfg_build(ea, flags).expect("cxx cfg_build on the first function");
        // SAFETY: `ea` is a real function entry; the raw handle is freed at the end of the block.
        let h = unsafe { sys::idakit_cfg_build(ea, flags) };
        assert!(
            !h.is_null(),
            "raw cfg_build returned null on the first function"
        );

        let n = sys::cfg_nblocks(&fc);
        // SAFETY: `h` is a live raw flow-chart handle for the duration of this block.
        assert_eq!(
            n as i32,
            unsafe { sys::idakit_cfg_nblocks(h) },
            "cxx/raw nblocks disagree"
        );
        // SAFETY: `h` is a live raw flow-chart handle for the duration of this block.
        assert_eq!(
            sys::cfg_nproper(&fc) as i32,
            unsafe { sys::idakit_cfg_nproper(h) },
            "cxx/raw nproper disagree"
        );

        for b in 0..n {
            let info = sys::cfg_block(&fc, b).expect("cxx cfg_block in range");
            let (mut rs, mut re, mut rk) = (0u64, 0u64, 0i32);
            // SAFETY: `b < n`; the out-params are valid stack locals.
            let ok = unsafe { sys::idakit_cfg_block(h, b as i32, &mut rs, &mut re, &mut rk) };
            assert_eq!(ok, 1, "raw cfg_block failed at block {b}");
            assert_eq!(info.start, rs, "block {b} start disagrees");
            assert_eq!(info.end, re, "block {b} end disagrees");
            assert_eq!(info.kind, rk, "block {b} kind disagrees");

            let ns = sys::cfg_nsucc(&fc, b);
            // SAFETY: `h` live, `b < n`.
            assert_eq!(ns as i32, unsafe { sys::idakit_cfg_nsucc(h, b as i32) });
            for i in 0..ns {
                let s = sys::cfg_succ(&fc, b, i).expect("cxx cfg_succ in range");
                // SAFETY: `h` live, `b < n`, `i < ns`.
                assert_eq!(s as i32, unsafe {
                    sys::idakit_cfg_succ(h, b as i32, i as i32)
                });
            }

            let np = sys::cfg_npred(&fc, b);
            // SAFETY: `h` live, `b < n`.
            assert_eq!(np as i32, unsafe { sys::idakit_cfg_npred(h, b as i32) });
            for i in 0..np {
                let p = sys::cfg_pred(&fc, b, i).expect("cxx cfg_pred in range");
                // SAFETY: `h` live, `b < n`, `i < np`.
                assert_eq!(p as i32, unsafe {
                    sys::idakit_cfg_pred(h, b as i32, i as i32)
                });
            }

            // qvector<scalar> -> Vec<u32>: the whole-edge-list cxx path (one copy) must equal
            // the per-index accessors it retires, element for element.
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
            // container, borrowed out of the live flow chart. Read it BOTH ways -- a copying
            // shim to Vec<i32>, and a zero-copy &[i32] borrowed from the container's {array, n}
            // -- and cross-check both against the cfg_succs copy and per-index cfg_succ paths.
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

        // Out-of-range bounds surface as `Err` on the cxx path (the raw path returns 0/-1).
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

        // SAFETY: `h` came from idakit_cfg_build and has not been freed yet.
        unsafe { sys::idakit_cfg_free(h) };
        // `fc` drops here: cxx's UniquePtr glue runs qflow_chart_t's destructor, no manual free.
        println!("cxx cfg bridge cross-check OK: {n} blocks agree with the raw facade");
    }

    // cxx ExternType cross-check (Goal A): the `range_t` Trivial ExternType crosses by value four
    // ways -- returned bare (range_entry_chunk), taken by value (range_size), a by-value shared-
    // struct field (ChunkInfo.range), and a Vec element (range_all_chunks). Each must agree with
    // the raw `idakit_func_chunk` out-param facade on the same function.
    {
        use idakit_sys as sys;

        let ea = address.get();

        // range_entry_chunk (by-value return) vs raw idakit_func_chunk(ea, 0, ...).
        let entry =
            sys::range_entry_chunk(ea).expect("cxx range_entry_chunk on the first function");
        let (mut rs, mut re) = (0u64, 0u64);
        // SAFETY: `ea` is a real function entry; out-params are valid stack locals.
        let ok = unsafe { sys::idakit_func_chunk(ea, 0, &mut rs, &mut re) };
        assert_eq!(ok, 1, "raw idakit_func_chunk failed on the entry chunk");
        assert_eq!(
            entry.start, rs,
            "range_entry_chunk start disagrees with raw"
        );
        assert_eq!(entry.end, re, "range_entry_chunk end disagrees with raw");

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
        // SAFETY: `ea` is a real function entry.
        let raw_qty = unsafe { sys::idakit_func_chunk_qty(ea) };
        assert_eq!(
            chunks.len(),
            raw_qty as usize,
            "range_all_chunks count disagrees with raw"
        );
        for (i, chunk) in chunks.iter().enumerate() {
            let (mut cs, mut ce) = (0u64, 0u64);
            // SAFETY: `i < raw_qty`; out-params are valid stack locals.
            let ok = unsafe { sys::idakit_func_chunk(ea, i as i32, &mut cs, &mut ce) };
            assert_eq!(ok, 1, "raw idakit_func_chunk failed at chunk {i}");
            assert_eq!(chunk.start, cs, "chunk {i} start disagrees with raw");
            assert_eq!(chunk.end, ce, "chunk {i} end disagrees with raw");
        }
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
        // element. rangevec_build_chunks yields a rangevec_t owned by UniquePtr (so the
        // zero-copy borrow ties to a container Rust controls); rangevec_slice borrows it as
        // &[RangeT] with no copy. Cross-check element-for-element against the range_all_chunks
        // Vec<RangeT> copy path from the sibling range bridge.
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
            "cxx range_t ExternType cross-check OK: {} chunks agree with the raw facade",
            chunks.len()
        );
    }

    // cxx snapshot cross-check: `imports_build()` returns the whole import table as one owned
    // Vec<ImportRec> (shared struct with String fields). It must match the raw handle/index/free
    // path (idakit_imports_build + _qty + _item + _name + _module + _free) row for row.
    {
        use idakit_sys as sys;

        let recs = sys::imports_build();

        // SAFETY: handle from idakit_imports_build; freed at the end of this block.
        let h = unsafe { sys::idakit_imports_build() };
        assert!(!h.is_null(), "raw imports_build returned null");
        // SAFETY: `h` is a live imports handle for the duration of this block.
        let raw_qty = unsafe { sys::idakit_imports_qty(h) };
        assert_eq!(
            recs.len(),
            raw_qty,
            "cxx imports count disagrees with the raw facade"
        );

        for (n, rec) in recs.iter().enumerate() {
            let (mut ea, mut ord) = (0u64, 0u64);
            // SAFETY: `n < raw_qty`; out-params are valid stack locals.
            let ok = unsafe { sys::idakit_imports_item(h, n, &mut ea, &mut ord) };
            assert_eq!(ok, 1, "raw imports_item failed at row {n}");
            assert_eq!(rec.ea, ea, "import row {n} ea disagrees");
            assert_eq!(rec.ord, ord, "import row {n} ord disagrees");

            // Raw name buffer: length probe then a fill; a negative length means "no name".
            let mut buf = [0u8; 512];
            // SAFETY: `n < raw_qty`; buf/cap valid.
            let name_len =
                unsafe { sys::idakit_imports_name(h, n, buf.as_mut_ptr().cast(), buf.len()) };
            let raw_name = if name_len < 0 {
                String::new()
            } else {
                String::from_utf8_lossy(&buf[..name_len as usize]).into_owned()
            };
            assert_eq!(rec.name, raw_name, "import row {n} name disagrees");

            // SAFETY: `n < raw_qty`; buf/cap valid.
            let mod_len =
                unsafe { sys::idakit_imports_module(h, n, buf.as_mut_ptr().cast(), buf.len()) };
            let raw_module = if mod_len < 0 {
                String::new()
            } else {
                String::from_utf8_lossy(&buf[..mod_len as usize]).into_owned()
            };
            assert_eq!(rec.module, raw_module, "import row {n} module disagrees");
        }

        // SAFETY: `h` came from idakit_imports_build and has not been freed yet.
        unsafe { sys::idakit_imports_free(h) };
        println!(
            "cxx imports snapshot cross-check OK: {} rows agree with the raw facade",
            recs.len()
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

    // cxx extern "Rust" opaque-visitor cross-check (Round 7): the tinfo type walk driven by a Rust
    // opaque `TypeWalkVisitor` (its `&mut self` methods called from C++, names crossing as
    // `rust::Str`, struct members as a `rust::Slice<const MemberInfo>` of a lifetime-generic
    // shared struct with a borrowed `&str` name) must produce the same node/name stream as the
    // existing raw `TypeVtbl` function-pointer walk over the same types. Both paths record a
    // `Vec<VisitEvent>`; the visitor path is `typewalk_visit_*`, the raw path
    // `typewalk_record_*` (a hand-written recording vtbl over the production `idakit_*_walk`
    // entry). A name that is not valid UTF-8 makes only the `rust::Str` visitor path bail (the
    // recorder is lossy), so a one-sided result is skipped rather than failed.
    {
        use idakit_sys as sys;

        let mut compared = 0usize;
        let mut skipped = 0usize;
        let mut saw_struct_member = false;
        let mut saw_named_or_opaque = false;

        // Named local types (ordinals): the richest coverage -- structs/unions/enums/typedefs, so
        // the fill_struct/fill_enum borrowed-name-in-array path (Goal B) is exercised.
        for nt in idb.named_types().take(2000) {
            let ord = nt.ordinal();
            match (
                sys::typewalk_visit_ordinal(ord),
                sys::typewalk_record_ordinal(ord),
            ) {
                (Some(visited), Some(recorded)) => {
                    assert_eq!(
                        visited, recorded,
                        "cxx visitor vs raw TypeVtbl walk disagree on named type ordinal {ord}"
                    );
                    compared += 1;
                    for ev in &visited {
                        match ev {
                            sys::VisitEvent::FillStruct { members, .. } => {
                                if members.iter().any(|m| !m.name.is_empty()) {
                                    saw_struct_member = true;
                                }
                            }
                            sys::VisitEvent::NamedRef { .. } | sys::VisitEvent::Opaque { .. } => {
                                saw_named_or_opaque = true;
                            }
                            _ => {}
                        }
                    }
                }
                (None, None) => {}
                _ => skipped += 1,
            }
        }

        // Function prototypes (Goal D "typed functions"): the same cross-check, keyed by address.
        let mut func_compared = 0usize;
        for f in idb.functions().take(2000) {
            let ea = f.address().get();
            match (sys::typewalk_visit_func(ea), sys::typewalk_record_func(ea)) {
                (Some(visited), Some(recorded)) => {
                    assert_eq!(
                        visited, recorded,
                        "cxx visitor vs raw TypeVtbl walk disagree on function prototype at {ea:#x}"
                    );
                    func_compared += 1;
                }
                (None, None) => {}
                _ => skipped += 1,
            }
        }

        // Guard against a vacuous pass: the canonical DB carries named types and typed functions,
        // so the visitor must actually have walked something for the agreement to mean anything.
        assert!(
            compared + func_compared > 0,
            "cxx opaque-visitor cross-check walked nothing (compared={compared}, \
             func_compared={func_compared})"
        );
        println!(
            "cxx opaque-visitor cross-check OK: {compared} named types + {func_compared} function \
             prototypes agree with the raw TypeVtbl walk ({skipped} one-sided skips; \
             struct-member names seen: {saw_struct_member}, named/opaque refs seen: \
             {saw_named_or_opaque})"
        );
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

            // Round 8 spike: cfuncptr_t (qrefcnt_t<cfunc_t>, the decompiler's intrusive-
            // refcounted smart pointer) modeled through cxx + moveit. (a) Goal A -- an Opaque
            // ExternType owned by UniquePtr, whose cxx deleter runs ~cfuncptr_t on drop. (b)
            // Goal B -- moveit's construction traits over that SAME cxx type (the UniquePtr
            // composition) and over a pure-moveit inline stack value type, each proving the C++
            // copy-ctor bumps the intrusive refcount and the C++ destructor releases it.
            {
                use idakit_sys as sys;
                let ea = address.get();

                // Goal A: decompile through the cxx Opaque + UniquePtr path; a live cfuncptr_t
                // holds at least one ref.
                let cptr =
                    sys::cfunc_decompile(ea).expect("cxx cfunc_decompile on the first function");
                let base = cptr.as_ref().expect("cfuncptr UniquePtr is non-null");
                let r = sys::cfunc_refcnt(base);
                assert!(r >= 1, "a live cfuncptr_t must hold >= 1 ref, got {r}");
                println!("cxx cfunc_decompile OK: UniquePtr<CfuncPtr>, refcnt = {r}");

                // Goal B (composition): clone via moveit copy-ctor into a second UniquePtr, then
                // drop it. Deltas, not absolutes, since the cfunc_t may be shared/cached.
                let [c0, c1, c2] = sys::cfunc_moveit_uniqueptr_probe(ea)
                    .expect("moveit UniquePtr probe (decompile succeeded above)");
                assert_eq!(
                    c1,
                    c0 + 1,
                    "moveit copy-ctor must bump refcount ({c0} -> {c1})"
                );
                assert_eq!(
                    c2, c0,
                    "dropping the moveit clone must release ({c1} -> {c2})"
                );
                println!(
                    "moveit + cxx UniquePtr composition OK: refcnt {c0} -> {c1} (clone) -> {c2} (drop)"
                );

                // Goal B (inline): the same semantics on a pure-moveit stack value type (no cxx).
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
                // `cptr` (UniquePtr<CfuncPtr>) drops here, running ~cfuncptr_t (release()).
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
