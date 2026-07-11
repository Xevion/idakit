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

    // Spec-generated segment bridge (idakit_gen::gen_seg_*): built entirely from the declarative
    // SEGMENT_SPEC via cxx-gen, cross-checked against the raw idakit_seg_* facade over every
    // segment. idakit's `Segment` view now rides this generated bridge, so the genuine cxx-vs-raw
    // comparison is gen against the raw facade directly: passthrough scalars, lookup+scalar, and
    // the owned Result<String> getters, which must match the raw snprintf buffer byte for byte.
    {
        use std::os::raw::c_char;

        use idakit_sys as sys;

        // SAFETY: read-only raw facade calls on the open database, used throughout this block.
        let raw_qty = unsafe { sys::idakit_seg_qty() };
        assert_eq!(
            sys::gen_seg_qty(),
            raw_qty as usize,
            "generated gen_seg_qty disagrees with the raw facade"
        );
        for n in 0..raw_qty {
            assert_eq!(
                sys::gen_seg_start(n),
                unsafe { sys::idakit_seg_start(n) },
                "generated gen_seg_start disagrees with raw at segment {n}"
            );
            assert_eq!(
                sys::gen_seg_end(n),
                unsafe { sys::idakit_seg_end(n) },
                "generated gen_seg_end disagrees with raw at segment {n}"
            );
            assert_eq!(
                sys::gen_seg_perm(n),
                unsafe { sys::idakit_seg_perm(n) },
                "generated gen_seg_perm disagrees with raw at segment {n}"
            );
            assert_eq!(
                sys::gen_seg_bitness(n),
                unsafe { sys::idakit_seg_bitness(n) },
                "generated gen_seg_bitness disagrees with raw at segment {n}"
            );

            let mut buf = [0u8; 4096];
            let raw_len =
                unsafe { sys::idakit_seg_name(n, buf.as_mut_ptr() as *mut c_char, buf.len()) };
            let raw_name = (raw_len > 0).then(|| {
                assert!(
                    (raw_len as usize) < buf.len(),
                    "seg_name buffer too small at segment {n}"
                );
                String::from_utf8_lossy(&buf[..raw_len as usize]).into_owned()
            });
            assert_eq!(
                sys::gen_seg_name(n).ok(),
                raw_name,
                "generated gen_seg_name disagrees with raw at segment {n}"
            );

            // Absent class: gen throws (mapped to Err -> None here); the raw buffer path reports a
            // non-positive length (also None). Both agree.
            let mut cbuf = [0u8; 4096];
            let craw_len =
                unsafe { sys::idakit_seg_class(n, cbuf.as_mut_ptr() as *mut c_char, cbuf.len()) };
            let raw_class = (craw_len > 0).then(|| {
                assert!(
                    (craw_len as usize) < cbuf.len(),
                    "seg_class buffer too small at segment {n}"
                );
                String::from_utf8_lossy(&cbuf[..craw_len as usize]).into_owned()
            });
            assert_eq!(
                sys::gen_seg_class(n).ok(),
                raw_class,
                "generated gen_seg_class disagrees with raw at segment {n}"
            );
        }
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
            "cxx generated segment cross-check OK: {seg_count} segments agree with the raw facade"
        );
    }

    // Generated function domain (idakit_gen::func_*): every accessor cross-checked against the raw
    // idakit_func_* facade over every function. func_qty is a templated body; the lookups are
    // hand-written (facade/gen_function.cc).
    {
        use std::os::raw::c_char;

        use idakit_sys as sys;

        // SAFETY: read-only raw facade calls on the open database, used throughout this block.
        assert_eq!(
            sys::func_qty(),
            unsafe { sys::idakit_func_qty() },
            "generated func_qty disagrees with raw"
        );
        for (n, func) in idb.functions().enumerate() {
            let ea = func.address().get();
            assert_eq!(
                sys::func_ea(n),
                unsafe { sys::idakit_func_ea(n) },
                "generated func_ea disagrees with raw at index {n}"
            );
            assert_eq!(
                sys::func_start(ea),
                unsafe { sys::idakit_func_start(ea) },
                "generated func_start disagrees with raw at {ea:#x}"
            );
            assert_eq!(
                sys::func_end(ea),
                unsafe { sys::idakit_func_end(ea) },
                "generated func_end disagrees with raw at {ea:#x}"
            );
            assert_eq!(
                sys::func_flags(ea),
                unsafe { sys::idakit_func_flags(ea) },
                "generated func_flags disagrees with raw at {ea:#x}"
            );
            assert_eq!(
                sys::func_chunk_qty(ea),
                unsafe { sys::idakit_func_chunk_qty(ea) },
                "generated func_chunk_qty disagrees with raw at {ea:#x}"
            );
            // func_name: generated Result<String> vs the raw snprintf buffer (large enough for any
            // realistic name; the assert guards against silent truncation).
            let mut buf = [0u8; 4096];
            let raw_len =
                unsafe { sys::idakit_func_name(ea, buf.as_mut_ptr() as *mut c_char, buf.len()) };
            assert!(
                (raw_len as usize) < buf.len(),
                "func_name buffer too small at {ea:#x}"
            );
            let raw_name = (raw_len > 0)
                .then(|| String::from_utf8_lossy(&buf[..raw_len as usize]).into_owned());
            assert_eq!(
                sys::func_name(ea).ok(),
                raw_name,
                "generated func_name disagrees with raw at {ea:#x}"
            );
        }
        println!("cxx generated function cross-check OK: {func_count} functions agree with raw");
    }

    // Generated export domain (idakit_gen::export_*): every accessor cross-checked against the raw
    // idakit_export_* facade over every entry point.
    {
        use std::os::raw::c_char;

        use idakit_sys as sys;

        // SAFETY: read-only raw facade calls on the open database, used throughout this block.
        let export_count = sys::export_qty();
        assert_eq!(
            export_count,
            unsafe { sys::idakit_export_qty() },
            "generated export_qty disagrees with raw"
        );
        for idx in 0..export_count {
            assert_eq!(
                sys::export_ea(idx),
                unsafe { sys::idakit_export_ea(idx) },
                "generated export_ea disagrees with raw at index {idx}"
            );
            assert_eq!(
                sys::export_ordinal(idx),
                unsafe { sys::idakit_export_ordinal(idx) },
                "generated export_ordinal disagrees with raw at index {idx}"
            );
            let mut buf = [0u8; 4096];
            let raw_len =
                unsafe { sys::idakit_export_name(idx, buf.as_mut_ptr() as *mut c_char, buf.len()) };
            let raw_name = (raw_len > 0).then(|| {
                assert!(
                    (raw_len as usize) < buf.len(),
                    "export_name buffer too small at index {idx}"
                );
                String::from_utf8_lossy(&buf[..raw_len as usize]).into_owned()
            });
            assert_eq!(
                sys::export_name(idx).ok(),
                raw_name,
                "generated export_name disagrees with raw at index {idx}"
            );

            let mut fbuf = [0u8; 4096];
            let fwd_len = unsafe {
                sys::idakit_export_forwarder(idx, fbuf.as_mut_ptr() as *mut c_char, fbuf.len())
            };
            let raw_fwd = (fwd_len > 0).then(|| {
                assert!(
                    (fwd_len as usize) < fbuf.len(),
                    "export_forwarder buffer too small at index {idx}"
                );
                String::from_utf8_lossy(&fbuf[..fwd_len as usize]).into_owned()
            });
            assert_eq!(
                sys::export_forwarder(idx).ok(),
                raw_fwd,
                "generated export_forwarder disagrees with raw at index {idx}"
            );
        }
        println!("cxx generated export cross-check OK: {export_count} exports agree with raw");
    }

    // Generated meta domain (idakit_gen): database-wide metadata cross-checked against the raw
    // idakit_* meta facade. No iteration -- these are single db-wide values.
    {
        use std::os::raw::c_char;

        use idakit_sys as sys;

        // SAFETY: read-only raw facade calls on the open database, used throughout this block.
        assert_eq!(
            sys::bitness(),
            unsafe { sys::idakit_bitness() },
            "generated bitness disagrees with raw"
        );
        assert_eq!(
            sys::image_base(),
            unsafe { sys::idakit_image_base() },
            "generated image_base disagrees with raw"
        );

        // Each string getter: generated Result<String> vs the raw snprintf-style buffer, guarded
        // against silent truncation. A non-positive length means "no value" (generated Err).
        let check_str = |raw: unsafe extern "C" fn(*mut c_char, usize) -> i64,
                         got: Option<String>,
                         what: &str| {
            let mut buf = [0u8; 4096];
            let raw_len = unsafe { raw(buf.as_mut_ptr() as *mut c_char, buf.len()) };
            let raw_str = (raw_len > 0).then(|| {
                assert!((raw_len as usize) < buf.len(), "{what} buffer too small");
                String::from_utf8_lossy(&buf[..raw_len as usize]).into_owned()
            });
            assert_eq!(got, raw_str, "generated {what} disagrees with raw");
        };

        check_str(sys::idakit_proc_name, sys::proc_name().ok(), "proc_name");
        check_str(
            sys::idakit_file_type_name,
            sys::file_type_name().ok(),
            "file_type_name",
        );
        check_str(sys::idakit_input_path, sys::input_path().ok(), "input_path");
        check_str(
            sys::idakit_root_filename,
            sys::root_filename().ok(),
            "root_filename",
        );

        println!("cxx generated meta cross-check OK: all db-wide metadata agrees with raw");
    }

    // Generated name domain (idakit_gen::{get_ea_name, ...}): every accessor cross-checked against
    // the raw idakit_* name facade; the has_*_name predicates are fed each function's flags word.
    {
        use std::os::raw::c_char;

        use idakit_sys as sys;

        // SAFETY: read-only raw facade calls on the open database, used throughout this block.
        assert_eq!(
            sys::nlist_size(),
            unsafe { sys::idakit_nlist_size() },
            "generated nlist_size disagrees with raw"
        );
        for idx in 0..sys::nlist_size() {
            assert_eq!(
                sys::nlist_ea(idx),
                unsafe { sys::idakit_nlist_ea(idx) },
                "generated nlist_ea disagrees with raw at {idx}"
            );
            let mut buf = [0u8; 4096];
            let raw_len =
                unsafe { sys::idakit_nlist_name(idx, buf.as_mut_ptr() as *mut c_char, buf.len()) };
            let raw_name = (raw_len > 0).then(|| {
                assert!(
                    (raw_len as usize) < buf.len(),
                    "nlist_name buffer too small at {idx}"
                );
                String::from_utf8_lossy(&buf[..raw_len as usize]).into_owned()
            });
            assert_eq!(
                sys::nlist_name(idx).ok(),
                raw_name,
                "generated nlist_name disagrees with raw at {idx}"
            );
        }

        for func in idb.functions() {
            let ea = func.address().get();

            let mut buf = [0u8; 4096];
            let raw_len =
                unsafe { sys::idakit_get_ea_name(ea, buf.as_mut_ptr() as *mut c_char, buf.len()) };
            let raw_name = (raw_len > 0).then(|| {
                assert!(
                    (raw_len as usize) < buf.len(),
                    "get_ea_name buffer too small at {ea:#x}"
                );
                String::from_utf8_lossy(&buf[..raw_len as usize]).into_owned()
            });
            assert_eq!(
                sys::get_ea_name(ea).ok(),
                raw_name,
                "generated get_ea_name disagrees with raw at {ea:#x}"
            );

            let flags = unsafe { sys::idakit_get_flags(ea) };
            assert_eq!(
                sys::has_user_name(flags),
                unsafe { sys::idakit_has_user_name(flags) } != 0,
                "generated has_user_name disagrees with raw at {ea:#x}"
            );
            assert_eq!(
                sys::has_auto_name(flags),
                unsafe { sys::idakit_has_auto_name(flags) } != 0,
                "generated has_auto_name disagrees with raw at {ea:#x}"
            );
            assert_eq!(
                sys::has_dummy_name(flags),
                unsafe { sys::idakit_has_dummy_name(flags) } != 0,
                "generated has_dummy_name disagrees with raw at {ea:#x}"
            );

            if let Ok(name) = sys::get_ea_name(ea) {
                assert_eq!(
                    sys::get_name_ea(&name),
                    unsafe {
                        let c = std::ffi::CString::new(name.as_str()).unwrap();
                        sys::idakit_get_name_ea(c.as_ptr())
                    },
                    "generated get_name_ea disagrees with raw for {name:?}"
                );

                let mut dbuf = [0u8; 4096];
                let draw_len = unsafe {
                    let c = std::ffi::CString::new(name.as_str()).unwrap();
                    sys::idakit_demangle_name(
                        c.as_ptr(),
                        dbuf.as_mut_ptr() as *mut c_char,
                        dbuf.len(),
                    )
                };
                let draw = (draw_len > 0).then(|| {
                    assert!(
                        (draw_len as usize) < dbuf.len(),
                        "demangle_name buffer too small for {name:?}"
                    );
                    String::from_utf8_lossy(&dbuf[..draw_len as usize]).into_owned()
                });
                assert_eq!(
                    sys::demangle_name(&name).ok(),
                    draw,
                    "generated demangle_name disagrees with raw for {name:?}"
                );
            }
        }
        println!("cxx generated name cross-check OK");
    }

    // Generated strings domain (idakit_gen::strlist_*/strlit_contents): the string list built and
    // walked through the generated facade, cross-checked against the raw idakit_strlist_* /
    // idakit_strlit_contents facade. Capped at the first 200 entries so a corpus with a huge string
    // list stays cheap; the cross-check is uniform per entry, so the cap costs no coverage.
    {
        use std::os::raw::c_char;

        use idakit_sys as sys;

        // SAFETY: read-only raw facade calls on the open database, used throughout this block.
        sys::strlist_build();
        assert_eq!(
            sys::strlist_qty(),
            unsafe { sys::idakit_strlist_qty() },
            "generated strlist_qty disagrees with raw"
        );

        let qty = sys::strlist_qty().min(200);
        for n in 0..qty {
            let item = sys::strlist_item(n).expect("strlist_item within range");

            let mut ea: u64 = 0;
            let mut length: i32 = 0;
            let mut type_: i32 = 0;
            let ok = unsafe { sys::idakit_strlist_item(n, &mut ea, &mut length, &mut type_) };
            assert_eq!(ok, 1, "raw idakit_strlist_item failed at index {n}");
            assert_eq!(
                item.ea, ea,
                "generated strlist_item.ea disagrees with raw at {n}"
            );
            assert_eq!(
                item.length, length,
                "generated strlist_item.length disagrees with raw at {n}"
            );
            assert_eq!(
                item.type_, type_,
                "generated strlist_item.type_ disagrees with raw at {n}"
            );

            let mut buf = [0u8; 4096];
            let raw_len = unsafe {
                sys::idakit_strlit_contents(
                    ea,
                    length as usize,
                    type_,
                    buf.as_mut_ptr() as *mut c_char,
                    buf.len(),
                )
            };
            if raw_len >= 0 {
                assert!(
                    (raw_len as usize) < buf.len(),
                    "strlit_contents buffer too small at {ea:#x}"
                );
            }
            let raw_str = (raw_len >= 0)
                .then(|| String::from_utf8_lossy(&buf[..raw_len as usize]).into_owned());
            assert_eq!(
                sys::strlit_contents(ea, length as usize, type_).ok(),
                raw_str,
                "generated strlit_contents disagrees with raw at {ea:#x}"
            );
        }
        println!("cxx generated strings cross-check OK: {qty} string-list entries agree with raw");
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

    // cxx nested-struct cross-check: the generated `decode_insn` returns an owned InstructionData
    // (a right-sized Vec<OperandData> nesting RegisterData by value, `status` standing in for the
    // raw return code) that must agree field-for-field with the raw flat-POD `idakit_decode_insn`
    // on real instructions. Skips gracefully off x86 (status -2), since the decoder is x86-only.
    {
        use std::ffi::CStr;

        use idakit_sys as sys;

        fn cstr_name(buf: &[std::ffi::c_char]) -> String {
            // SAFETY: the facade NUL-terminates these fixed buffers within range.
            unsafe { CStr::from_ptr(buf.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        }

        if sys::decode_insn(address.get()).status == -2 {
            println!("skipping instruction cross-check: non-x86 processor (status -2)");
        } else {
            let mut ea = address.get();
            let mut decoded = 0u32;
            while decoded < 64 {
                let data = sys::decode_insn(ea);
                // SAFETY: InstructionRaw is an all-integer POD, so zeroed is a valid init value.
                let mut raw: sys::InstructionRaw = unsafe { std::mem::zeroed() };
                // SAFETY: `out` is a valid local; the facade fills it.
                let rc = unsafe { sys::idakit_decode_insn(ea, &mut raw) };
                assert_eq!(data.status, rc, "decode status disagrees at {ea:#x}");
                if rc != 0 {
                    break;
                }
                assert_eq!(data.len, raw.len, "insn len disagrees at {ea:#x}");
                assert_eq!(data.itype, raw.itype, "itype disagrees at {ea:#x}");
                assert_eq!(data.isa, raw.isa, "isa disagrees at {ea:#x}");
                assert_eq!(data.flow, raw.flow, "flow disagrees at {ea:#x}");
                assert_eq!(data.target, raw.target, "target disagrees at {ea:#x}");
                assert_eq!(data.nops, raw.nops, "nops disagrees at {ea:#x}");
                assert_eq!(
                    data.nops as usize,
                    data.ops.len(),
                    "nops vs ops.len() disagree at {ea:#x}"
                );
                assert_eq!(
                    data.mnemonic,
                    cstr_name(&raw.mnemonic),
                    "mnemonic disagrees at {ea:#x}"
                );
                for (i, op) in data.ops.iter().enumerate() {
                    let ro = &raw.ops[i];
                    assert_eq!(op.kind, ro.kind, "op {i} kind disagrees at {ea:#x}");
                    assert_eq!(op.idx, ro.idx, "op {i} idx disagrees at {ea:#x}");
                    assert_eq!(
                        op.data_type, ro.data_type,
                        "op {i} dtype disagrees at {ea:#x}"
                    );
                    assert_eq!(op.access, ro.access, "op {i} access disagrees at {ea:#x}");
                    assert_eq!(op.scale, ro.scale, "op {i} scale disagrees at {ea:#x}");
                    assert_eq!(op.disp, ro.disp, "op {i} disp disagrees at {ea:#x}");
                    assert_eq!(op.value, ro.value, "op {i} value disagrees at {ea:#x}");
                    assert_eq!(op.addr, ro.addr, "op {i} addr disagrees at {ea:#x}");
                    assert_eq!(op.sel, ro.sel, "op {i} sel disagrees at {ea:#x}");
                    assert_eq!(
                        op.reg.num, ro.register.num,
                        "op {i} reg num disagrees at {ea:#x}"
                    );
                    assert_eq!(
                        op.reg.name,
                        cstr_name(&ro.register.name),
                        "op {i} reg name disagrees at {ea:#x}"
                    );
                    assert_eq!(
                        op.base.name,
                        cstr_name(&ro.base.name),
                        "op {i} base name disagrees at {ea:#x}"
                    );
                    assert_eq!(
                        op.index.name,
                        cstr_name(&ro.index.name),
                        "op {i} index name disagrees at {ea:#x}"
                    );
                }
                ea += raw.len as u64;
                decoded += 1;
            }
            assert!(decoded > 0, "decoded no instructions in the first function");
            println!(
                "cxx instruction bridge cross-check OK: {decoded} instructions agree with the raw facade"
            );
        }
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

    // cxx snapshot cross-check: `xrefs_build(ea, is_to)` returns every cross-reference edge at an
    // address as one owned Vec<XrefRec>, retiring the raw open/next/close cursor. Sampled over the
    // first 200 function entries (xrefs *to* each), it must match the raw open/next/close loop edge
    // for edge.
    {
        use idakit_sys as sys;

        let sample = sys::func_qty().min(200);
        let mut edge_total = 0usize;
        for n in 0..sample {
            let ea = sys::func_ea(n);

            let recs = sys::xrefs_build(ea, true);

            // SAFETY: cursor from idakit_xref_open; closed below.
            let cursor = unsafe { sys::idakit_xref_open(ea, 1) };
            assert!(!cursor.is_null(), "raw xref_open returned null at {ea:#x}");
            let mut i = 0usize;
            loop {
                let (mut from, mut to) = (0u64, 0u64);
                let (mut type_, mut iscode, mut user) = (0u8, 0u8, 0u8);
                // SAFETY: cursor is live; out-params are valid stack locals.
                let more = unsafe {
                    sys::idakit_xref_next(
                        cursor,
                        &mut from,
                        &mut to,
                        &mut type_,
                        &mut iscode,
                        &mut user,
                    )
                };
                if more == 0 {
                    break;
                }
                assert!(
                    i < recs.len(),
                    "raw produced more xref edges than xrefs_build at {ea:#x}"
                );
                let rec = &recs[i];
                assert_eq!(rec.from, from, "xref edge {i} from disagrees at {ea:#x}");
                assert_eq!(rec.to, to, "xref edge {i} to disagrees at {ea:#x}");
                assert_eq!(
                    rec.type_, type_ as i32,
                    "xref edge {i} type disagrees at {ea:#x}"
                );
                assert_eq!(
                    rec.iscode,
                    iscode != 0,
                    "xref edge {i} iscode disagrees at {ea:#x}"
                );
                assert_eq!(
                    rec.user,
                    user != 0,
                    "xref edge {i} user disagrees at {ea:#x}"
                );
                i += 1;
            }
            // SAFETY: cursor came from idakit_xref_open and has not been closed.
            unsafe { sys::idakit_xref_close(cursor) };
            assert_eq!(
                recs.len(),
                i,
                "xrefs_build count disagrees with raw at {ea:#x}"
            );
            edge_total += i;
        }
        println!(
            "cxx xrefs snapshot cross-check OK: {edge_total} xref edges agree with the raw facade over {sample} functions"
        );
    }

    // cxx bytes cross-check: the generated bytes accessors (Result-shaped typed reads, the Vec<u8>
    // range read, item navigation, flags, and comment) must agree with the raw idakit_get_* facade.
    // Sampled over the first 300 function entries plus the database bounds.
    {
        use std::ffi::c_void;
        use std::os::raw::c_char;

        use idakit_sys as sys;

        // SAFETY: read-only raw facade calls on the open database, used throughout this block.
        assert_eq!(
            sys::min_ea(),
            unsafe { sys::idakit_min_ea() },
            "generated min_ea disagrees with raw"
        );
        assert_eq!(
            sys::max_ea(),
            unsafe { sys::idakit_max_ea() },
            "generated max_ea disagrees with raw"
        );
        let (min_ea, max_ea) = (sys::min_ea(), sys::max_ea());

        let sample = sys::func_qty().min(300);
        for n in 0..sample {
            let ea = sys::func_ea(n);
            assert_eq!(
                sys::get_flags(ea),
                unsafe { sys::idakit_get_flags(ea) },
                "generated get_flags disagrees at {ea:#x}"
            );
            assert_eq!(
                sys::get_item_head(ea),
                unsafe { sys::idakit_get_item_head(ea) },
                "generated get_item_head disagrees at {ea:#x}"
            );
            assert_eq!(
                sys::get_item_end(ea),
                unsafe { sys::idakit_get_item_end(ea) },
                "generated get_item_end disagrees at {ea:#x}"
            );
            assert_eq!(
                sys::get_next_head(ea, max_ea),
                unsafe { sys::idakit_get_next_head(ea, max_ea) },
                "generated get_next_head disagrees at {ea:#x}"
            );
            assert_eq!(
                sys::get_prev_head(ea, min_ea),
                unsafe { sys::idakit_get_prev_head(ea, min_ea) },
                "generated get_prev_head disagrees at {ea:#x}"
            );

            // Typed scalar reads: the generated Result<uN> vs the raw (rc, *out) pair, at the
            // narrowest and widest widths.
            let mut out8 = 0u8;
            // SAFETY: valid out-param.
            let rc8 = unsafe { sys::idakit_get_u8(ea, &mut out8) };
            match sys::get_u8(ea) {
                Ok(v) => {
                    assert_eq!(rc8, 1, "get_u8 Ok but raw failed at {ea:#x}");
                    assert_eq!(v, out8, "get_u8 value disagrees at {ea:#x}");
                }
                Err(_) => assert_eq!(rc8, 0, "get_u8 Err but raw succeeded at {ea:#x}"),
            }
            let mut out64 = 0u64;
            // SAFETY: valid out-param.
            let rc64 = unsafe { sys::idakit_get_u64(ea, &mut out64) };
            match sys::get_u64(ea) {
                Ok(v) => {
                    assert_eq!(rc64, 1, "get_u64 Ok but raw failed at {ea:#x}");
                    assert_eq!(v, out64, "get_u64 value disagrees at {ea:#x}");
                }
                Err(_) => assert_eq!(rc64, 0, "get_u64 Err but raw succeeded at {ea:#x}"),
            }

            // Byte-range read: the first 4 bytes of the item vs raw get_bytes.
            let mut rawbuf = [0u8; 4];
            // SAFETY: buffer of 4 bytes.
            let rr = unsafe {
                sys::idakit_get_bytes(ea, rawbuf.as_mut_ptr() as *mut c_void, rawbuf.len())
            };
            match sys::get_bytes(ea, rawbuf.len()) {
                Ok(v) => {
                    assert!(rr >= 0, "get_bytes Ok but raw failed at {ea:#x}");
                    assert_eq!(&v[..], &rawbuf[..], "get_bytes disagrees at {ea:#x}");
                }
                Err(_) => assert!(rr < 0, "get_bytes Err but raw succeeded at {ea:#x}"),
            }

            // Comment read: the generated Result<String> vs the raw (-1 when none) buffer path.
            let mut cbuf = [0u8; 4096];
            // SAFETY: valid buffer.
            let cl =
                unsafe { sys::idakit_get_cmt(ea, 0, cbuf.as_mut_ptr() as *mut c_char, cbuf.len()) };
            match sys::get_cmt(ea, false) {
                Ok(s) => {
                    assert!(
                        cl >= 0 && (cl as usize) <= cbuf.len(),
                        "get_cmt Ok but raw none/oversized at {ea:#x}"
                    );
                    assert_eq!(
                        s.as_bytes(),
                        &cbuf[..cl as usize],
                        "get_cmt disagrees at {ea:#x}"
                    );
                }
                Err(_) => assert!(cl < 0, "get_cmt Err but raw had one at {ea:#x}"),
            }
        }
        println!(
            "cxx bytes cross-check OK: typed reads, range reads, navigation, and comments agree with raw over {sample} functions"
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
