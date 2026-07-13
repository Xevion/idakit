use super::super::model::*;
use super::{CF, EA};

/// The Hex-Rays decompiler domain: the SDK's `cfuncptr_t` (`qrefcnt_t<cfunc_t>`) bound as an
/// `Opaque` `ExternType` ([`CFunc`]) owned by [`UniquePtr`](cxx::UniquePtr), so its cxx deleter runs
/// `~cfuncptr_t` (`release()`) on drop, retiring the raw `new`/`delete` handle dance. `decompile`
/// wraps the microcode pipeline in the facade's `guarded<>` trap and throws on failure; the read
/// accessors take a borrowed `&CFunc` and return pseudocode, ctree counts, and the extraction-gap
/// diagnostic. The ctree walk itself is a separate hand-written `cxx` bridge (`bridge_visitors`) fed
/// the same `&CFunc`. Bodies are in `facade/hexrays_custom.cc`.
pub const HEXRAYS: Domain = Domain {
    name: "hexrays",
    // funcs.hpp (pulling bytes.hpp/xref.hpp) precedes hexrays.hpp so the generated header is
    // self-sufficient: hexrays.hpp names casevec_t from xref.hpp, and gen_bridge.h pulls this
    // header into every domain TU.
    sdk_includes: &["<funcs.hpp>", "<hexrays.hpp>"],
    externs: &[ExternTy {
        rust_name: "CFunc",
        cxx_name: "cfuncptr_t",
        kind: ExternKind::Opaque,
        doc: "The SDK's `cfuncptr_t` (`qrefcnt_t<cfunc_t>`), an opaque decompilation result \
              handled only behind indirection (`&CFunc` or `UniquePtr<CFunc>`).",
        safety: "The type id names the real SDK typedef cfuncptr_t; Opaque is correct because \
                 qrefcnt_t<cfunc_t> has a nontrivial copy-ctor and destructor, so it may only cross \
                 the bridge behind a reference or UniquePtr, never by value.",
    }],
    structs: &[
        SharedStruct {
            name: "CtreeCounts",
            doc: "Statement, expression, and call-site counts of a decompiled function's ctree, \
                  returned by value from [`cfunc_counts`].",
            fields: fields! {
                insns: I32 = "Number of statement nodes.";
                expressions: I32 = "Number of expression nodes.";
                calls: I32 = "Number of call sites.";
            },
        },
        SharedStruct {
            name: "ExprGap",
            doc: "The ctree extraction-fidelity diagnostic, returned by value from \
                  [`cfunc_expr_gap`].",
            fields: fields! {
                visitor_total: I32 = "Every expression the SDK's own ctree visitor sees.";
                expected: I32 = "How many the extraction walker should materialize (visitor total minus \
                          elided empty-expression placeholders in optional slots).";
            },
        },
    ],
    custom_tu: Some("facade/hexrays_custom.cc"),
    body_helpers: None,
    fns: &[
        FnSpec {
            name: "decompile",
            receiver: None,
            args: EA,
            ret: RetKind::ResultUniquePtr("CFunc"),
            body: BodyKind::Custom,
            doc: "Decompile the function at `ea` into a heap `cfuncptr_t` owned by a \
                  [`UniquePtr`](cxx::UniquePtr) (one owned ref); `Err` on any decompile failure. \
                  Wrapped in the facade trap, so a fatal `exit()` surfaces as a trapped `Err` the \
                  caller distinguishes via its own trap query. The `UniquePtr`'s cxx deleter runs \
                  `~cfuncptr_t` (`release()`) on drop.",
        },
        FnSpec {
            name: "cfunc_pseudocode",
            receiver: None,
            args: CF,
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "The rendered pseudocode of `cf`, tags stripped; `Err` if the SDK cannot produce \
                  it.",
        },
        FnSpec {
            name: "cfunc_counts",
            receiver: None,
            args: CF,
            ret: RetKind::Shared("CtreeCounts"),
            body: BodyKind::Custom,
            doc: "Statement, expression, and call-site counts of `cf`'s ctree.",
        },
        FnSpec {
            name: "cfunc_refresh_text",
            receiver: None,
            args: CF,
            ret: RetKind::ResultString,
            body: BodyKind::Custom,
            doc: "Re-print `cf`'s pseudocode from its current ctree (`refresh_func_ctext`), then \
                  return it; `Err` if the SDK cannot produce it. Cheap compared to a re-decompile, \
                  since it walks the already-decompiled ctree, but reflects only what the ctree \
                  already encodes (a rename resolves fresh; a structural or type change needs a \
                  fresh [`decompile`]).",
        },
        FnSpec {
            name: "cfunc_expr_gap",
            receiver: None,
            args: CF,
            ret: RetKind::Shared("ExprGap"),
            body: BodyKind::Custom,
            doc: "The extraction-fidelity diagnostic for `cf`: total expressions the SDK visitor \
                  sees vs how many the extraction walker should materialize.",
        },
        FnSpec {
            name: "hexrays_init",
            receiver: None,
            args: &[],
            ret: RetKind::Bool,
            body: BodyKind::Custom,
            doc: "Initialize the Hex-Rays decompiler (loading the plugin if needed); `true` once \
                  ready.",
        },
        FnSpec {
            name: "mark_cfunc_dirty",
            receiver: None,
            args: args!(ea: U64, close_views: Bool),
            ret: RetKind::Bool,
            body: BodyKind::Custom,
            doc: "Evict the cached decompilation for `ea`; `true` if an entry existed, `false` if \
                  none or the decompiler is not initialized.",
        },
        FnSpec {
            name: "clear_cached_cfuncs",
            receiver: None,
            args: &[],
            ret: RetKind::Unit,
            body: BodyKind::Custom,
            doc: "Evict every cached decompilation; a no-op if the decompiler is not initialized.",
        },
        FnSpec {
            name: "has_cached_cfunc",
            receiver: None,
            args: EA,
            ret: RetKind::Bool,
            body: BodyKind::Custom,
            doc: "Whether `ea` has a cached decompilation; `false` if none or not initialized.",
        },
    ],
};
