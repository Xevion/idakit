//! Sentinels shared with the raw (non-domain) facade TUs: the visitor bridge's absent-child
//! marker and the fatal-exit trap's result/kind codes. None of these belongs to a single
//! [`super::model::Domain`] (they're used by `runtime.cpp`, `probe_cxx.cc`, and the visitor
//! bridge's `ctree_cxx.cc`/`typewalk_cxx.cc`), so they're generated from this standalone list
//! into `gen_facade_consts.h` instead of a per-domain header.

use super::model::{ConstDef, ConstTy};

/// Every public facade sentinel with no owning domain, generated to both faces by
/// [`super::emit::facade_consts_tokens`] (Rust, a plain `pub const`) and
/// [`super::emit::facade_consts_header_source`] (the `gen_facade_consts.h` C++ header, alongside
/// [`HIDDEN_FACADE_CONSTS`]).
pub const FACADE_CONSTS: &[ConstDef] = &[
    ConstDef {
        name: "NONE",
        ty: ConstTy::U32,
        value: 0xFFFF_FFFF,
        doc: "Absent optional child / sentinel for the visitor bridge (ctree and tinfo walks).",
    },
    ConstDef {
        name: "EXIT_TRAPPED",
        ty: ConstTy::I32,
        value: -0x7FFF_FFFF,
        doc: "Sentinel rc a guarded call returns when it trapped a fatal `exit`/`abort` instead \
              of it tearing down the process.",
    },
];

/// Test-only fault-injection kinds for `test_fatal`/`trigger_fatal`: generated to the Rust face as
/// `#[doc(hidden)]` (see [`super::emit::facade_consts_tokens`]), keeping them off the public API
/// exactly as the hand-written consts they replace were, and to the C++ face as an ordinary
/// `constexpr` alongside [`FACADE_CONSTS`] (the C++ side has no visibility distinction to preserve).
pub const HIDDEN_FACADE_CONSTS: &[ConstDef] = &[
    ConstDef {
        name: "FATAL_EXIT",
        ty: ConstTy::I32,
        value: 0,
        doc: "`test_fatal`/`trigger_fatal` kind: run `exit()` inside the guarded call.",
    },
    ConstDef {
        name: "FATAL_ABORT",
        ty: ConstTy::I32,
        value: 1,
        doc: "`test_fatal`/`trigger_fatal` kind: run `abort()` inside the guarded call.",
    },
    ConstDef {
        name: "FATAL_INTERR",
        ty: ConstTy::I32,
        value: 2,
        doc: "`test_fatal`/`trigger_fatal` kind: run `interr()` inside the guarded call.",
    },
];
