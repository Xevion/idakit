//! The declarative manifest for the ctree/tinfo `extern "Rust"` opaque-visitor bridge.
//!
//! [`VISITOR_BRIDGE`] pairs the ctree walk's [`CtreeSink`](VisitorSink)-shaped spec with the tinfo
//! type walk's, plus the shared `extern "C++"` driver block both are called through. The engine
//! that turns this into the Rust bridge and the C++ shim glue lives in the sibling `emit` module;
//! the hand-written C++ drivers stay in `facade/ctree_bridge.cpp` / `facade/typewalk_bridge.cpp`.
//!
//! The `args!` / `fields!` / `methods!` DSL macros used below are defined in the parent `dsl`
//! module (they author every spec's arg and field slices, not just this one). The ctree and tinfo
//! sinks each live in their own sibling module ([`ctree`], [`typewalk`]).

mod ctree;
mod typewalk;

use super::model::*;
use ctree::{CTREE_SINK, LOC_PIECE};
use typewalk::{ENUM_CONST_INFO, FRAME_VAR, FRAME_WALK, MEMBER_INFO, TYPE_WALK_SINK};

/// The visitor bridge's `extern "C++"` driver block: the four standalone type-walk entry points
/// plus the ctree walk's `cfunc_walk_ctree`, all hand-written in `facade/ctree_bridge.cpp` /
/// `facade/typewalk_bridge.cpp`.
const DRIVERS: &[VisitorDriverFn] = &[
    VisitorDriverFn {
        name: "cfunc_walk_ctree",
        doc: "Walk `cfunc`'s ctree, minting nodes and locals through `nodes` and node types \
              through the tinfo walker whose pointer is passed as an integer address in \
              `type_visitor` (`cxx` has no `c_void`; the C++ side reinterprets it back to `void*` \
              for the shared type walker). Returns the root statement handle.\n\n# Safety\n\
              `type_visitor` must be a live `TypeWalkVisitor*`, cast to `usize`, that outlives \
              the call.",
        args: args!(cfunc: ExternRef("CFunc"), nodes: VisitorMut("CtreeVisitor"), type_visitor: Usize),
        ret: ret!(U32),
        unsafe_: true,
    },
    VisitorDriverFn {
        name: "type_walk_visit_named",
        doc: "Walk the local type named `name`, driving `visitor`'s methods per node; returns the \
              root handle. `Err` when no such type exists (or a thrown SDK error).",
        args: args!(name: Str, visitor: VisitorMut("TypeWalkVisitor")),
        ret: ret!(ResultU32),
        unsafe_: false,
    },
    VisitorDriverFn {
        name: "type_walk_visit_ordinal",
        doc: "Walk the local type at `ordinal`, driving `visitor`'s methods per node; returns the \
              root handle. `Err` when no type occupies the ordinal (or a thrown SDK error).",
        args: args!(ordinal: U32, visitor: VisitorMut("TypeWalkVisitor")),
        ret: ret!(ResultU32),
        unsafe_: false,
    },
    VisitorDriverFn {
        name: "func_type_walk_visit",
        doc: "Walk the stored prototype of the function at `ea`, driving `visitor`; returns the \
              root handle. `Err` when the function has no type info.",
        args: args!(ea: U64, visitor: VisitorMut("TypeWalkVisitor")),
        ret: ret!(ResultU32),
        unsafe_: false,
    },
    VisitorDriverFn {
        name: "frame_type_walk_visit",
        doc: "Walk the stack frame of the function at `ea`: each variable's type through \
              `visitor`, returning the frame size and variables. `Err` when there is no function \
              or frame at `ea`.",
        args: args!(ea: U64, visitor: VisitorMut("TypeWalkVisitor")),
        ret: ret!(ResultShared("FrameWalk")),
        unsafe_: false,
    },
];

/// The whole visitor bridge, built once: the five shared structs, the ctree and tinfo sink pairs,
/// and the shared driver block.
pub const VISITOR_BRIDGE: VisitorBridge = VisitorBridge {
    structs: &[
        LOC_PIECE,
        MEMBER_INFO,
        ENUM_CONST_INFO,
        FRAME_VAR,
        FRAME_WALK,
    ],
    sinks: &[CTREE_SINK, TYPE_WALK_SINK],
    drivers: DRIVERS,
};
