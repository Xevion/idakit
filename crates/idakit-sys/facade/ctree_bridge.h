// Declarations for the cxx extern "Rust" opaque-visitor ctree walk (namespace bridge). cxx
// emits the shim that calls cfunc_walk_ctree and expects this header (named by the bridge's
// include!) to declare it; the generated glue and the hand-written driver in ctree_bridge.cpp both
// include it.
#pragma once

#include <cstddef>
#include <cstdint>

// Full SDK definition of cfuncptr_t (qrefcnt_t<cfunc_t>): the visitor bridge's own CFunc alias
// re-emits cxx's layout check against ::cfuncptr_t (as bridge_qvec does for its aliased FlowChart),
// so the type must be complete here, not just forward declared.
#include <pro.h>

#include <ida.hpp>

#include <funcs.hpp>
#include <hexrays.hpp>

#include "rust/cxx.h"
#include "trycatch.h"

namespace bridge {

// The extern "Rust" opaque ctree visitor, defined by the generated header (gen_visitors.h) with a
// member function per node/statement/local kind. Forward-declared here so the driver signature can
// name it by reference; ctree_bridge.cpp includes the generated header for the full class.
struct CtreeVisitor;

// Walk cfunc's ctree, minting nodes and locals through `nodes` and node types through the shared
// tinfo walker at `type_visitor` (an address, since cxx has no c_void); returns the root statement
// handle.
uint32_t cfunc_walk_ctree(const ::cfuncptr_t &cfunc, CtreeVisitor &nodes, size_t type_visitor);

} // namespace bridge
