// Declarations for the cxx extern "Rust" opaque-visitor ctree walk (namespace idakit_cxx). cxx
// emits the shims that call cfunc_walk_ctree / hexrays_init / etc. and expects this header (named
// by the bridge's include!) to declare them; the generated glue and the hand-written driver in
// ctree_cxx.cc both include it.
#pragma once

#include <cstddef>
#include <cstdint>

// Full SDK definition of cfuncptr_t (qrefcnt_t<cfunc_t>): this bridge's own CFunc alias re-emits
// cxx's layout check against ::cfuncptr_t (see bridge_cfg_check's FlowChart precedent), so the type
// must be complete here, not just forward declared.
#include <pro.h>

#include <ida.hpp>

#include <funcs.hpp>
#include <hexrays.hpp>

#include "idakit_trycatch.h"
#include "rust/cxx.h"

namespace idakit_cxx {

// The extern "Rust" opaque ctree visitor, defined by the generated header (bridge_ctree.rs.h) with
// a member function per node/statement/local kind. Forward-declared here so the driver signature
// can name it by reference; ctree_cxx.cc includes the generated header for the full class.
struct CtreeVisitor;

bool hexrays_init();
bool mark_cfunc_dirty(uint64_t ea, bool close_views);
void clear_cached_cfuncs();
bool has_cached_cfunc(uint64_t ea);

// Walk cfunc's ctree, minting nodes and locals through `nodes` and node types through the shared
// tinfo walker at `type_visitor` (an address, since cxx has no c_void); returns the root statement
// handle.
uint32_t cfunc_walk_ctree(const ::cfuncptr_t &cfunc, CtreeVisitor &nodes, size_t type_visitor);

} // namespace idakit_cxx
