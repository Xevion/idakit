// Declarations for the cxx probe bridge. The bodies live in probe_cxx.cc; the
// cxx-generated shim (from src/bridge_probe.rs) calls them by their idakit_cxx-namespaced name, so
// they are declared here for both the generated glue and the hand-written .cc to include.
#pragma once

#include <cstdint>
#include <memory>

#include "rust/cxx.h"

// The DropProbe opaque type: a real type whose out-of-line destructor bumps a counter, so a
// test can observe cxx's UniquePtr drop invoking the C++ deleter. Defined completely here (not
// forward-declared) because cxx's UniquePtr glue instantiates std::unique_ptr<DropProbe> in its
// own generated TU. Named at global scope and aliased into idakit_cxx, so cxx's own
// `using DropProbe = ::idakit_cxx::DropProbe;` is a legal identical re-typedef rather than a
// clash with a same-named class (see the FlowChart/qflow_chart_t pattern in cfg_cxx.h).
struct idakit_drop_probe_t {
  ~idakit_drop_probe_t();
};

namespace idakit_cxx {

using DropProbe = ::idakit_drop_probe_t;

rust::String probe_fatal_through_cxx(int32_t kind);
rust::String probe_throw(int32_t kind);
std::unique_ptr<DropProbe> drop_probe_make();
uint32_t drop_probe_count();

} // namespace idakit_cxx
