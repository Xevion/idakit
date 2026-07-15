// Declarations for the cxx probe bridge. The bodies live in testonly_probe.cpp; the
// cxx-generated shim (from src/bridge_probe.rs) calls them by their bridge-namespaced name, so
// they are declared here for both the generated glue and the hand-written .cc to include.
#pragma once

#include <cstdint>
#include <memory>

#include "rust/cxx.h"

// The DropProbe opaque type: a real type whose out-of-line destructor bumps a counter, so a
// test can observe cxx's UniquePtr drop invoking the C++ deleter. Defined completely here (not
// forward-declared) because cxx's UniquePtr glue instantiates std::unique_ptr<DropProbe> in its
// own generated TU. Named at global scope and aliased into bridge, so cxx's own
// `using DropProbe = ::bridge::DropProbe;` is a legal identical re-typedef rather than a
// clash with a same-named class (see the FlowChart/qflow_chart_t pattern in cfg_cxx.h).
struct drop_probe_t {
  ~drop_probe_t();
};

namespace bridge {

using DropProbe = ::drop_probe_t;

rust::String probe_throw(int32_t kind);
std::unique_ptr<DropProbe> drop_probe_make();
uint32_t drop_probe_count();

} // namespace bridge
