// Declarations for the cxx-bridged segment facade. cxx does not synthesize declarations for
// `extern "C++"` free functions; it emits the shim that calls them and expects this header
// (named by the bridge's `include!`) to declare them. Both the generated glue and the
// hand-written bodies in segment_cxx.cc include it.
#pragma once

#include <cstddef>
#include <cstdint>

#include "rust/cxx.h"

namespace idakit_cxx {

size_t seg_qty();
uint64_t seg_start(int32_t n);
uint64_t seg_end(int32_t n);
int32_t seg_perm(int32_t n);
int32_t seg_bitness(int32_t n);
rust::String seg_name(int32_t n);
rust::String seg_class(int32_t n);

} // namespace idakit_cxx
