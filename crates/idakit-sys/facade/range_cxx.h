#pragma once

#include <cstddef>
#include <cstdint>

// range_t must be a complete type here: cxx maps the Trivial ExternType `RangeT` to ::range_t,
// so the generated bridge header (which includes this one) needs the full definition to lay out
// the ChunkInfo shared struct's by-value `range` field and to instantiate rust::Vec<range_t>.
#include <pro.h>

#include <ida.hpp>

#include <range.hpp>

#include "rust/cxx.h"

namespace idakit_cxx {

// The cxx shared struct, defined by the generated header. Forward-declared so the declarations
// below can name it by value; range_cxx.cc includes the generated header for the full definition.
struct ChunkInfo;

::range_t range_entry_chunk(uint64_t ea);
uint64_t range_size(::range_t r);
ChunkInfo range_chunk_info(uint64_t ea, size_t n);
rust::Vec<::range_t> range_all_chunks(uint64_t ea);

} // namespace idakit_cxx
