// Hand-written Custom bodies for the generated range domain (namespace gen). range_t is a
// Trivial ExternType, so it crosses by value: returned bare (range_entry_chunk), taken by value
// (range_size), carried in the ChunkInfo shared struct (range_chunk_info), and collected into an
// owned rust::Vec<range_t> (range_all_chunks). Out-of-range indices throw -> Rust Err.

#include <ida.hpp>
#include <pro.h>

#include <funcs.hpp> // get_func, func_tail_iterator_t
#include <range.hpp>

#include <stdexcept>

#include "gen_range.h"
// The cxx-generated header defines the ChunkInfo shared struct (full definition needed to construct
// it) and instantiates rust::Vec<range_t>; gen_range.h only forward-declares ChunkInfo.
#include "gen_bridge.h"

namespace gen {

::range_t range_entry_chunk(uint64_t addr) {
  func_t *func = get_func(static_cast<ea_t>(addr));
  if (func == nullptr)
    throw std::out_of_range("no function at address");
  func_tail_iterator_t fti(func);
  if (!fti.main())
    throw std::out_of_range("function has no entry chunk");
  return fti.chunk(); // const range_t& -> by-value copy across the bridge
}

uint64_t range_size(::range_t range) { return static_cast<uint64_t>(range.size()); }

ChunkInfo range_chunk_info(uint64_t addr, size_t n) {
  func_t *func = get_func(static_cast<ea_t>(addr));
  if (func == nullptr)
    throw std::out_of_range("no function at address");
  func_tail_iterator_t fti(func);
  size_t i = 0;
  for (bool ok = fti.main(); ok; ok = fti.next(), i++) {
    if (i == n) {
      ChunkInfo info;
      info.index = n;
      info.range = fti.chunk();
      return info;
    }
  }
  throw std::out_of_range("chunk index out of range");
}

rust::Vec<::range_t> range_all_chunks(uint64_t addr) {
  func_t *func = get_func(static_cast<ea_t>(addr));
  if (func == nullptr)
    throw std::out_of_range("no function at address");
  rust::Vec<::range_t> out;
  func_tail_iterator_t fti(func);
  for (bool ok = fti.main(); ok; ok = fti.next())
    out.push_back(fti.chunk());
  return out;
}

} // namespace gen
