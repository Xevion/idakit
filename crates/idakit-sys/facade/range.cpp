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

::range_t range_entry_chunk(uint64_t ea) {
  func_t *pfn = get_func((ea_t)ea);
  if (pfn == nullptr)
    throw std::out_of_range("no function at address");
  func_tail_iterator_t fti(pfn);
  if (!fti.main())
    throw std::out_of_range("function has no entry chunk");
  return fti.chunk(); // const range_t& -> by-value copy across the bridge
}

uint64_t range_size(::range_t r) { return (uint64_t)r.size(); }

ChunkInfo range_chunk_info(uint64_t ea, size_t n) {
  func_t *pfn = get_func((ea_t)ea);
  if (pfn == nullptr)
    throw std::out_of_range("no function at address");
  func_tail_iterator_t fti(pfn);
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

rust::Vec<::range_t> range_all_chunks(uint64_t ea) {
  func_t *pfn = get_func((ea_t)ea);
  if (pfn == nullptr)
    throw std::out_of_range("no function at address");
  rust::Vec<::range_t> out;
  func_tail_iterator_t fti(pfn);
  for (bool ok = fti.main(); ok; ok = fti.next())
    out.push_back(fti.chunk());
  return out;
}

} // namespace gen
