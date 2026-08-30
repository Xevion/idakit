// Hand-written Custom bodies for the generated range domain (namespace gen). range_t is a
// Trivial ExternType, so it crosses the cxx bridge by value in every direction: returned bare,
// taken by value, embedded in the ChunkInfo shared struct, and collected into an owned
// rust::Vec<range_t>. A missing function or an out-of-range chunk index throws, surfacing as a
// Rust Err.

#include <ida.hpp>
#include <pro.h>

#include <funcs.hpp> // function_tail_iterator_t
#include <range.hpp>

#include <stdexcept>

#include "gen_range.h"
// The cxx-generated header defines the ChunkInfo shared struct (full definition needed to construct
// it) and instantiates rust::Vec<range_t>; gen_range.h only forward-declares ChunkInfo.
#include "gen_bridge.h"

#include "compat.h"

namespace gen {

// The entry (main) chunk of the function at addr; throws if there's no function there or it has
// no entry chunk.
::range_t range_entry_chunk(uint64_t addr) {
  function_tail_iterator_t fti;
  if (!fti.set(static_cast<ea_t>(addr)))
    throw std::out_of_range("no function at address");
  if (!fti.main())
    throw std::out_of_range("function has no entry chunk");
  ::range_t chunk;
  fti.chunk(&chunk);
  return chunk;
}

// The byte length of range (end_ea - start_ea).
uint64_t range_size(::range_t range) { return static_cast<uint64_t>(range.size()); }

// The n-th chunk (entry chunk first, then tails) of the function at addr, paired with its index
// in ChunkInfo; throws if there's no function at addr or n is out of range.
ChunkInfo range_chunk_info(uint64_t addr, size_t n) {
  function_tail_iterator_t fti;
  if (!fti.set(static_cast<ea_t>(addr)))
    throw std::out_of_range("no function at address");
  size_t i = 0;
  for (bool ok = fti.main(); ok; ok = fti.next(), i++) {
    if (i == n) {
      ChunkInfo info;
      info.index = n;
      fti.chunk(&info.range);
      return info;
    }
  }
  throw std::out_of_range("chunk index out of range");
}

// Every chunk of the function at addr (entry chunk first, then tails), collected into an owned
// Vec; throws if there's no function at addr.
rust::Vec<::range_t> range_all_chunks(uint64_t addr) {
  function_tail_iterator_t fti;
  if (!fti.set(static_cast<ea_t>(addr)))
    throw std::out_of_range("no function at address");
  rust::Vec<::range_t> out;
  ::range_t chunk;
  for (bool ok = fti.main(); ok; ok = fti.next()) {
    fti.chunk(&chunk);
    out.push_back(chunk);
  }
  return out;
}

} // namespace gen
