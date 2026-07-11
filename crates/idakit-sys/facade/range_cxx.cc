// cxx-bridged range_t facade (namespace idakit_cxx). range_t is the SDK POD exposed as a cxx
// Trivial ExternType (RangeT), so it crosses the bridge by value: returned bare, taken as an
// argument, carried by value inside the ChunkInfo shared struct, and collected into an owned
// rust::Vec<range_t>. This coexists with the raw idakit_func_chunk out-param facade; the cross-
// check in roundtrip.rs proves the two paths agree. Out-of-range indices throw -> Rust Err.

#include <pro.h>

#include <ida.hpp>

#include <funcs.hpp> // get_func, func_tail_iterator_t
#include <range.hpp>

#include <stdexcept>

#include "range_cxx.h"
// The generated header defines the ChunkInfo shared struct (full definition needed to construct
// it) and instantiates rust::Vec<range_t>; range_cxx.h only forward-declares ChunkInfo.
#include "idakit-sys/src/bridge_range.rs.h"

namespace idakit_cxx {

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

} // namespace idakit_cxx
