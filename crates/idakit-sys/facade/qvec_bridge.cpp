// cxx-bridged qvector<T> facade (namespace bridge): the KDAB per-instantiation
// recipe applied to two of IDA's own generic containers. intvec_t (qvector<int>)
// and rangevec_t (qvector<range_t>) are each bound as a cxx Opaque ExternType and
// read two ways: a copying shim to an owned rust::Vec, and a zero-copy rust::Slice
// borrowed from the container's {array, n} (never touching alloc/qalloc/qfree;
// Rust only reads). The cross-check in roundtrip.rs proves both agree with the
// existing per-index / raw-facade paths.

#include <pro.h>

#include <ida.hpp>

#include <funcs.hpp> // get_func, func_tail_iterator_t
#include <gdl.hpp>
#include <range.hpp>

#include <stdexcept>

#include "qvec_bridge.h"

// The recipe's "explicit instantiation to force the symbols" step (template class
// qvector<range_t>;) does NOT compile here: it instantiates *every* member, and
// qvector<T>::resize_noinit carries CASSERT(is_trivially_constructible<T>), which
// range_t (user-declared ctors) fails. qvector's members are all inline in pro.h,
// so use-based implicit instantiation emits exactly the members we call
// (push_back/size/begin/empty/ctor/dtor) and none of the asserting ones, which is
// all we need. So no explicit instantiation is used.

// int is 32-bit on every target this crate builds (LP64 / LLP64), so an intvec_t's
// backing array is bit-identical to a [i32]; the zero-copy slice cast below relies on it.
static_assert(sizeof(int) == sizeof(std::int32_t), "intvec_t element is not 32-bit");

namespace bridge {

const intvec_t &cfg_succ_vec(const ::qflow_chart_t &flow, size_t n) {
  if (n >= flow.blocks.size())
    throw std::out_of_range("block index out of range");
  return flow.blocks[n].succ;
}

size_t intvec_len(const intvec_t &v) { return v.size(); }

rust::Vec<std::int32_t> intvec_copy(const intvec_t &v) {
  rust::Vec<std::int32_t> out;
  out.reserve(v.size());
  for (int x : v)
    out.push_back(static_cast<std::int32_t>(x));
  return out;
}

rust::Slice<const std::int32_t> intvec_slice(const intvec_t &v) {
  if (v.empty())
    return {};
  // Zero-copy: borrow {array (== begin()), n (== size())}. begin() on a const
  // qvector returns the const T* backing pointer; alloc is never read.
  return rust::Slice<const std::int32_t>(reinterpret_cast<const std::int32_t *>(v.begin()),
                                         v.size());
}

std::unique_ptr<rangevec_t> rangevec_build_chunks(std::uint64_t addr) {
  func_t *pfn = get_func(static_cast<ea_t>(addr));
  if (pfn == nullptr)
    throw std::out_of_range("no function at address");
  auto out = std::make_unique<rangevec_t>();
  func_tail_iterator_t fti(pfn);
  for (bool ok = fti.main(); ok; ok = fti.next())
    out->push_back(fti.chunk());
  return out;
}

size_t rangevec_len(const rangevec_t &v) { return v.size(); }

rust::Slice<const ::range_t> rangevec_slice(const rangevec_t &v) {
  if (v.empty())
    return {};
  return rust::Slice<const ::range_t>(v.begin(), v.size());
}

} // namespace bridge
