// Declarations for the cxx-bridged qvector<T> facade (namespace bridge): two of IDA's own generic
// containers, intvec_t and rangevec_t, each bound as a cxx Opaque ExternType and readable both as
// a copying rust::Vec and as a zero-copy rust::Slice borrowed from the container's own backing
// array. The generated glue and the hand-written driver in qvec_bridge.cpp both include this
// header.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

// The two qvector<T> instantiations bound here name real global SDK types,
// intvec_t (typedef qvector<int>) and rangevec_t (struct : qvector<range_t>),
// so cxx names them with no local `using` alias. Both must be complete here:
// cxx's UniquePtr glue instantiates std::unique_ptr<rangevec_t> in its own
// generated TU, which sees only this header.
#include <pro.h>

#include <ida.hpp>

#include <gdl.hpp>   // qflow_chart_t (the intvec_t source)
#include <range.hpp> // range_t, rangevec_t

#include "rust/cxx.h"
#include "trycatch.h"

namespace bridge {

// qvector<int> == intvec_t. Source: a flow-chart block's successor edge list
// (qbasic_block_t::succ). Borrows the list out of the live flow; the returned reference is valid
// only while that flow is borrowed. Throws if n is out of range.
const intvec_t &cfg_succ_vec(const ::qflow_chart_t &flow, size_t n);
// Element count.
size_t intvec_len(const intvec_t &v);
// Copy every element into an owned rust::Vec.
rust::Vec<std::int32_t> intvec_copy(const intvec_t &v);
// Borrow the backing array as a slice with no copy; empty for an empty vector.
rust::Slice<const std::int32_t> intvec_slice(const intvec_t &v);

// qvector<range_t> == rangevec_t. Builds the address range of every tail chunk of the function at
// addr into a fresh vector, owned by a unique_ptr so the zero-copy slice below can borrow from a
// container whose lifetime Rust controls. Throws if no function exists at addr.
std::unique_ptr<rangevec_t> rangevec_build_chunks(std::uint64_t addr);
// Element count.
size_t rangevec_len(const rangevec_t &v);
// Borrow the backing array as a slice with no copy; empty for an empty vector.
rust::Slice<const ::range_t> rangevec_slice(const rangevec_t &v);

} // namespace bridge
