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
// (qbasic_block_t::succ). cfg_succ_vec borrows the list out of the live
// qflow_chart_t; the returned reference is valid only while that fc is borrowed.
const intvec_t &cfg_succ_vec(const ::qflow_chart_t &fc, size_t n);
size_t intvec_len(const intvec_t &v);
rust::Vec<std::int32_t> intvec_copy(const intvec_t &v);
rust::Slice<const std::int32_t> intvec_slice(const intvec_t &v);

// qvector<range_t> == rangevec_t. Built here and owned by a unique_ptr, so the
// zero-copy slice borrows from a container whose lifetime Rust controls.
std::unique_ptr<rangevec_t> rangevec_build_chunks(std::uint64_t ea);
size_t rangevec_len(const rangevec_t &v);
rust::Slice<const ::range_t> rangevec_slice(const rangevec_t &v);

} // namespace bridge
