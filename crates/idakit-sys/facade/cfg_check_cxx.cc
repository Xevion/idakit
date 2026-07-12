// cxx-bridged cross-bridge shared-ExternType validation (namespace idakit_cxx). Its only purpose is
// to prove a hand-written bridge can share the generated FlowChart/qflow_chart_t ExternType: it
// takes a const qflow_chart_t& built by the generated cfg_build and sums each block's successor
// count. Because both bridges bind the same ::qflow_chart_t ExternType, the Rust FlowChart is one
// type across both, no conversion needed. Consumed only by roundtrip.rs.

#include <pro.h>

#include <ida.hpp>

#include <gdl.hpp>

#include "cfg_check_cxx.h"

namespace idakit_cxx {

size_t cfg_total_edges_check(const ::qflow_chart_t &fc) {
  size_t total = 0;
  for (size_t n = 0; n < fc.blocks.size(); n++)
    total += (size_t)fc.nsucc((int)n);
  return total;
}

} // namespace idakit_cxx
