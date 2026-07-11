// cxx-bridged second flow-chart accessor (namespace idakit_cxx). Its only purpose is to prove
// cross-bridge ExternType sharing: it takes a const qflow_chart_t& built by the cfg bridge's
// cfg_build and sums each block's successor count. Because both bridges bind the same
// ::qflow_chart_t ExternType, the Rust FlowChart is one type across both, no conversion needed.

#include <pro.h>

#include <ida.hpp>

#include <gdl.hpp>

#include "cfg2_cxx.h"

namespace idakit_cxx {

size_t cfg2_total_edges(const ::qflow_chart_t &fc) {
  size_t total = 0;
  for (size_t n = 0; n < fc.blocks.size(); n++)
    total += (size_t)fc.nsucc((int)n);
  return total;
}

} // namespace idakit_cxx
