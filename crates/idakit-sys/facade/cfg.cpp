// Hand-written Custom bodies for the generated control-flow-graph domain (namespace gen).
// FlowChart is the SDK's qflow_chart_t owned by std::unique_ptr, so cxx's UniquePtr deleter retires
// the raw free + Rust Drop; cfg_block returns the BlockInfo shared struct by value, and the edge
// lists copy into rust::Vec<uint32_t>. size() is a self:-member call bound straight to the SDK
// member, so it has no body here. Out-of-range indices throw and surface as a Rust Err.

#include <ida.hpp>
#include <pro.h>

#include <funcs.hpp>
#include <gdl.hpp>

#include <stdexcept>

#include "gen_cfg.h"
// The generated bridge header defines the BlockInfo shared struct (full definition needed to
// construct it below); gen_cfg.h only forward-declares it.
#include "gen_bridge.h"

namespace gen {

std::unique_ptr<::qflow_chart_t> cfg_build(uint64_t ea, int32_t flags) {
  func_t *pfn = get_func((ea_t)ea);
  if (pfn == nullptr)
    throw std::out_of_range("no function at address");
  return std::make_unique<::qflow_chart_t>("", pfn, BADADDR, BADADDR, flags);
}

size_t cfg_nblocks(const ::qflow_chart_t &fc) { return fc.blocks.size(); }

size_t cfg_nproper(const ::qflow_chart_t &fc) { return (size_t)fc.nproper; }

BlockInfo cfg_block(const ::qflow_chart_t &fc, size_t n) {
  if (n >= fc.blocks.size())
    throw std::out_of_range("block index out of range");
  const qbasic_block_t &b = fc.blocks[n];
  BlockInfo info;
  info.start = (uint64_t)b.start_ea;
  info.end = (uint64_t)b.end_ea;
  info.kind = (int32_t)fc.calc_block_type(n);
  return info;
}

size_t cfg_nsucc(const ::qflow_chart_t &fc, size_t n) {
  if (n >= fc.blocks.size())
    return 0;
  return (size_t)fc.nsucc((int)n);
}

size_t cfg_succ(const ::qflow_chart_t &fc, size_t n, size_t i) {
  if (n >= fc.blocks.size() || i >= (size_t)fc.nsucc((int)n))
    throw std::out_of_range("successor index out of range");
  return (size_t)fc.succ((int)n, (int)i);
}

size_t cfg_npred(const ::qflow_chart_t &fc, size_t n) {
  if (n >= fc.blocks.size())
    return 0;
  return (size_t)fc.npred((int)n);
}

size_t cfg_pred(const ::qflow_chart_t &fc, size_t n, size_t i) {
  if (n >= fc.blocks.size() || i >= (size_t)fc.npred((int)n))
    throw std::out_of_range("predecessor index out of range");
  return (size_t)fc.pred((int)n, (int)i);
}

// Copy the block's succ/pred intvec_t (qvector<int>) into an owned rust::Vec<uint32_t>: one linear
// copy, no lifetime tie to the FlowChart.
rust::Vec<uint32_t> cfg_succs(const ::qflow_chart_t &fc, size_t n) {
  if (n >= fc.blocks.size())
    throw std::out_of_range("block index out of range");
  const intvec_t &succ = fc.blocks[n].succ;
  rust::Vec<uint32_t> out;
  out.reserve(succ.size());
  for (int s : succ)
    out.push_back((uint32_t)s);
  return out;
}

rust::Vec<uint32_t> cfg_preds(const ::qflow_chart_t &fc, size_t n) {
  if (n >= fc.blocks.size())
    throw std::out_of_range("block index out of range");
  const intvec_t &pred = fc.blocks[n].pred;
  rust::Vec<uint32_t> out;
  out.reserve(pred.size());
  for (int p : pred)
    out.push_back((uint32_t)p);
  return out;
}

} // namespace gen
