// Hand-written Custom bodies for the generated control-flow-graph domain (namespace gen).
// FlowChart is the SDK's qflow_chart_t, owned through std::unique_ptr, so cxx's UniquePtr deleter
// retires the raw free plus Rust Drop. size() is a plain self-member call bound straight to the
// SDK member, so it has no body here. A missing function or an out-of-range block/edge index
// throws, surfacing as a Rust Err.

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

// Builds the control-flow graph of the function at addr, owned by the returned handle; throws if
// there's no function there.
std::unique_ptr<::qflow_chart_t> cfg_build(uint64_t addr, int32_t flags) {
  func_t *func = get_func(static_cast<ea_t>(addr));
  if (func == nullptr)
    throw std::out_of_range("no function at address");
  return std::make_unique<::qflow_chart_t>("", func, BADADDR, BADADDR, flags);
}

// The total number of basic blocks in flow.
size_t cfg_nblocks(const ::qflow_chart_t &flow) { return flow.blocks.size(); }

// The number of blocks that fall within the function's own range, as opposed to blocks pulled in
// from elsewhere.
size_t cfg_nproper(const ::qflow_chart_t &flow) { return static_cast<size_t>(flow.nproper); }

// The n-th basic block's start/end addresses and kind, wrapped in BlockInfo; throws if n is out of
// range.
BlockInfo cfg_block(const ::qflow_chart_t &flow, size_t n) {
  if (n >= flow.blocks.size())
    throw std::out_of_range("block index out of range");
  const qbasic_block_t &block = flow.blocks[n];
  BlockInfo info;
  info.start = static_cast<uint64_t>(block.start_ea);
  info.end = static_cast<uint64_t>(block.end_ea);
  info.kind = static_cast<int32_t>(flow.calc_block_type(n));
  return info;
}

// The number of successor edges from block n; 0 (not a throw) if n itself is out of range.
size_t cfg_nsucc(const ::qflow_chart_t &flow, size_t n) {
  if (n >= flow.blocks.size())
    return 0;
  return static_cast<size_t>(flow.nsucc(static_cast<int>(n)));
}

// The i-th successor block index of block n; throws if n or i is out of range.
size_t cfg_succ(const ::qflow_chart_t &flow, size_t n, size_t i) {
  if (n >= flow.blocks.size() || i >= static_cast<size_t>(flow.nsucc(static_cast<int>(n))))
    throw std::out_of_range("successor index out of range");
  return static_cast<size_t>(flow.succ(static_cast<int>(n), static_cast<int>(i)));
}

// The number of predecessor edges into block n; 0 (not a throw) if n itself is out of range.
size_t cfg_npred(const ::qflow_chart_t &flow, size_t n) {
  if (n >= flow.blocks.size())
    return 0;
  return static_cast<size_t>(flow.npred(static_cast<int>(n)));
}

// The i-th predecessor block index of block n; throws if n or i is out of range.
size_t cfg_pred(const ::qflow_chart_t &flow, size_t n, size_t i) {
  if (n >= flow.blocks.size() || i >= static_cast<size_t>(flow.npred(static_cast<int>(n))))
    throw std::out_of_range("predecessor index out of range");
  return static_cast<size_t>(flow.pred(static_cast<int>(n), static_cast<int>(i)));
}

// Every successor block index of block n, copied out of the intvec_t into an owned Vec with no
// lifetime tie to flow; throws if n is out of range.
rust::Vec<uint32_t> cfg_succs(const ::qflow_chart_t &flow, size_t n) {
  if (n >= flow.blocks.size())
    throw std::out_of_range("block index out of range");
  const intvec_t &succs = flow.blocks[n].succ;
  rust::Vec<uint32_t> out;
  out.reserve(succs.size());
  for (int succ : succs)
    out.push_back(static_cast<uint32_t>(succ));
  return out;
}

// Every predecessor block index of block n, copied out of the intvec_t into an owned Vec with no
// lifetime tie to flow; throws if n is out of range.
rust::Vec<uint32_t> cfg_preds(const ::qflow_chart_t &flow, size_t n) {
  if (n >= flow.blocks.size())
    throw std::out_of_range("block index out of range");
  const intvec_t &preds = flow.blocks[n].pred;
  rust::Vec<uint32_t> out;
  out.reserve(preds.size());
  for (int pred : preds)
    out.push_back(static_cast<uint32_t>(pred));
  return out;
}

} // namespace gen
