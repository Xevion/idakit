#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

// FlowChart is the SDK's qflow_chart_t exposed as a cxx opaque type. cxx's UniquePtr glue
// instantiates std::unique_ptr<FlowChart> in its own generated TU, which sees only this
// header, so the SDK definition must be complete here (not merely forward-declared).
#include <pro.h>

#include <ida.hpp>

#include <gdl.hpp>

#include "rust/cxx.h"

namespace idakit_cxx {

// The cxx shared struct, defined by the generated header. Forward-declared here so the
// cfg_block declaration below can name it by value (a declaration may return an incomplete
// type); cfg_cxx.cc includes the generated header for the full definition.
struct BlockInfo;

// The FlowChart ExternType binds ::qflow_chart_t directly (bridge_cfg.rs sets cxx_name +
// namespace), so these signatures name the SDK class with no local alias.
std::unique_ptr<::qflow_chart_t> cfg_build(uint64_t ea, int32_t flags);
size_t cfg_nblocks(const ::qflow_chart_t &fc);
size_t cfg_nproper(const ::qflow_chart_t &fc);
BlockInfo cfg_block(const ::qflow_chart_t &fc, size_t n);
size_t cfg_nsucc(const ::qflow_chart_t &fc, size_t n);
size_t cfg_succ(const ::qflow_chart_t &fc, size_t n, size_t i);
size_t cfg_npred(const ::qflow_chart_t &fc, size_t n);
size_t cfg_pred(const ::qflow_chart_t &fc, size_t n, size_t i);
rust::Vec<uint32_t> cfg_succs(const ::qflow_chart_t &fc, size_t n);
rust::Vec<uint32_t> cfg_preds(const ::qflow_chart_t &fc, size_t n);

} // namespace idakit_cxx
