#pragma once

#include <cstddef>

// FlowChart maps to the SDK's ::qflow_chart_t (shared with the cfg bridge via a hand-written
// ExternType). The definition must be complete so cfg2_total_edges can walk its blocks.
#include <pro.h>

#include <ida.hpp>

#include <gdl.hpp>

namespace idakit_cxx {

// FlowChart binds ::qflow_chart_t directly (shared ExternType, cxx_name set in bridge_cfg.rs),
// so this names the SDK class with no local alias.
size_t cfg2_total_edges(const ::qflow_chart_t &fc);

} // namespace idakit_cxx
