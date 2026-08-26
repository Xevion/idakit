#pragma once

// The Hex-Rays half of the 9.4 back-port (see compat.h), split out because only this shim needs
// hexrays.hpp.

#include <pro.h>

#if IDA_SDK_VERSION < 940

#include <hexrays.hpp>

#include "compat.h"

inline cfuncptr_t decompile_function(ea_t func_ea, hexrays_failure_t *hf = nullptr,
                                     int decomp_flags = 0) {
  func_t *pfn = get_func(func_ea);
  return pfn != nullptr ? decompile_func(pfn, hf, decomp_flags) : cfuncptr_t(nullptr);
}

#endif // IDA_SDK_VERSION < 940
