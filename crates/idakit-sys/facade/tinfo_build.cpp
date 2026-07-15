// Hand-written Custom bodies for the generated type-write domain (namespace gen): granular
// tinfo_t construction. Each builder mints a fresh heap tinfo_t owned by a UniquePtr, whose cxx
// deleter (~tinfo_t) frees it on drop. A build failure returns a null handle (an Err only for the
// parse-driven tinfo_decl). The transform builders copy the borrowed `inner`, never consuming it,
// so the caller's input handle stays live.

#include <memory>
#include <stdexcept>
#include <string>

#include <pro.h>

#include <ida.hpp>

#include <typeinf.hpp> // tinfo_t, parse_decl, create_*

#include "gen_type_build.h"
#include "internal.h" // guarded<>, g_output (msg-channel capture)
// The generated bridge header defines the shared structs (full definitions needed to construct them
// below); gen_type_build.h only forward-declares them.
#include "gen_bridge.h"
#include "type_write_common.h" // captured_reason, build_int, build_float, build_named

using namespace facade;

namespace gen {

std::unique_ptr<::tinfo_t> tinfo_void() {
  try {
    auto t = std::make_unique<::tinfo_t>();
    if (!t->create_simple_type(BTF_VOID))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

std::unique_ptr<::tinfo_t> tinfo_bool() {
  try {
    auto t = std::make_unique<::tinfo_t>();
    if (!t->create_simple_type(BT_BOOL))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

std::unique_ptr<::tinfo_t> tinfo_int(uint32_t bytes, bool is_signed) {
  try {
    auto t = std::make_unique<::tinfo_t>();
    if (!build_int(*t, bytes, is_signed))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

std::unique_ptr<::tinfo_t> tinfo_float(uint32_t bytes) {
  try {
    auto t = std::make_unique<::tinfo_t>();
    if (!build_float(*t, bytes))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

std::unique_ptr<::tinfo_t> tinfo_named(rust::Str name) {
  try {
    std::string names(name.data(), name.size());
    auto t = std::make_unique<::tinfo_t>();
    if (!build_named(*t, names.c_str()))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

// The one builder with a parse step: throw the captured reason on failure so cxx maps it to a Rust
// Err (hence no abort shell, matching the decompile body in hexrays.cpp).
std::unique_ptr<::tinfo_t> tinfo_decl(rust::Str decl) {
  std::string decls(decl.data(), decl.size());
  auto t = std::make_unique<::tinfo_t>();
  bool ok = guarded<bool>(false, true, [&]() -> bool {
    qstring pname;
    return parse_decl(t.get(), &pname, get_idati(), decls.c_str(), PT_SEMICOLON);
  });
  if (!ok)
    throw std::runtime_error(std::string(g_output.c_str(), g_output.length()));
  return t;
}

std::unique_ptr<::tinfo_t> tinfo_ptr(const ::tinfo_t &inner) {
  try {
    auto t = std::make_unique<::tinfo_t>();
    if (!t->create_ptr(inner))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

std::unique_ptr<::tinfo_t> tinfo_array(const ::tinfo_t &inner, uint64_t nelems) {
  try {
    if (nelems > 0xffffffffULL)
      return nullptr;
    auto t = std::make_unique<::tinfo_t>();
    if (!t->create_array(inner, (uint32)nelems))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

std::unique_ptr<::tinfo_t> tinfo_const(const ::tinfo_t &inner) {
  try {
    auto t = std::make_unique<::tinfo_t>(inner);
    t->set_const();
    return t;
  } catch (...) {
    std::abort();
  }
}

std::unique_ptr<::tinfo_t> tinfo_volatile(const ::tinfo_t &inner) {
  try {
    auto t = std::make_unique<::tinfo_t>(inner);
    t->set_volatile();
    return t;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult tinfo_apply(uint64_t ea, const ::tinfo_t &handle, int32_t flags) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(TYPE_ERR_APPLY, true, [&]() -> int {
      if (!apply_tinfo((ea_t)ea, handle, (uint32)flags | TINFO_DEFINITE))
        return TYPE_ERR_APPLY;
      return TYPE_OK;
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

} // namespace gen
