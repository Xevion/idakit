// Hand-written Custom bodies for the generated type-write domain (namespace gen): granular
// tinfo_t construction. Each builder mints a fresh heap tinfo_t owned by a UniquePtr, whose cxx
// deleter (~tinfo_t) frees it on drop. A build failure returns a null handle (an Err only for the
// parse-driven tinfo_decl). The transform builders copy the borrowed `inner`, never consuming it,
// so the caller's input handle stays live. Shared helpers (scalar leaf builders, the
// captured-diagnostic reader) live in type_write_common.

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

// The void type as a fresh handle.
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

// The boolean type as a fresh handle.
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

// A bytes-wide integer (1/2/4/8/16), signed when is_signed, as a fresh handle; null if the
// width has no matching SDK int type.
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

// A bytes-wide float (4 or 8) as a fresh handle; null for any other width.
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

// The named type `name` as a fresh handle, an unresolved typedef ref. Non-null even when
// `name` is absent from the local til (see build_named); the caller checks existence itself.
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

// The type `decl` parses to, as a fresh handle. The one builder with a parse step: throws
// the captured reason on failure so cxx maps it to a Rust Err, hence no catch-all abort
// shell like the other builders in this file use.
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

// A pointer to inner as a fresh handle; inner is copied, not consumed, so the caller's
// handle stays live. Null if create_ptr rejects it.
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

// An nelems-element array of inner as a fresh handle; inner is copied, not consumed. Null
// when nelems exceeds u32 or create_array rejects it.
std::unique_ptr<::tinfo_t> tinfo_array(const ::tinfo_t &inner, uint64_t nelems) {
  try {
    // create_array's count param is a uint32, so a wider element count can't fit it.
    constexpr uint64_t MAX_ARRAY_ELEMS = 0xffffffffULL;
    if (nelems > MAX_ARRAY_ELEMS)
      return nullptr;
    auto t = std::make_unique<::tinfo_t>();
    if (!t->create_array(inner, static_cast<uint32>(nelems)))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

// A const-qualified copy of inner as a fresh handle; inner is not consumed.
std::unique_ptr<::tinfo_t> tinfo_const(const ::tinfo_t &inner) {
  try {
    auto t = std::make_unique<::tinfo_t>(inner);
    t->set_const();
    return t;
  } catch (...) {
    std::abort();
  }
}

// A volatile-qualified copy of inner as a fresh handle; inner is not consumed.
std::unique_ptr<::tinfo_t> tinfo_volatile(const ::tinfo_t &inner) {
  try {
    auto t = std::make_unique<::tinfo_t>(inner);
    t->set_volatile();
    return t;
  } catch (...) {
    std::abort();
  }
}

// Apply the built `handle` at `addr`; TYPE_OK/TYPE_ERR_APPLY, marking it definite (user-set,
// not guessed) as every other apply path here does. The handle itself is not consumed.
TypeWriteResult tinfo_apply(uint64_t addr, const ::tinfo_t &handle, int32_t flags) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(TYPE_ERR_APPLY, true, [&]() -> int {
      if (!apply_tinfo(static_cast<ea_t>(addr), handle,
                       static_cast<uint32>(flags) | TINFO_DEFINITE))
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
