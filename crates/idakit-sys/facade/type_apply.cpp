// Hand-written Custom bodies for the generated type-write domain (namespace gen): parse,
// resolve, or build a tinfo from a recipe and apply it at an address, or clear the type note
// entirely. Reports an int result code plus captured diagnostic through a TypeWriteResult shared
// struct, as the sibling type-write TUs do.

#include <string>

#include <pro.h>

#include <ida.hpp>

#include <nalt.hpp>    // get_tinfo, set_tinfo (address-level type note)
#include <typeinf.hpp> // tinfo_t, parse_decl, apply_tinfo

#include "gen_type_build.h"
#include "internal.h" // guarded<>
// The generated bridge header defines the shared structs (full definitions needed to construct them
// below); gen_type_build.h only forward-declares them.
#include "gen_bridge.h"
#include "type_write_common.h" // captured_reason, build_recipe

using namespace facade;

namespace gen {

TypeWriteResult apply_type_decl(uint64_t ea, rust::Str decl, int32_t flags) {
  try {
    TypeWriteResult out{};
    std::string decls(decl.data(), decl.size());
    out.code = guarded<int>(TYPE_ERR_APPLY, true, [&]() -> int {
      tinfo_t tif;
      qstring name;
      if (!parse_decl(&tif, &name, get_idati(), decls.c_str(), PT_SEMICOLON))
        return TYPE_ERR_INPUT;
      if (!apply_tinfo((ea_t)ea, tif, (uint32)flags | TINFO_DEFINITE))
        return TYPE_ERR_APPLY;
      return TYPE_OK;
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult apply_named_type(uint64_t ea, rust::Str name) {
  try {
    TypeWriteResult out{};
    std::string names(name.data(), name.size());
    out.code = guarded<int>(TYPE_ERR_APPLY, false, [&]() -> int {
      tinfo_t tif;
      if (!tif.get_named_type(get_idati(), names.c_str()))
        return TYPE_ERR_INPUT;
      if (!apply_tinfo((ea_t)ea, tif, TINFO_DEFINITE))
        return TYPE_ERR_APPLY;
      return TYPE_OK;
    });
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult clear_type(uint64_t ea) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(TYPE_ERR_APPLY, false, [&]() -> int {
      tinfo_t cur;
      if (!get_tinfo(&cur, (ea_t)ea) || cur.empty())
        return TYPE_OK;
      return set_tinfo((ea_t)ea, nullptr) ? TYPE_OK : TYPE_ERR_APPLY;
    });
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult apply_type_recipe(uint64_t ea, rust::Slice<const uint8_t> recipe, int32_t flags) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(TYPE_ERR_APPLY, true, [&]() -> int {
      tinfo_t t;
      int rc = build_recipe(recipe.data(), recipe.size(), t);
      if (rc != TYPE_OK)
        return rc;
      if (!apply_tinfo((ea_t)ea, t, (uint32)flags | TINFO_DEFINITE))
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
