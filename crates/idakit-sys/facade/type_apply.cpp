// Hand-written Custom bodies for the generated type-write domain (namespace gen): parse,
// resolve, or build a tinfo from a recipe and apply it at an address, or clear the type note
// entirely. Reports an int result code plus captured diagnostic through a TypeWriteResult shared
// struct, as the sibling type-write TUs do. Shared helpers (recipe building, the
// captured-diagnostic reader) live in type_write_common.

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

// Parse `decl` against the local til and apply it at `addr`. TYPE_ERR_INPUT if it doesn't
// parse, TYPE_ERR_APPLY if apply_tinfo rejects the result.
TypeWriteResult apply_type_decl(uint64_t addr, rust::Str decl, int32_t flags) {
  try {
    TypeWriteResult out{};
    std::string decls(decl.data(), decl.size());
    out.code = guarded<int>(TYPE_ERR_APPLY, true, [&]() -> int {
      tinfo_t tif;
      qstring name;
      if (!parse_decl(&tif, &name, get_idati(), decls.c_str(), PT_SEMICOLON))
        return TYPE_ERR_INPUT;
      // TINFO_DEFINITE marks the type as user-set, not a guess later auto-analysis may overwrite.
      if (!apply_tinfo(static_cast<ea_t>(addr), tif, static_cast<uint32>(flags) | TINFO_DEFINITE))
        return TYPE_ERR_APPLY;
      return TYPE_OK;
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

// Resolve the existing named type `name` and apply it at `addr`. TYPE_ERR_INPUT if no such
// type in the local til, TYPE_ERR_APPLY if apply_tinfo rejects it.
TypeWriteResult apply_named_type(uint64_t addr, rust::Str name) {
  try {
    TypeWriteResult out{};
    std::string names(name.data(), name.size());
    out.code = guarded<int>(TYPE_ERR_APPLY, false, [&]() -> int {
      tinfo_t tif;
      if (!tif.get_named_type(get_idati(), names.c_str()))
        return TYPE_ERR_INPUT;
      if (!apply_tinfo(static_cast<ea_t>(addr), tif, TINFO_DEFINITE))
        return TYPE_ERR_APPLY;
      return TYPE_OK;
    });
    return out;
  } catch (...) {
    std::abort();
  }
}

// Clear any type note at `addr`. Idempotent: TYPE_OK is returned even when there was
// nothing to clear.
TypeWriteResult clear_type(uint64_t addr) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(TYPE_ERR_APPLY, false, [&]() -> int {
      tinfo_t cur;
      if (!get_tinfo(&cur, static_cast<ea_t>(addr)) || cur.empty())
        return TYPE_OK;
      return set_tinfo(static_cast<ea_t>(addr), nullptr) ? TYPE_OK : TYPE_ERR_APPLY;
    });
    return out;
  } catch (...) {
    std::abort();
  }
}

// Build the tinfo the postfix recipe in `recipe` encodes and apply it at `addr`. Same codes
// as apply_type_decl; an unresolved named leaf builds a forward reference that fails at
// apply, not here.
TypeWriteResult apply_type_recipe(uint64_t addr, rust::Slice<const uint8_t> recipe, int32_t flags) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(TYPE_ERR_APPLY, true, [&]() -> int {
      tinfo_t tif;
      int rc = build_recipe(recipe.data(), recipe.size(), tif);
      if (rc != TYPE_OK)
        return rc;
      if (!apply_tinfo(static_cast<ea_t>(addr), tif, static_cast<uint32>(flags) | TINFO_DEFINITE))
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
