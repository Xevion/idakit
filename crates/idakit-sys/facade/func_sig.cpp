// Hand-written Custom bodies for the generated type-write domain (namespace gen):
// prototype-surgery on a function's type at an address, replacing the return type, one parameter's
// type or name, the calling convention, or prepending an implicit `this`. Reports an int result
// code plus captured diagnostic and parameter count through a SigWriteResult/TypeWriteResult shared
// struct, as the sibling type-write TUs do.

#include <string>

#include <pro.h>

#include <ida.hpp>

#include <nalt.hpp>    // get_tinfo (address-level type note)
#include <typeinf.hpp> // tinfo_t, func_type_data_t, funcarg_t, apply_tinfo, create_func

#include "gen_type_build.h"
#include "internal.h" // guarded<>
// The generated bridge header defines the shared structs (full definitions needed to construct them
// below); gen_type_build.h only forward-declares them.
#include "gen_bridge.h"
#include "type_write_common.h" // captured_reason, build_recipe

using namespace facade;

namespace gen {

namespace {

// Read ea's function type into (tif, ftd); false if ea carries no function type to edit. Reads
// without recomputing arg locations (GTD_NO_ARGLOCS); rebuild_and_apply forces a recompute. Only
// called from the func_* bodies below, so this stays file-local.
bool read_func_details(ea_t ea, tinfo_t &tif, func_type_data_t &ftd) {
  return get_tinfo(&tif, ea) && !tif.empty() && tif.get_func_details(&ftd, GTD_NO_ARGLOCS);
}

// Rebuild the function type from mutated details and re-apply it at ea. Clears any explicit arg
// locations the edit invalidated so create_func recomputes them. SIG_APPLY if create_func or
// apply_tinfo rejects the result. Only called from the func_* bodies below, so this stays
// file-local.
int rebuild_and_apply(ea_t ea, func_type_data_t &ftd) {
  ftd.flags &= ~(FTI_ARGLOCS | FTI_EXPLOCS);
  tinfo_t nt;
  if (!nt.create_func(ftd))
    return SIG_APPLY;
  if (!apply_tinfo(ea, nt, TINFO_DEFINITE))
    return SIG_APPLY;
  return SIG_OK;
}

} // namespace

TypeWriteResult func_set_rettype(uint64_t ea, rust::Slice<const uint8_t> recipe) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return SIG_NO_PROTOTYPE;
      tinfo_t rt;
      if (build_recipe(recipe.data(), recipe.size(), rt) != TYPE_OK)
        return SIG_BUILD;
      ftd.rettype = rt;
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

SigWriteResult func_set_argtype(uint64_t ea, size_t idx, rust::Slice<const uint8_t> recipe) {
  try {
    SigWriteResult out{};
    size_t arity = 0;
    out.code = guarded<int>(SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return SIG_NO_PROTOTYPE;
      arity = ftd.size();
      if (idx >= ftd.size())
        return SIG_ARG_RANGE;
      tinfo_t at;
      if (build_recipe(recipe.data(), recipe.size(), at) != TYPE_OK)
        return SIG_BUILD;
      ftd[idx].type = at;
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    out.arity = arity;
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

SigWriteResult func_rename_arg(uint64_t ea, size_t idx, rust::Str name) {
  try {
    SigWriteResult out{};
    std::string names(name.data(), name.size());
    size_t arity = 0;
    out.code = guarded<int>(SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return SIG_NO_PROTOTYPE;
      arity = ftd.size();
      if (idx >= ftd.size())
        return SIG_ARG_RANGE;
      ftd[idx].name = names.c_str();
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    out.arity = arity;
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult func_set_cc(uint64_t ea, int32_t cc) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return SIG_NO_PROTOTYPE;
      ftd.set_cc((callcnv_t)cc);
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult func_prepend_this(uint64_t ea, rust::Slice<const uint8_t> recipe) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return SIG_NO_PROTOTYPE;
      tinfo_t pt;
      if (build_recipe(recipe.data(), recipe.size(), pt) != TYPE_OK)
        return SIG_BUILD;
      funcarg_t self_arg;
      self_arg.type = pt;
      self_arg.name = "this";
      ftd.insert(ftd.begin(), self_arg);
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

} // namespace gen
