// Hand-written Custom bodies for the generated type-write domain (namespace gen): add,
// reprise, rename, or delete one constant of a named enum in the local til, plus the enum-level
// bitmask/repr/width setters. Reports an int result code plus captured diagnostic through a
// TypeWriteResult shared struct, as the sibling type-write TUs do.

#include <cstdint>
#include <string>

#include <pro.h>

#include <ida.hpp>

#include <typeinf.hpp> // tinfo_t, edm_t, value_repr_t

#include "gen_type_build.h"
#include "internal.h" // guarded<>
// The generated bridge header defines the shared structs (full definitions needed to construct them
// below); gen_type_build.h only forward-declares them.
#include "gen_bridge.h"
#include "type_write_common.h" // captured_reason, load_named_type

using namespace facade;

namespace gen {

namespace {

// Resolve an enum constant index by name; -1 if not found. Constants are keyed by name (values may
// repeat within a bitmask enum, names are unique). Only called from the enum_* bodies below, so
// this stays file-local.
ssize_t resolve_edm(const tinfo_t &tif, const char *name) {
  edm_t edm;
  return tif.get_edm(&edm, name);
}

} // namespace

TypeWriteResult enum_add_member(rust::Str type_name, rust::Str member_name, uint64_t value,
                                uint64_t bmask, uint32_t etf_flags) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      return (int)tif.add_edm(mn.c_str(), value, (bmask64_t)bmask, etf_flags);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult enum_set_bitmask(rust::Str type_name, bool on) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      return (int)tif.set_enum_is_bitmask(on ? tinfo_t::ENUMBM_ON : tinfo_t::ENUMBM_OFF);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

// vtype is a value_repr_t FRB_* value-type nibble, same convention as udt_set_member_repr.
TypeWriteResult enum_set_repr(rust::Str type_name, uint32_t vtype, bool is_signed,
                              bool leading_zeros) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      value_repr_t repr;
      repr.set_vtype(vtype);
      repr.set_signed(is_signed);
      repr.set_lzeroes(leading_zeros);
      return (int)tif.set_enum_repr(repr);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult enum_set_width(rust::Str type_name, int32_t nbytes) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      return (int)tif.set_enum_width(nbytes);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult enum_set_member_value(rust::Str type_name, rust::Str member_name, uint64_t value) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      ssize_t idx = resolve_edm(tif, mn.c_str());
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      return (int)tif.edit_edm((size_t)idx, value);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult enum_rename_member(rust::Str type_name, rust::Str member_name, rust::Str new_name,
                                   uint32_t etf_flags) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    std::string nn(new_name.data(), new_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      ssize_t idx = resolve_edm(tif, mn.c_str());
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      return (int)tif.rename_edm((size_t)idx, nn.c_str(), etf_flags);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult enum_del_member(rust::Str type_name, rust::Str member_name) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      ssize_t idx = resolve_edm(tif, mn.c_str());
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      return (int)tif.del_edm((size_t)idx);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult enum_del_member_by_value(rust::Str type_name, uint64_t value) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      return (int)tif.del_edm_by_value(value, 0, DEFMASK64, 0);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

} // namespace gen
