// Hand-written Custom bodies for the generated type-write domain (namespace gen): add,
// retype, rename, comment on, restyle the display of, or delete one member of a named
// struct/union in the local til. Reports an int result code plus captured diagnostic through
// a TypeWriteResult shared struct, as the sibling type-write TUs do. Shared helpers (recipe
// building, named-type resolution, the captured-diagnostic reader) live in type_write_common.

#include <cstdint>
#include <string>

#include <pro.h>

#include <ida.hpp>

#include <typeinf.hpp> // tinfo_t, udm_t, value_repr_t

#include "gen_type_build.h"
#include "internal.h" // guarded<>
// The generated bridge header defines the shared structs (full definitions needed to construct them
// below); gen_type_build.h only forward-declares them.
#include "gen_bridge.h"
#include "type_write_common.h" // captured_reason, build_recipe, load_named_type

using namespace facade;

namespace gen {

namespace {

// Resolve a member index in `tif`: by name when `member_name` is non-null, else by bit offset.
// -1 if no member matches. Only called from the udt_* bodies below, so this stays file-local.
int resolve_member(const tinfo_t &tif, const char *member_name, uint64_t member_bit) {
  udm_t key;
  int flags;
  if (member_name != nullptr) {
    key.name = member_name;
    flags = STRMEM_NAME;
  } else {
    key.offset = member_bit;
    flags = STRMEM_OFFSET;
  }
  return tif.find_udm(&key, flags);
}

// A bitfield member's declared field width in bits, or false for an ordinary type. add_udm's
// auto-size path (the name/type/offset overload) derives a member's size from the type's byte
// size, which for a bitfield tinfo_t is its container width, not the narrower field it actually
// occupies; udt_add_member must set udm_t::size to this width explicitly instead of relying on
// that auto-size path. Only called from udt_add_member, so this stays file-local.
bool bitfield_width_bits(const tinfo_t &member_type, uint16 &width) {
  if (!member_type.is_bitfield())
    return false;
  bitfield_type_data_t details;
  if (!member_type.get_bitfield_details(&details))
    return false;
  width = details.width;
  return true;
}

} // namespace

// Add a member built from `recipe` to the named struct/union `type_name` at bit offset
// `member_bit` (or appended past the last member when it is MEMBER_APPEND). An empty
// `member_name` adds an anonymous member. TEDIT_NO_TYPE/TEDIT_BUILD pre-failures, else
// add_udm's raw tinfo_code_t.
TypeWriteResult udt_add_member(rust::Str type_name, rust::Str member_name,
                               rust::Slice<const uint8_t> recipe, uint64_t member_bit) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    // A cxx rust::Str is never null, so an empty member name is the by-bit/anonymous selector.
    const char *mnp = member_name.empty() ? nullptr : mn.c_str();
    out.code = guarded<int>(static_cast<int>(TERR_SAVE_ERROR), true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      tinfo_t member_type;
      if (build_recipe(recipe.data(), recipe.size(), member_type) != TYPE_OK)
        return TEDIT_BUILD;
      // Append means "past the last member": offset 0 for a union (all members share it), the
      // current byte size in bits for a struct.
      uint64_t offset = member_bit;
      if (offset == MEMBER_APPEND) {
        asize_t sz = tif.is_union() ? 0 : tif.get_size();
        offset = (sz == BADSIZE ? 0 : static_cast<uint64_t>(sz)) * 8;
      }
      uint16 width;
      if (bitfield_width_bits(member_type, width)) {
        udm_t udm;
        udm.name = mnp != nullptr ? mnp : "";
        udm.type = member_type;
        udm.offset = offset;
        udm.size = width;
        return static_cast<int>(tif.add_udm(udm));
      }
      return static_cast<int>(tif.add_udm(mnp, member_type, offset));
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

// Replace the type of the member resolved by name (or, when empty, by bit offset) with the
// recipe type. TEDIT_NO_TYPE/TEDIT_NO_MEMBER/TEDIT_BUILD pre-failures, else set_udm_type's
// raw tinfo_code_t.
TypeWriteResult udt_set_member_type(rust::Str type_name, rust::Str member_name, uint64_t member_bit,
                                    rust::Slice<const uint8_t> recipe, uint32_t etf_flags) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    const char *mnp = member_name.empty() ? nullptr : mn.c_str();
    out.code = guarded<int>(static_cast<int>(TERR_SAVE_ERROR), true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      int idx = resolve_member(tif, mnp, member_bit);
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      tinfo_t member_type;
      if (build_recipe(recipe.data(), recipe.size(), member_type) != TYPE_OK)
        return TEDIT_BUILD;
      return static_cast<int>(tif.set_udm_type(static_cast<size_t>(idx), member_type, etf_flags));
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

// Rename the member resolved by name (or, when empty, by bit offset) to `new_name`.
// TEDIT_NO_TYPE/TEDIT_NO_MEMBER pre-failures, else rename_udm's raw tinfo_code_t.
TypeWriteResult udt_rename_member(rust::Str type_name, rust::Str member_name, uint64_t member_bit,
                                  rust::Str new_name) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    std::string nn(new_name.data(), new_name.size());
    const char *mnp = member_name.empty() ? nullptr : mn.c_str();
    out.code = guarded<int>(static_cast<int>(TERR_SAVE_ERROR), true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      int idx = resolve_member(tif, mnp, member_bit);
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      return static_cast<int>(tif.rename_udm(static_cast<size_t>(idx), nn.c_str()));
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

// Set a plain (non-repeatable) comment on the member resolved by name (or, when empty, by
// bit offset). TEDIT_NO_TYPE/TEDIT_NO_MEMBER pre-failures, else set_udm_cmt's raw
// tinfo_code_t.
TypeWriteResult udt_set_member_comment(rust::Str type_name, rust::Str member_name,
                                       uint64_t member_bit, rust::Str comment) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    std::string cn(comment.data(), comment.size());
    const char *mnp = member_name.empty() ? nullptr : mn.c_str();
    out.code = guarded<int>(static_cast<int>(TERR_SAVE_ERROR), true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      int idx = resolve_member(tif, mnp, member_bit);
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      return static_cast<int>(tif.set_udm_cmt(static_cast<size_t>(idx), cn.c_str()));
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

// Set the numeric display (vtype/sign/leading zeros) on the member resolved by name or bit
// offset. TEDIT_NO_TYPE/TEDIT_NO_MEMBER pre-failures, else set_udm_repr's raw tinfo_code_t.
// vtype is a value_repr_t FRB_* value-type nibble (FRB_NUMB/NUMO/NUMH/NUMD/CHAR); idakit maps
// its own NumberFormat enum onto it and never forwards an info-carrying nibble (FRB_ENUM,
// FRB_OFFSET, ...) here.
TypeWriteResult udt_set_member_repr(rust::Str type_name, rust::Str member_name, uint64_t member_bit,
                                    uint32_t vtype, bool is_signed, bool leading_zeros) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    const char *mnp = member_name.empty() ? nullptr : mn.c_str();
    out.code = guarded<int>(static_cast<int>(TERR_SAVE_ERROR), true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      int idx = resolve_member(tif, mnp, member_bit);
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      value_repr_t repr;
      repr.set_vtype(vtype);
      repr.set_signed(is_signed);
      repr.set_lzeroes(leading_zeros);
      return static_cast<int>(tif.set_udm_repr(static_cast<size_t>(idx), repr));
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

// Delete the member resolved by name (or, when empty, by bit offset) from `type_name`.
// TEDIT_NO_TYPE/TEDIT_NO_MEMBER pre-failures, else del_udm's raw tinfo_code_t.
TypeWriteResult udt_del_member(rust::Str type_name, rust::Str member_name, uint64_t member_bit) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    const char *mnp = member_name.empty() ? nullptr : mn.c_str();
    out.code = guarded<int>(static_cast<int>(TERR_SAVE_ERROR), true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      int idx = resolve_member(tif, mnp, member_bit);
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      return static_cast<int>(tif.del_udm(static_cast<size_t>(idx)));
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

} // namespace gen
