// Hand-written Custom bodies for the generated local-type read domain (namespace gen).
// Render a function's prototype and name the local type at an ordinal; both throw when the SDK has
// no value, which cxx maps to a Rust Err. The ordinal-limit passthrough is templated, not here.
// The *_ids emitters name each tattr context's SDK bits, so a renumbering fails idakit's tests.

#include <ida.hpp>
#include <pro.h>

#include <typeinf.hpp> // print_type, get_idati, get_numbered_type_name

#include <initializer_list>
#include <stdexcept>

#include "gen_ty.h"

namespace gen {

namespace {

rust::Vec<uint32_t> collect(std::initializer_list<uint32_t> bits) {
  rust::Vec<uint32_t> out;
  for (uint32_t bit : bits)
    out.push_back(bit);
  return out;
}

} // namespace

// One-line, semicolon-terminated prototype text for the function at addr; throws if it has no type.
rust::String func_type(uint64_t addr) {
  qstring out;
  if (!print_type(&out, static_cast<ea_t>(addr), PRTYPE_1LINE | PRTYPE_SEMI))
    throw std::runtime_error("function has no type");
  return to_rust_string(out);
}

// Name of the local type numbered ordinal in this database's type library; throws if none exists.
rust::String type_name_at(uint32_t ordinal) {
  const char *name = get_numbered_type_name(get_idati(), ordinal);
  if (name == nullptr)
    throw std::runtime_error("no type at ordinal");
  qstring out(name);
  return to_rust_string(out);
}

// idakit StructAttributes.
rust::Vec<uint32_t> struct_attribute_ids() {
  return collect({TAUDT_MSSTRUCT, TAUDT_UNALIGNED, TAUDT_CPPOBJ, TAUDT_VFTABLE, TAUDT_FIXED,
                  TAUDT_TUPLE, TAUDT_IFACE});
}

// idakit MemberAttributes.
rust::Vec<uint32_t> member_attribute_ids() {
  return collect({TAFLD_BASECLASS, TAFLD_UNALIGNED, TAFLD_VIRTBASE, TAFLD_VFTABLE, TAFLD_METHOD,
                  TAFLD_GAP, TAFLD_REGCMT, TAFLD_FRAME_R, TAFLD_FRAME_S, TAFLD_BYTIL});
}

// idakit EnumAttributes.
rust::Vec<uint32_t> enum_attribute_ids() {
  return collect({TAENUM_64BIT, TAENUM_UNSIGNED, TAENUM_SIGNED, TAENUM_OCT, TAENUM_BIN,
                  TAENUM_NUMSIGN, TAENUM_LZERO});
}

// idakit PointerAttributes.
rust::Vec<uint32_t> pointer_attribute_ids() { return collect({TAPTR_SHIFTED}); }

// idakit PointerModifier.
rust::Vec<uint32_t> pointer_modifier_ids() {
  return collect({TAPTR_PTR32, TAPTR_PTR64, TAPTR_RESTRICT});
}

} // namespace gen
