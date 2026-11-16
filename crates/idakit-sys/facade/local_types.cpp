// Hand-written Custom bodies for the generated local-type read domain (namespace gen).
// Render a function's prototype and name the local type at an ordinal; both throw when the SDK has
// no value, which cxx maps to a Rust Err. The ordinal-limit passthrough is templated, not here.
// The *_ids emitters name the SDK's tattr, FTI_, FAI_, and type_t values, so a renumbering fails
// idakit's tests.

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

// idakit FunctionTypeFlags.
rust::Vec<uint32_t> function_type_flag_ids() {
  return collect({FTI_SPOILED, FTI_NORET, FTI_PURE, FTI_HIGH, FTI_STATIC, FTI_VIRTUAL, FTI_ARGLOCS,
                  FTI_EXPLOCS, FTI_CONST, FTI_CTOR, FTI_DTOR});
}

// idakit CallType.
rust::Vec<uint32_t> call_type_ids() {
  return collect({FTI_DEFCALL, FTI_NEARCALL, FTI_FARCALL, FTI_INTCALL});
}

// idakit-sys BaseType.
rust::Vec<uint32_t> base_type_ids() {
  return collect({BT_UNK, BT_VOID, BT_INT8, BT_INT16, BT_INT32, BT_INT64, BT_INT128, BT_INT,
                  BT_BOOL, BT_FLOAT, BT_PTR, BT_ARRAY, BT_FUNC, BT_COMPLEX, BT_BITFIELD,
                  BT_RESERVED});
}

// idakit-sys's sub-type enums, concatenated in Subtype's variant order: SizeClass, IntSign,
// BoolSize, FloatKind, PointerKind, ArrayFlags, CallMethod, ComplexKind, BitfieldStorage.
rust::Vec<uint32_t> type_subtype_ids() {
  return collect({BTMT_SIZE0,    BTMT_SIZE12,   BTMT_SIZE48,  BTMT_SIZE128,  BTMT_UNKSIGN,
                  BTMT_SIGNED,   BTMT_USIGNED,  BTMT_CHAR,    BTMT_DEFBOOL,  BTMT_BOOL1,
                  BTMT_BOOL2,    BTMT_BOOL4,    BTMT_FLOAT,   BTMT_DOUBLE,   BTMT_LNGDBL,
                  BTMT_SPECFLT,  BTMT_DEFPTR,   BTMT_NEAR,    BTMT_FAR,      BTMT_CLOSURE,
                  BTMT_NONBASED, BTMT_ARRESERV, BTMT_DEFCALL, BTMT_NEARCALL, BTMT_FARCALL,
                  BTMT_INTCALL,  BTMT_STRUCT,   BTMT_UNION,   BTMT_ENUM,     BTMT_TYPEDEF,
                  BTMT_BFLDI8,   BTMT_BFLDI16,  BTMT_BFLDI32, BTMT_BFLDI64});
}

// idakit-sys Qualifiers, then the three field masks.
rust::Vec<uint32_t> type_modifier_ids() {
  return collect({BTM_CONST, BTM_VOLATILE, TYPE_BASE_MASK, TYPE_FLAGS_MASK, TYPE_MODIF_MASK});
}

// idakit ParameterFlags.
rust::Vec<uint32_t> parameter_flag_ids() {
  return collect({FAI_HIDDEN, FAI_RETPTR, FAI_STRUCT, FAI_ARRAY, FAI_UNUSED});
}

} // namespace gen
