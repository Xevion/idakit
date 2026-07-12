// Hand-written Custom bodies for the generated local-type read domain (namespace idakit_gen).
// Render a function's prototype and name the local type at an ordinal; both throw when the SDK has
// no value, which cxx maps to a Rust Err. The ordinal-limit passthrough is templated, not here.

#include <pro.h>
#include <ida.hpp>

#include <typeinf.hpp> // print_type, get_idati, get_numbered_type_name

#include <stdexcept>

#include "gen_ty.h"

namespace idakit_gen {

rust::String func_type(uint64_t ea) {
  qstring out;
  if (!print_type(&out, (ea_t)ea, PRTYPE_1LINE | PRTYPE_SEMI))
    throw std::runtime_error("function has no type");
  return rust::String(out.c_str(), out.length());
}

rust::String type_name_at(uint32_t ordinal) {
  const char *name = get_numbered_type_name(get_idati(), ordinal);
  if (name == nullptr)
    throw std::runtime_error("no type at ordinal");
  qstring out(name);
  return rust::String(out.c_str(), out.length());
}

} // namespace idakit_gen
