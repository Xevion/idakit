// Hand-written Custom bodies for the generated local-type read domain (namespace gen).
// Render a function's prototype and name the local type at an ordinal; both throw when the SDK has
// no value, which cxx maps to a Rust Err. The ordinal-limit passthrough is templated, not here.

#include <ida.hpp>
#include <pro.h>

#include <typeinf.hpp> // print_type, get_idati, get_numbered_type_name

#include <stdexcept>

#include "gen_ty.h"

namespace gen {

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

} // namespace gen
