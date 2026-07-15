// Hand-written Custom bodies for the generated name domain (namespace idakit_gen). Name lookups
// (get_ea_name, get_name_ea, demangle_name), the name-list accessors, and the flags-word name
// classifiers. The string getters throw (Err on no name) rather than returning a -1 length. SDK
// calls are ::-qualified: several generated symbols
// share the SDK's own spelling (get_ea_name, has_user_name, ...), so an unqualified call would
// recurse into this namespace instead of reaching the kernel.

#include <ida.hpp>
#include <pro.h>

#include <bytes.hpp>
#include <name.hpp>

#include <stdexcept>
#include <string>

#include "gen_name.h"

namespace idakit_gen {

rust::String get_ea_name(uint64_t ea) {
  qstring out;
  if (::get_ea_name(&out, (ea_t)ea) <= 0)
    throw std::runtime_error("no name at address");
  return to_rust_string(out);
}

uint64_t get_name_ea(rust::Str name) {
  return (uint64_t)::get_name_ea(BADADDR, std::string(name.data(), name.size()).c_str());
}

// Full demangle (disable_mask 0). An unmangled name leaves `out` empty; throw so the caller sees
// "not mangled" as an Err rather than an empty string.
rust::String demangle_name(rust::Str name) {
  qstring out;
  ::demangle_name(&out, std::string(name.data(), name.size()).c_str(), 0);
  if (out.empty())
    throw std::runtime_error("name is not mangled");
  return to_rust_string(out);
}

size_t nlist_size() { return ::get_nlist_size(); }

uint64_t nlist_ea(size_t idx) { return (uint64_t)::get_nlist_ea(idx); }

rust::String nlist_name(size_t idx) {
  const char *nm = ::get_nlist_name(idx);
  if (nm == nullptr)
    throw std::runtime_error("no name at nlist index");
  return to_rust_string(nm, qstrlen(nm));
}

// Name classification over an address's flags word: pure bit tests (inline in bytes.hpp, no kernel
// state), exposed so the Rust side can pin its FF_NAME/FF_LABL derivation against IDA's own logic.
bool has_user_name(uint64_t flags) { return ::has_user_name((flags64_t)flags); }

bool has_auto_name(uint64_t flags) { return ::has_auto_name((flags64_t)flags); }

bool has_dummy_name(uint64_t flags) { return ::has_dummy_name((flags64_t)flags); }

} // namespace idakit_gen
