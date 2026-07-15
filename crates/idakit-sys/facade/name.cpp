// Hand-written Custom bodies for the generated name domain (namespace gen): name lookups, the
// name-list accessors, and the flags-word name classifiers. String getters throw
// std::runtime_error (a Rust Err) instead of returning a sentinel length. SDK calls are
// ::-qualified since several generated symbols share the SDK's own spelling (get_ea_name,
// has_user_name, ...), so an unqualified call would recurse into this namespace instead of
// reaching the kernel.

#include <ida.hpp>
#include <pro.h>

#include <bytes.hpp>
#include <name.hpp>

#include <stdexcept>
#include <string>

#include "gen_name.h"

namespace gen {

// The user-visible name at addr; throws when addr has no name.
rust::String get_ea_name(uint64_t addr) {
  qstring out;
  if (::get_ea_name(&out, static_cast<ea_t>(addr)) <= 0)
    throw std::runtime_error("no name at address");
  return to_rust_string(out);
}

// Address bound to name, or BADADDR when no such name exists.
uint64_t get_name_ea(rust::Str name) {
  return static_cast<uint64_t>(
      ::get_name_ea(BADADDR, std::string(name.data(), name.size()).c_str()));
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

// Number of entries in the named-item list.
size_t nlist_size() { return ::get_nlist_size(); }

// Address of the name-list entry at idx.
uint64_t nlist_ea(size_t idx) { return static_cast<uint64_t>(::get_nlist_ea(idx)); }

// Name of the name-list entry at idx; throws when the entry has no name.
rust::String nlist_name(size_t idx) {
  const char *nm = ::get_nlist_name(idx);
  if (nm == nullptr)
    throw std::runtime_error("no name at nlist index");
  return to_rust_string(nm, qstrlen(nm));
}

// Pure bit tests over an address's flags word (inline in bytes.hpp, no kernel call); exposed so
// the Rust side can pin its own FF_NAME/FF_LABL derivation against IDA's logic.

// True when the name at flags was set by the user, not auto-generated.
bool has_user_name(uint64_t flags) { return ::has_user_name(static_cast<flags64_t>(flags)); }

// True when IDA auto-generated the name at flags (sub_, loc_, byte_, ...).
bool has_auto_name(uint64_t flags) { return ::has_auto_name(static_cast<flags64_t>(flags)); }

// True when the name at flags is an IDA placeholder/dummy name.
bool has_dummy_name(uint64_t flags) { return ::has_dummy_name(static_cast<flags64_t>(flags)); }

} // namespace gen
