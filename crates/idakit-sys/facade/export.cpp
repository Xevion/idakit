// Hand-written Custom bodies for the generated export domain (namespace gen): entry-point
// lookups over get_entry/get_entry_ordinal, plus the name and forwarder as a rust::String
// (throws when absent, since most exports have no forwarder). export_qty is templated
// (gen_export_bodies.cc), not here.

#include <ida.hpp>
#include <pro.h>

#include <entry.hpp>

#include <stdexcept>

#include "gen_export.h"

namespace gen {

// Address of the entry point at idx in the entry-point list.
uint64_t export_ea(size_t idx) { return static_cast<uint64_t>(get_entry(get_entry_ordinal(idx))); }

// Ordinal of the entry point at idx in the entry-point list.
uint64_t export_ordinal(size_t idx) { return static_cast<uint64_t>(get_entry_ordinal(idx)); }

// Name of the export at idx; throws when the entry has no name.
rust::String export_name(size_t idx) {
  qstring out;
  if (get_entry_name(&out, get_entry_ordinal(idx)) <= 0)
    throw std::runtime_error("no export name at index");
  return to_rust_string(out);
}

// Forwarder target of the export at idx; throws when it doesn't forward (most exports don't).
rust::String export_forwarder(size_t idx) {
  qstring out;
  if (get_entry_forwarder(&out, get_entry_ordinal(idx)) <= 0)
    throw std::runtime_error("no export forwarder at index");
  return to_rust_string(out);
}

} // namespace gen
