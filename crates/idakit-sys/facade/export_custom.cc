// Hand-written Custom bodies for the generated export domain (namespace idakit_gen). Entry-point
// lookups over get_entry/get_entry_ordinal, plus the name and forwarder as a rust::String (Err when
// absent, since most exports have no forwarder). export_qty is templated (gen_export_bodies.cc),
// not here.

#include <pro.h>
#include <ida.hpp>

#include <entry.hpp>

#include <stdexcept>

#include "gen_export.h"

namespace idakit_gen {

uint64_t export_ea(size_t idx) {
  return (uint64_t)get_entry(get_entry_ordinal(idx));
}

uint64_t export_ordinal(size_t idx) {
  return (uint64_t)get_entry_ordinal(idx);
}

rust::String export_name(size_t idx) {
  qstring out;
  if (get_entry_name(&out, get_entry_ordinal(idx)) <= 0)
    throw std::runtime_error("no export name at index");
  return to_rust_string(out);
}

rust::String export_forwarder(size_t idx) {
  qstring out;
  if (get_entry_forwarder(&out, get_entry_ordinal(idx)) <= 0)
    throw std::runtime_error("no export forwarder at index");
  return to_rust_string(out);
}

} // namespace idakit_gen
