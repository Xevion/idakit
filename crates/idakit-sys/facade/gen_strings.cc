// Hand-written Custom bodies for the generated strings domain (namespace idakit_gen). Wraps IDA's
// string list: build_strlist (an O(database) scan), its
// length, and the nth entry filled into the StrlistItem shared struct (throw when out of range).
// strlit_contents decodes the string at (ea,len,type) to a rust::String (throw when undecodable).
// StrlistItem is a cxx shared struct, defined by the cxx-generated gen_bridge.h.

#include <pro.h>
#include <ida.hpp>

#include <strlist.hpp> // build_strlist, get_strlist_qty, get_strlist_item, string_info_t
#include <bytes.hpp>   // get_strlit_contents, STRCONV_REPLCHAR

#include <stdexcept>

#include "gen_strings.h"
// The cxx-generated header defines the StrlistItem shared struct (full definition needed to
// construct it); gen_strings.h only forward-declares it.
#include "gen_bridge.h"

namespace idakit_gen {

void strlist_build() { build_strlist(); }

size_t strlist_qty() { return get_strlist_qty(); }

StrlistItem strlist_item(size_t n) {
  string_info_t si;
  if (!get_strlist_item(&si, n))
    throw std::out_of_range("string list index out of range");
  StrlistItem item;
  item.ea = (uint64_t)si.ea;
  item.length = (int32_t)si.length;
  item.type_ = (int32_t)si.type;
  return item;
}

rust::String strlit_contents(uint64_t ea, size_t len, int32_t strtype) {
  qstring out;
  ssize_t r = get_strlit_contents(&out, (ea_t)ea, len, strtype, nullptr, STRCONV_REPLCHAR);
  if (r < 0)
    throw std::runtime_error("undecodable string literal");
  return rust::String(out.c_str(), out.length());
}

} // namespace idakit_gen
