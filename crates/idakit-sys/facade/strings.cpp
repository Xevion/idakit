// Hand-written Custom bodies for the generated strings domain (namespace gen). Two independent
// pieces: IDA's cached string list (build/query/index into StrlistItem, a cxx shared struct
// defined by the cxx-generated gen_bridge.h), and strlit_contents/strlit_escaped, which decode a
// string literal at a given address directly, list or not. Every out-of-range index or unreadable
// literal throws, surfacing as a Rust Err; STRCONV_REPLCHAR/STRCONV_ESCAPE both guarantee the
// decoded bytes are valid UTF-8.

#include <ida.hpp>
#include <pro.h>

#include <bytes.hpp>   // get_strlit_contents, STRCONV_REPLCHAR, STRCONV_ESCAPE
#include <strlist.hpp> // build_strlist, get_strlist_qty, get_strlist_item, string_info_t

#include <stdexcept>

#include "gen_strings.h"
// The cxx-generated header defines the StrlistItem shared struct (full definition needed to
// construct it); gen_strings.h only forward-declares it.
#include "gen_bridge.h"

namespace gen {

// Rebuilds IDA's cached string list; an O(database) scan.
void strlist_build() { build_strlist(); }

// The number of entries in the cached string list.
size_t strlist_qty() { return get_strlist_qty(); }

// The n-th entry of the cached string list; throws if n is out of range.
StrlistItem strlist_item(size_t n) {
  string_info_t info;
  if (!get_strlist_item(&info, n))
    throw std::out_of_range("string list index out of range");
  StrlistItem item;
  item.ea = static_cast<uint64_t>(info.ea);
  item.length = static_cast<int32_t>(info.length);
  item.type_ = static_cast<int32_t>(info.type);
  return item;
}

// The string literal at addr, decoded with undecodable bytes replaced by U+FFFD; throws if the
// literal can't be read.
rust::String strlit_contents(uint64_t addr, size_t len, int32_t strtype) {
  qstring out;
  ssize_t r =
      get_strlit_contents(&out, static_cast<ea_t>(addr), len, strtype, nullptr, STRCONV_REPLCHAR);
  if (r < 0)
    throw std::runtime_error("unreadable string literal");
  return to_rust_string(out);
}

// The string literal at addr, decoded to its C-escaped display form (\n, \xNN, ...); throws if
// the literal can't be read.
rust::String strlit_escaped(uint64_t addr, size_t len, int32_t strtype) {
  qstring out;
  ssize_t r =
      get_strlit_contents(&out, static_cast<ea_t>(addr), len, strtype, nullptr, STRCONV_ESCAPE);
  if (r < 0)
    throw std::runtime_error("unreadable string literal");
  return to_rust_string(out);
}

} // namespace gen
