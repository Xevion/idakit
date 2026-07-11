// cxx spike bodies (test-shims only). See probe_ext_cxx.h for the custom trycatch that every
// Result-returning body here routes through.

#include <pro.h>

#include <ida.hpp>

#include <bytes.hpp>
#include <name.hpp>

#include <stdexcept>
#include <string>

#include "rust/cxx.h"

#include "probe_ext_cxx.h"
// The cxx-generated header carries the full definition of the WriteOutcome shared enum (forward-
// declared in probe_ext_cxx.h), so ext_classify below can name its variants.
#include "idakit-sys/src/bridge_probe_ext.rs.h"

namespace idakit_cxx {

// A non-std::exception throw: cxx's default trycatch would std::terminate here; the custom
// catch(...) arm turns it into a Rust Err instead. Never returns normally.
rust::String ext_throw_plain_int() {
  throw 42;
  return rust::String("unreachable");
}

// interr_exc_t carries only an int code and inherits the generic base what(); the custom
// catch(const interr_exc_t&) arm is what makes the code legible on the Rust side.
rust::String ext_throw_interr(int32_t code) {
  throw interr_exc_t(code);
  return rust::String("unreachable");
}

// Structured data encoded INTO the message string, the only channel a cxx::Exception has
// (it carries what() and nothing else). The Rust side re-parses the code back out.
rust::String ext_throw_coded(int32_t code) {
  throw std::runtime_error("idakit:qerrno=" + std::to_string(code));
  return rust::String("unreachable");
}

std::unique_ptr<AddrCursor> make_addr_cursor(uint64_t init) {
  return std::unique_ptr<AddrCursor>(new AddrCursor{init});
}

// rust::Str is not NUL-terminated; copy into a std::string for the C API. set_name returns
// false on rejection -> throw, which cxx maps to a Rust Err (the failure SIGNAL; the Rust caller
// re-derives qerrno/reason from last_reason(), it is not read off the message).
void ext_set_name(uint64_t ea, rust::Str name) {
  std::string owned(name.data(), name.size());
  if (!set_name((ea_t)ea, owned.c_str(), 0))
    throw std::runtime_error("set_name rejected");
}

void ext_set_cmt(uint64_t ea, rust::Str comment, bool repeatable) {
  std::string owned(comment.data(), comment.size());
  if (!set_cmt((ea_t)ea, owned.c_str(), repeatable))
    throw std::runtime_error("set_cmt rejected");
}

// Return the generated shared enum by value; the Rust side matches it with a wildcard arm.
WriteOutcome ext_classify(int32_t code) {
  switch (code) {
  case 0:
    return WriteOutcome::Applied;
  case 1:
    return WriteOutcome::Rejected;
  default:
    return WriteOutcome::NoChange;
  }
}

} // namespace idakit_cxx
