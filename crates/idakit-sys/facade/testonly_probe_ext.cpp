// cxx spike bodies. See testonly_probe_ext.h for the custom trycatch that every
// Result-returning body here routes through.

#include <pro.h>

#include <ida.hpp>

#include <stdexcept>
#include <string>

#include "rust/cxx.h"

#include "testonly_probe_ext.h"

namespace bridge {

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

} // namespace bridge
