// The custom rust::behavior::trycatch every production cxx bridge routes its Result-returning shims
// through, plus the RAII that arms it. Included by each production bridge's C++ header so it is in
// scope in the bridge's cxx-generated .cc: cxx guards its default (std::exception-only) trycatch
// behind a `decltype(trycatch(...)) == missing` SFINAE probe, and this concrete overload being
// already visible resolves that probe away, disabling the default. Every Result shim then arms
// throwing-interr for its body and turns an idalib interr (or a non-std throw) into a Rust Err
// instead of std::terminate.
#pragma once

#include <string>

// set_interr_throws, interr_exc_t (a std::exception subclass that does not override what()).
#include <pro.h>

#include "rust/cxx.h"

namespace facade {

// RAII arming idalib's throwing-interr mode for the enclosing scope, restoring the prior setting on
// exit. An interr unwinds as an ordinary C++ throw, so this destructor runs on the catch path too;
// it is trivially destructible bar the flag write, so it is safe there (unlike a longjmp trap).
struct interr_scope {
  bool prev; // prior throwing-interr setting, restored on scope exit
  interr_scope() : prev(set_interr_throws(true)) {}
  ~interr_scope() { set_interr_throws(prev); }
  interr_scope(const interr_scope &) = delete;
  interr_scope &operator=(const interr_scope &) = delete;
};

} // namespace facade

namespace rust {
namespace behavior {

// `func`/`fail` are dependent template parameters, so the body is only type-checked at
// instantiation, by which point cxx's ::rust::detail::Fail is complete. The interr_exc_t arm is
// more-derived than std::exception, so it must precede it; it formats the internal code into the
// message (the base what() would say only "std::exception").
template <typename Try, typename Fail> static void trycatch(Try &&func, Fail &&fail) noexcept {
  facade::interr_scope arm;
  try {
    func();
  } catch (const interr_exc_t &ie) {
    fail(std::string("idakit: IDA internal error, code=") + std::to_string(ie.code));
  } catch (const std::exception &e) {
    fail(e.what());
  } catch (...) {
    fail(std::string("idakit: non-std::exception thrown across the cxx bridge"));
  }
}

} // namespace behavior
} // namespace rust
