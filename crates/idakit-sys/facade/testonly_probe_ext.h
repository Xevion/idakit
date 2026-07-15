// Declarations for the cxx spike bridge. Proves a custom rust::behavior::trycatch widens what the
// generated shim catches. Bodies live in testonly_probe_ext.cpp; the
// cxx-generated shim (from src/bridge_probe_ext.rs) calls them by their bridge-namespaced name.
#pragma once

#include <cstdint>
#include <exception>
#include <string>

// interr_exc_t (a std::exception subclass that does NOT override what(), so the base what() is the
// uninformative "std::exception"): the case the custom trycatch below enriches with its code.
#include <pro.h>

#include "rust/cxx.h"

// Custom rust::behavior::trycatch specialization for THIS bridge's generated shim.
//
// cxx's generated .cc includes this header first, then defines a default trycatch guarded by a
// `decltype(trycatch(...)) == missing` SFINAE probe. Because this concrete overload is already in
// scope, that probe resolves to `void` (not the sentinel `missing`), disabling the default: every
// Result-shim in this bridge routes its C++ body through the arms below instead. `func`/`fail` are
// dependent template parameters, so the body is only type-checked at instantiation, by which point
// cxx's ::rust::detail::Fail (with operator()(char const*) / (std::string const&)) is complete.
//
// Two arms beyond cxx's stock `catch (std::exception const&)`:
//   * interr_exc_t: more-derived, so it must precede the std::exception arm; formats the internal
//     code into the message (the base what() would just say "std::exception").
//   * catch (...): a non-std::exception throw (e.g. `throw 42;`) that cxx's default lets escape
//     to std::terminate becomes an ordinary Rust Err here.
namespace rust {
namespace behavior {
template <typename Try, typename Fail> static void trycatch(Try &&func, Fail &&fail) noexcept try {
  func();
} catch (const interr_exc_t &ie) {
  fail(std::string("idakit: IDA internal error, code=") + std::to_string(ie.code));
} catch (const std::exception &e) {
  fail(e.what());
} catch (...) {
  fail(std::string("idakit: non-std::exception thrown across the cxx bridge"));
}
} // namespace behavior
} // namespace rust

namespace bridge {

// Throwing probes exercising the three trycatch arms above.
rust::String ext_throw_plain_int();
rust::String ext_throw_interr(int32_t code);
rust::String ext_throw_coded(int32_t code);

} // namespace bridge
