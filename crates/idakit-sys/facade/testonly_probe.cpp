// Fault-injection probes for the cxx bridge. Two jobs:
//
//   * probe_fatal_through_cxx / test_fatal_through_cxx force the "dangerous topology": a
//     guarded<> setjmp ABOVE a cxx Result-shim, with the fatal firing from C++
//     BELOW the shim, so the trap's longjmp must unwind through the cxx-generated try/catch
//     landing-pad frame. idakit's real code never produces this (cxx bridge fns are leaves that
//     never call guarded<>, and the guarded entry points are raw extern "C" whose lambdas call
//     the SDK directly), so this is synthetic on purpose; it establishes the empirical boundary.
//
//   * probe_throw: a body that throws the selected C++ exception, so a test can see exactly how
//     cxx surfaces each as a Rust Err and where it does not (a non-std::exception
//     throw escapes cxx's `catch (std::exception const&)` shim and std::terminate()s).

#include <pro.h>

#include <ida.hpp>

#include <atomic>
#include <memory>
#include <stdexcept>

#include "rust/cxx.h"

#include "abi.h"               // trigger_fatal
#include "gen_facade_consts.h" // idakit_gen::EXIT_TRAPPED
#include "internal.h"          // guarded<>
#include "testonly_probe.h"

namespace idakit_cxx {

// Body reached through the cxx shim. On the exit/abort kinds trigger_fatal never returns
// (the trap longjmps back to the guard above); on the interr kind it throws interr_exc_t, which
// the shim's own `catch (std::exception const&)` intercepts (interr_exc_t : std::exception).
rust::String probe_fatal_through_cxx(int32_t kind) {
  trigger_fatal(kind);
  return rust::String("probe_fatal_through_cxx: fatal did not fire");
}

rust::String probe_throw(int32_t kind) {
  if (kind == 0)
    throw std::runtime_error("probe_throw: runtime_error from C++");
  if (kind == 1)
    throw std::out_of_range("probe_throw: out_of_range from C++");
  if (kind == 2)
    throw 42; // not a std::exception: cxx's trycatch won't catch it -> std::terminate
  return rust::String("probe_throw: no throw");
}

namespace {
std::atomic<uint32_t> g_drop_probe_count{0};
} // namespace

std::unique_ptr<DropProbe> drop_probe_make() { return std::make_unique<DropProbe>(); }

uint32_t drop_probe_count() { return g_drop_probe_count.load(); }

} // namespace idakit_cxx

// Out-of-line so it is never elided: dropping a UniquePtr<DropProbe> must reach this.
idakit_drop_probe_t::~idakit_drop_probe_t() {
  idakit_cxx::g_drop_probe_count.fetch_add(1, std::memory_order_relaxed);
}

// The cxx-generated C-ABI shim for probe_fatal_through_cxx. cxx does not offer a supported way to
// call a bridge shim from C++, so we declare the mangled symbol directly. Its shape is pattern (d)
// from cxxbridge's mangle scheme: {namespace}$cxxbridge1${CXXVERSION}${name}, where CXXVERSION is
// cxx's minor version, 197 for cxx 1.0.197 (pinned in Cargo.toml). A cxx bump changes it and
// breaks this test-only link loudly. The return value is a {ptr,len} POD (rust::repr::PtrLen);
// we mirror its layout with an identical local struct (extern "C" keys on the name, not the type).
namespace {
struct ProbePtrLen {
  void *ptr;
  ::std::size_t len;
};
} // namespace

extern "C" ProbePtrLen
idakit_cxx$cxxbridge1$197$probe_fatal_through_cxx(::std::int32_t kind,
                                                  ::rust::String *ret) noexcept;

// Arm the guard, then reach the fatal *through* the cxx shim.
extern "C" int test_fatal_through_cxx(int kind) {
  return idakit_facade::guarded<int>(idakit_gen::EXIT_TRAPPED, false, [kind]() -> int {
    // Return slot the shim placement-news into on success. Empty until then, so the longjmp path
    // (exit/abort) that never lets the shim return leaks nothing when its ~String is skipped.
    ::rust::String ret;
    ProbePtrLen pl = idakit_cxx$cxxbridge1$197$probe_fatal_through_cxx(kind, &ret);
    // Only reached if no longjmp fired: the interr kind, where cxx's shim caught interr_exc_t and
    // reported a Rust Err (pl.ptr != nullptr). The Err's heap allocation leaks here, acceptable
    // in a one-shot test process, and it never happens on the exit/abort (longjmp) paths.
    return pl.ptr != nullptr ? 1 : 0;
  });
}
