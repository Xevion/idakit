// Fault-injection probes for the cxx bridge. Two jobs:
//
//   * test_fatal_through_cxx forces the "dangerous topology": a guarded<> setjmp ABOVE the
//     shared production rust::behavior::trycatch landing pad (trycatch.h), with the fatal firing
//     from C++ below it, so the trap's longjmp must unwind through that frame. idakit's real code
//     never produces this (cxx bridge fns are leaves that never call guarded<>, and the guarded
//     entry points are raw extern "C" whose lambdas call the SDK directly), so this is synthetic
//     on purpose; it establishes the empirical boundary.
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
#include "gen_facade_consts.h" // gen::EXIT_TRAPPED
#include "internal.h"          // guarded<>
#include "testonly_probe.h"
#include "trycatch.h" // rust::behavior::trycatch

namespace bridge {

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

} // namespace bridge

// Out-of-line so it is never elided: dropping a UniquePtr<DropProbe> must reach this.
drop_probe_t::~drop_probe_t() {
  bridge::g_drop_probe_count.fetch_add(1, std::memory_order_relaxed);
}

extern "C" int test_fatal_through_cxx(int kind) {
  return facade::guarded<int>(gen::EXIT_TRAPPED, false, [kind]() -> int {
    // Reproduces cxx's Result-shim topology: the shared production rust::behavior::trycatch
    // (trycatch.h) lands between the guard and the fatal, with no dependency on cxx's generated
    // mangled symbol. exit/abort longjmp out through this frame, so guarded<> returns
    // EXIT_TRAPPED; interr is caught here instead, so caught becomes 1.
    int caught = 0;
    rust::behavior::trycatch([kind] { trigger_fatal(kind); },
                             [&caught](const std::string &) { caught = 1; });
    return caught;
  });
}
