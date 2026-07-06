// Shared facade internals: the fatal-trap state and the guarded<> wrapper. The trap machinery
// is defined in runtime.cpp; only runtime.cpp and hexrays.cpp (decompile) need it.
#ifndef IDAKIT_FACADE_INTERNAL_HPP
#define IDAKIT_FACADE_INTERNAL_HPP

#include <csetjmp>
#include <cstdio>
#include <string>

#include <pro.h> // set_interr_throws, interr_exc_t (caught by reference below)

#include "idakit_facade.h"

namespace idakit_facade {

extern thread_local jmp_buf g_exit_jmp;
extern thread_local bool g_exit_guarded;
extern thread_local bool g_trapped;
extern thread_local int g_exit_code;
extern thread_local std::string g_output;

// stdout+stderr capture over a guarded call via an in-memory pipe (no temp file). `rd < 0`
// means capture is off or setup failed, so end_capture is a no-op.
struct capture_t {
  int rd = -1; // pipe read end, drained into g_output at the end
  int wr = -1; // pipe write end; fd 1+2 are dup2'd onto it for the call
  int saved_out = -1;
  int saved_err = -1;
};

void install_fatal_traps();
capture_t begin_capture();
void end_capture(capture_t &cap);
// msg()-channel capture: an HT_UI hook that catches ui_msg text the fd capture can't see (headless
// routes msg() to a no-op sink). Paired like begin/end_capture; end_ui_capture folds the text into
// g_output only when the stderr capture stayed empty. See runtime.cpp.
void begin_ui_capture();
void end_ui_capture();

// Run fn() with the fatal paths armed, returning `trapval` instead of letting the process die
// on any of them: exit()/abort() are trapped via the GOT and longjmp back here, and interr()
// (switched to throwing by set_interr_throws) is caught. `capture` redirects IDA's
// stdout+stderr for the duration. The longjmp stays within this C call chain (fn() is a facade
// lambda calling the SDK directly, with no Rust frame to unwind); the interr throw unwinds
// normally, since those SDK frames carry the unwind info the longjmp paths lack.
template <class T, class F> T guarded(T trapval, bool capture, F &&fn) {
  install_fatal_traps();
  g_trapped = false;
  g_output.clear();
  capture_t cap = capture ? begin_capture() : capture_t{};
  if (capture)
    begin_ui_capture();
  bool prev_throws = set_interr_throws(true);
  // Called on every exit path. Not an RAII guard: a longjmp over a non-trivial destructor is
  // UB, and this runs on the longjmp path too. Reference captures make its destructor trivial.
  auto finish = [&] {
    set_interr_throws(prev_throws);
    end_capture(cap);
    if (capture)
      end_ui_capture();
  };
  if (setjmp(g_exit_jmp) != 0) {
    g_trapped = true;
    finish();
    return trapval;
  }
  g_exit_guarded = true;
  try {
    T rc = fn();
    g_exit_guarded = false;
    finish();
    return rc;
  } catch (const interr_exc_t &) {
    g_exit_guarded = false;
    g_trapped = true;
    finish();
    return trapval;
  }
}

} // namespace idakit_facade

#endif // IDAKIT_FACADE_INTERNAL_HPP
