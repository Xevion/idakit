// Shared facade internals: the fatal-trap state and the guarded<> wrapper. The trap machinery
// is defined in runtime.cpp; only runtime.cpp and hexrays.cpp (decompile) need it.
#ifndef IDAKIT_FACADE_INTERNAL_HPP
#define IDAKIT_FACADE_INTERNAL_HPP

#include <csetjmp>
#include <cstdio>
#include <string>

#include "idakit_facade.h"

namespace idakit_facade {

extern thread_local jmp_buf g_exit_jmp;
extern thread_local bool g_exit_guarded;
extern thread_local bool g_trapped;
extern thread_local int g_exit_code;
extern thread_local std::string g_output;

void install_fatal_traps();
FILE *begin_capture(int *saved_out, int *saved_err);
void end_capture(FILE *cap, int saved_out, int saved_err);

// Run fn() with the fatal traps armed: if IDA tries to exit() or abort() during the call,
// longjmp back here and return `trapval` instead of letting the process die. `capture`
// redirects IDA's stdout+stderr for the duration. The longjmp stays within this C call chain
// -- fn() is a facade lambda calling the SDK directly, with no Rust frame to unwind.
template <class T, class F> T guarded(T trapval, bool capture, F &&fn) {
  install_fatal_traps();
  g_trapped = false;
  g_output.clear();
  int saved_out = -1, saved_err = -1;
  FILE *cap = capture ? begin_capture(&saved_out, &saved_err) : nullptr;
  if (setjmp(g_exit_jmp) != 0) {
    g_trapped = true;
    if (cap != nullptr)
      end_capture(cap, saved_out, saved_err);
    return trapval;
  }
  g_exit_guarded = true;
  T rc = fn();
  g_exit_guarded = false;
  if (cap != nullptr)
    end_capture(cap, saved_out, saved_err);
  return rc;
}

} // namespace idakit_facade

#endif // IDAKIT_FACADE_INTERNAL_HPP
