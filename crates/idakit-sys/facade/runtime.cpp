// idakit facade: kernel lifecycle (open/analyze/close, EULA) and the fatal-exit trap that
// guards it. qstrings live and die here; callers get plain copied-out C strings.

#include <pro.h>

#include <ida.hpp>

#include <auto.hpp>     // auto_wait
#include <idalib.hpp>   // open_database
#include <kernwin.hpp>  // batch
#include <registry.hpp> // reg_read_int/reg_write_bool (EULA acceptance)

#include <csetjmp> // setjmp/longjmp exit trap
#include <cstdint> // uintptr_t
#include <cstdio>  // fflush
#include <cstdlib> // std::abort
#include <cstring>
#include <string>

// Platform split. The fatal-exit trap is ELF-specific (it rewrites libida's GOT slots), so it
// only compiles on Linux; elsewhere `install_fatal_traps` is a no-op and IDA's exit()/abort()
// still kill the process, exactly as raw idalib does. fd capture is portable POSIX, kept on
// Linux+macOS and stubbed on Windows. The interr trap in `guarded<>` is pure C++ and works
// everywhere. See idakit_facade_internal.hpp for `guarded<>`.
#if defined(_WIN32)
#include <process.h> // _exit
#else
#include <fcntl.h>  // open (/dev/null), fcntl (O_NONBLOCK)
#include <unistd.h> // pipe/dup/dup2/read/close/_exit
#endif

#if defined(__linux__)
#include <dlfcn.h>    // dlsym
#include <elf.h>      // ELF64_R_SYM
#include <link.h>     // dl_iterate_phdr, ElfW
#include <sys/mman.h> // mprotect
#endif

#include "idakit_facade_internal.hpp"

// pro.h poisons libc calls (#define stdout/setenv/... to dont_use_ names) to push callers
// onto IDA's wrappers. We deliberately want raw libc here: fd-level capture must catch
// whatever IDA writes however it writes it, and TVHEADLESS must land in the real
// environment libidalib reads. Undo the poisoning for the symbols we call directly.
#undef stdout
#undef stderr
#undef fflush
#undef setenv

// Fatal traps.
// IDA kills the process on unrecoverable conditions instead of returning an error: an
// unaccepted license runs verror() -> qexit() -> exit(), and bundled LLVM/libc++ asserts
// call abort() directly. We redirect libida's GOT slots for both to our handlers: inside a
// guarded call they longjmp back and report an error; outside one they defer to the real
// exit/abort, leaving ordinary shutdown and genuine crashes untouched. GOT patching (not
// symbol interposition) needs no link flag, so it works for any binary linking idakit.
namespace idakit_facade {

// libida's frames carry no unwind info, so a C++ throw from our stand-in can't propagate
// through them -- longjmp can (it just restores the stack pointer). It must reach a setjmp
// in the same C call chain, with no Rust frame between (Rust can't be longjmped over).
thread_local jmp_buf g_exit_jmp;
thread_local bool g_exit_guarded = false;
thread_local int g_exit_code = 0;
// True if the most recent guarded call trapped a fatal exit() rather than completing.
thread_local bool g_trapped = false;
// Captured stdout+stderr from the last guarded call.
thread_local std::string g_output;

namespace {
typedef void (*exit_fn)(int);
typedef void (*abort_fn)(void);
exit_fn g_real_exit = nullptr;
abort_fn g_real_abort = nullptr;
bool g_trap_installed = false;

// Our stand-in for libida's exit(): jump back to the armed guard if a guarded kernel call
// is on the stack, else fall through to the real libc exit so normal teardown still works.
// Off Linux nothing installs it into the GOT, so it's only reached (inside a guard) by the
// test shim -- hence maybe_unused there.
[[maybe_unused]] void idakit_exit(int status) {
  if (g_exit_guarded) {
    g_exit_guarded = false;
    g_exit_code = status;
    longjmp(g_exit_jmp, 1);
  }
  if (g_real_exit != nullptr)
    g_real_exit(status);
  _exit(status);
}

// Same escape as idakit_exit, for the abort() path; defer to the real abort outside a guard.
[[maybe_unused]] [[noreturn]] void idakit_abort(void) {
  if (g_exit_guarded) {
    g_exit_guarded = false;
    g_exit_code = 134; // 128 + SIGABRT
    longjmp(g_exit_jmp, 1);
  }
  if (g_real_abort != nullptr)
    g_real_abort();
  _exit(134);
}

#if defined(__linux__)
// Overwrite one GOT slot, handling a possibly read-only (RELRO) page. Left writable
// afterward, which is the normal state of the lazy-bound .got.plt this targets.
void patch_slot(void **slot, void *newval) {
  long pg = sysconf(_SC_PAGESIZE);
  uintptr_t addr = reinterpret_cast<uintptr_t>(slot);
  uintptr_t page = addr & ~(uintptr_t)(pg - 1);
  size_t len = (addr + sizeof(void *)) - page;
  if (mprotect(reinterpret_cast<void *>(page), len, PROT_READ | PROT_WRITE) != 0)
    return;
  *slot = newval;
}

// Redirect any relocation in [rela, rela+count) that resolves `symname` to `newfn`.
void scan_rela(ElfW(Addr) base, const ElfW(Rela) * rela, size_t count, const ElfW(Sym) * symtab,
               const char *strtab, const char *symname, void *newfn) {
  for (size_t i = 0; i < count; i++) {
    unsigned long sym = ELF64_R_SYM(rela[i].r_info);
    const char *name = strtab + symtab[sym].st_name;
    if (strcmp(name, symname) == 0)
      patch_slot(reinterpret_cast<void **>(base + rela[i].r_offset), newfn);
  }
}

// dl_iterate_phdr callback: for each loaded libida*/libidalib* object, walk its dynamic
// relocations and point its `exit`/`abort` slots at our stand-ins.
int patch_cb(struct dl_phdr_info *info, size_t, void *) {
  const char *objname = info->dlpi_name != nullptr ? info->dlpi_name : "";
  if (strstr(objname, "libida") == nullptr)
    return 0;

  const ElfW(Dyn) *dyn = nullptr;
  for (int i = 0; i < info->dlpi_phnum; i++) {
    if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
      dyn = reinterpret_cast<const ElfW(Dyn) *>(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
      break;
    }
  }
  if (dyn == nullptr)
    return 0;

  // .dynamic pointers may be stored as link-time vaddrs (need the load base added) or
  // already relocated to absolute; a value below the load base is the former.
  auto fixptr = [&](ElfW(Addr) p) -> ElfW(Addr) {
    return p < info->dlpi_addr ? info->dlpi_addr + p : p;
  };

  const ElfW(Sym) *symtab = nullptr;
  const char *strtab = nullptr;
  const ElfW(Rela) *jmprel = nullptr, *rela = nullptr;
  size_t pltrelsz = 0, relasz = 0, relaent = sizeof(ElfW(Rela));
  for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
    switch (d->d_tag) {
    case DT_SYMTAB:
      symtab = reinterpret_cast<const ElfW(Sym) *>(fixptr(d->d_un.d_ptr));
      break;
    case DT_STRTAB:
      strtab = reinterpret_cast<const char *>(fixptr(d->d_un.d_ptr));
      break;
    case DT_JMPREL:
      jmprel = reinterpret_cast<const ElfW(Rela) *>(fixptr(d->d_un.d_ptr));
      break;
    case DT_PLTRELSZ:
      pltrelsz = d->d_un.d_val;
      break;
    case DT_RELA:
      rela = reinterpret_cast<const ElfW(Rela) *>(fixptr(d->d_un.d_ptr));
      break;
    case DT_RELASZ:
      relasz = d->d_un.d_val;
      break;
    case DT_RELAENT:
      relaent = d->d_un.d_val;
      break;
    default:
      break;
    }
  }
  if (symtab == nullptr || strtab == nullptr)
    return 0;

  void *exit_trap = reinterpret_cast<void *>(&idakit_exit);
  void *abort_trap = reinterpret_cast<void *>(&idakit_abort);
  if (jmprel != nullptr && pltrelsz > 0) {
    size_t n = pltrelsz / sizeof(ElfW(Rela));
    scan_rela(info->dlpi_addr, jmprel, n, symtab, strtab, "exit", exit_trap);
    scan_rela(info->dlpi_addr, jmprel, n, symtab, strtab, "abort", abort_trap);
  }
  if (rela != nullptr && relasz > 0 && relaent > 0) {
    size_t n = relasz / relaent;
    scan_rela(info->dlpi_addr, rela, n, symtab, strtab, "exit", exit_trap);
    scan_rela(info->dlpi_addr, rela, n, symtab, strtab, "abort", abort_trap);
  }
  return 0;
}
#endif // __linux__
} // namespace

// Point libida's exit()/abort() at our handlers. Idempotent; safe to call before every
// guarded entry (the work happens once). Only the ELF GOT rewrite is implemented, so off
// Linux this is a no-op: those fatals fall through to the real exit/abort (process dies),
// while the interr trap in `guarded<>` still catches the common case everywhere.
void install_fatal_traps() {
  if (g_trap_installed)
    return;
  g_trap_installed = true;
#if defined(__linux__)
  g_real_exit = reinterpret_cast<exit_fn>(dlsym(RTLD_DEFAULT, "exit"));
  g_real_abort = reinterpret_cast<abort_fn>(dlsym(RTLD_DEFAULT, "abort"));
  dl_iterate_phdr(patch_cb, nullptr);
#endif
}

#if !defined(_WIN32)
// Redirect fd 1+2 into an in-memory pipe (no temp file), saving the originals. The write end
// is non-blocking: only small fatal error() text lands here, so were it ever to exceed the
// pipe buffer the excess drops rather than deadlocking the writer. POSIX primitive (pipe/dup2;
// Windows would need _pipe/_dup2 and a different non-blocking scheme, so it's stubbed there).
// `rd < 0` => setup failed, fds untouched. IDA writes diagnostics straight to fd 1/2, so this
// keeps them off the caller's console to ride along with the error instead.
capture_t begin_capture() {
  capture_t cap;
  (void)fflush(stdout);
  (void)fflush(stderr);
  int fds[2];
  if (pipe(fds) != 0)
    return cap;
  int fl = fcntl(fds[1], F_GETFL, 0);
  if (fl != -1)
    (void)fcntl(fds[1], F_SETFL, fl | O_NONBLOCK);
  cap.rd = fds[0];
  cap.wr = fds[1];
  cap.saved_out = dup(1);
  cap.saved_err = dup(2);
  dup2(fds[1], 1);
  dup2(fds[1], 2);
  return cap;
}

// Restore the original fds, then drain the pipe into g_output.
void end_capture(capture_t &cap) {
  if (cap.rd < 0)
    return;
  (void)fflush(stdout);
  (void)fflush(stderr);
  // Only restore fds that begin_capture actually saved (dup can fail, leaving -1).
  if (cap.saved_out >= 0) {
    dup2(cap.saved_out, 1);
    close(cap.saved_out);
  }
  if (cap.saved_err >= 0) {
    dup2(cap.saved_err, 2);
    close(cap.saved_err);
  }
  close(cap.wr); // drop the last write end so the drain read sees EOF
  g_output.clear();
  char buf[4096];
  for (;;) {
    ssize_t n = read(cap.rd, buf, sizeof(buf));
    if (n <= 0)
      break;
    g_output.append(buf, static_cast<size_t>(n));
  }
  close(cap.rd);
  cap.rd = -1;
}
#else
// Windows stub: no fd redirection (see begin_capture). `rd` stays -1 so a guarded call runs
// unredirected and end_capture is a no-op; g_output is left empty.
capture_t begin_capture() { return capture_t{}; }
void end_capture(capture_t &cap) { (void)cap; }
#endif // !_WIN32

} // namespace idakit_facade

using namespace idakit_facade;

// libidalib's init registers an atexit that prints a goodbye banner to stdout, corrupting
// parsers like `nextest --list`. Our constructor runs after that init, so our atexit runs
// before the banner (LIFO): redirecting fd 1 to /dev/null at exit swallows it, leaving
// already-written run-time output untouched. POSIX-only (constructor attribute + /dev/null);
// harmless to skip elsewhere -- the banner just isn't suppressed.
#if !defined(_WIN32)
namespace {
void swallow_exit_banner() {
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0) {
    (void)fflush(stdout);
    dup2(devnull, 1);
    close(devnull);
  }
}
__attribute__((constructor)) void install_exit_banner_filter() {
  (void)atexit(swallow_exit_banner);
}
} // namespace
#endif // !_WIN32

// libidalib reads TVHEADLESS to stay off the GUI/Qt path but never sets it, so set it here
// before init runs. Setting it in C (not the Rust env API) keeps this off the edition-2024
// unsafe set_var race and colocates it with init.
extern "C" int idakit_init_library(void) {
#if defined(_WIN32)
  _putenv_s("TVHEADLESS", "1");
#else
  setenv("TVHEADLESS", "1", 1);
#endif
  return init_library(0, nullptr);
}

// nonzero -> suppress dialogs / auto-answer prompts (headless default); zero -> interactive.
extern "C" void idakit_set_batch(int on) { batch = on != 0; }

// Returns open_database's rc, or IDAKIT_EXIT_TRAPPED if the kernel tried to exit() during
// the call (then idakit_last_exit_code()/idakit_last_output() carry the detail).
extern "C" int idakit_guarded_open(const char *file_path, int run_auto) {
  return guarded<int>(IDAKIT_EXIT_TRAPPED, true,
                      [&] { return open_database(file_path, run_auto != 0, nullptr); });
}

// Guarded auto-analysis wait: 1 on success, 0 on failure, IDAKIT_EXIT_TRAPPED on a trapped
// fatal. Analysis can run arbitrary kernel code, so it gets the same protection as open.
extern "C" int idakit_guarded_auto_wait(void) {
  return guarded<int>(IDAKIT_EXIT_TRAPPED, false, [] { return auto_wait() ? 1 : 0; });
}

// Guarded close: 0 normally, IDAKIT_EXIT_TRAPPED if a fatal fired while flushing/saving.
extern "C" int idakit_guarded_close(int save) {
  return guarded<int>(IDAKIT_EXIT_TRAPPED, false, [&] {
    close_database(save != 0);
    return 0;
  });
}

extern "C" int idakit_last_exit_code(void) { return g_exit_code; }

extern "C" int idakit_was_trapped(void) { return g_trapped ? 1 : 0; }

extern "C" int idakit_reg_read_int(const char *name, int defval) {
  return reg_read_int(name, defval, nullptr);
}

// Write EULA acceptance to the registry, as the GUI does on Accept; without it headless
// idalib refuses to open ("License not yet accepted"). Key is "EULA <version>"; 90 is what
// IDA 9.3 checks. Idempotent; returns the value after writing (nonzero = accepted).
extern "C" int idakit_accept_eula(void) {
  reg_write_bool("EULA 90", 1, nullptr);
  return reg_read_int("EULA 90", 0, nullptr);
}

// Copy the last guarded call's captured stdout+stderr into buf; returns its full length
// (which may exceed cap, like snprintf). Pass cap==0 to query the length.
extern "C" size_t idakit_last_output(char *buf, size_t cap) {
  size_t n = g_output.size();
  if (buf != nullptr && cap > 0) {
    size_t copy = n < cap - 1 ? n : cap - 1;
    memcpy(buf, g_output.data(), copy);
    buf[copy] = 0;
  }
  return n;
}

#ifdef IDAKIT_TEST_SHIMS
// Run the chosen fatal inside guarded<> so the trap tests can prove it's caught: the exit/abort
// stand-ins libida's patched GOT slots point at (the longjmp path), or interr (the throw path).
extern "C" int idakit_test_fatal(int kind) {
  return guarded<int>(IDAKIT_EXIT_TRAPPED, false, [kind]() -> int {
    if (kind == IDAKIT_FATAL_EXIT)
      idakit_exit(42);
    else if (kind == IDAKIT_FATAL_ABORT)
      idakit_abort();
    else if (kind == IDAKIT_FATAL_INTERR)
      interr(1);
    return 0;
  });
}

extern "C" int idakit_get_batch(void) { return batch ? 1 : 0; }
#endif
