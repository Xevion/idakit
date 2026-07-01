// idakit facade: kernel lifecycle (open/analyze/close, EULA) and the fatal-exit trap that
// guards it. qstrings live and die here; callers get plain copied-out C strings.

#include <pro.h>

#include <ida.hpp>

#include <auto.hpp>     // auto_wait
#include <idalib.hpp>   // open_database
#include <registry.hpp> // reg_read_int/reg_write_bool (EULA acceptance)

#include <csetjmp> // setjmp/longjmp exit trap
#include <cstdint> // uintptr_t
#include <cstdio>  // fflush, tmpfile
#include <cstdlib> // std::abort
#include <cstring>
#include <dlfcn.h> // dlsym
#include <elf.h>   // ELF64_R_SYM
#include <link.h>  // dl_iterate_phdr, ElfW
#include <string>
#include <sys/mman.h> // mprotect
#include <unistd.h>   // dup/dup2/read/lseek

#include "idakit_facade_internal.hpp"

// The SDK's pro.h poisons direct stdio (#define stdout dont_use_stdout, ...) to push
// callers onto IDA's own msg()/qfflush wrappers. The fatal-exit output capture works at
// the libc/fd level deliberately -- it must catch whatever IDA writes, however it writes
// it -- so undo the poisoning for the handful of symbols it uses.
#undef stdout
#undef stderr
#undef fflush
#undef fclose
#undef tmpfile
#undef fileno

// Fatal-exit trap.
// IDA reports unrecoverable conditions (e.g. an unaccepted license) by calling
// verror() -> qexit() -> libc exit(): it terminates the whole process instead of
// returning an error a library caller could handle. We redirect libida's own call
// table (GOT) entry for exit() to our handler: while a guarded kernel call is on the
// stack we convert the exit into a longjmp back to the guard and report it as an error;
// outside a guarded call we defer to the real exit so ordinary shutdown is untouched.
//
// GOT patching (rather than ELF symbol interposition) is deliberate: it needs no special
// link flag on the final executable, so the trap works for any binary that links idakit.
namespace idakit_facade {

// libida's verror/qexit frames carry no unwind info -- a C++ exception thrown from our
// exit() stand-in aborts (SIGABRT) trying to propagate through them. longjmp does not
// rely on unwind info (it just restores the stack pointer), so it is the only mechanism
// that escapes a fatal exit. It must jump back to a setjmp in the *same C call chain*,
// with no Rust frame in between (Rust frames have no longjmp support and would leak/UB).
thread_local jmp_buf g_exit_jmp;
thread_local bool g_exit_guarded = false;
thread_local int g_exit_code = 0;
// True if the most recent guarded call trapped a fatal exit() rather than completing.
thread_local bool g_trapped = false;
// Captured stdout+stderr from the last guarded call.
thread_local std::string g_output;

namespace {
typedef void (*exit_fn)(int);
exit_fn g_real_exit = nullptr;
bool g_trap_installed = false;

// Our stand-in for libida's exit(): jump back to the armed guard if a guarded kernel call
// is on the stack, else fall through to the real libc exit so normal teardown still works.
void idakit_exit(int status) {
  if (g_exit_guarded) {
    g_exit_guarded = false;
    g_exit_code = status;
    longjmp(g_exit_jmp, 1);
  }
  if (g_real_exit != nullptr)
    g_real_exit(status);
  _exit(status);
}

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
// relocations and point its `exit` slot at idakit_exit.
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
    }
  }
  if (symtab == nullptr || strtab == nullptr)
    return 0;

  void *trap = reinterpret_cast<void *>(&idakit_exit);
  if (jmprel != nullptr && pltrelsz > 0)
    scan_rela(info->dlpi_addr, jmprel, pltrelsz / sizeof(ElfW(Rela)), symtab, strtab, "exit", trap);
  if (rela != nullptr && relasz > 0 && relaent > 0)
    scan_rela(info->dlpi_addr, rela, relasz / relaent, symtab, strtab, "exit", trap);
  return 0;
}
} // namespace

// Point libida's exit() at our handler. Idempotent; safe to call before every guarded
// entry (the work happens once).
void install_exit_trap() {
  if (g_trap_installed)
    return;
  g_trap_installed = true;
  g_real_exit = reinterpret_cast<exit_fn>(dlsym(RTLD_DEFAULT, "exit"));
  dl_iterate_phdr(patch_cb, nullptr);
}

// Redirect fd 1 and 2 to a fresh temp file, saving the originals. Returns the capture
// FILE* (nullptr if capture could not be set up, in which case fds are untouched). IDA
// writes diagnostics (the "License not yet accepted" line, analysis chatter) straight to
// the process's stdout; capturing keeps that off the caller's console so the text can ride
// along with the error instead.
FILE *begin_capture(int *saved_out, int *saved_err) {
  fflush(stdout);
  fflush(stderr);
  FILE *cap = tmpfile();
  if (cap == nullptr)
    return nullptr;
  int cap_fd = fileno(cap);
  *saved_out = dup(1);
  *saved_err = dup(2);
  dup2(cap_fd, 1);
  dup2(cap_fd, 2);
  return cap;
}

// Restore the original fds and read everything written during the capture into g_output.
void end_capture(FILE *cap, int saved_out, int saved_err) {
  if (cap == nullptr)
    return;
  fflush(stdout);
  fflush(stderr);
  dup2(saved_out, 1);
  dup2(saved_err, 2);
  close(saved_out);
  close(saved_err);

  int fd = fileno(cap);
  off_t end = lseek(fd, 0, SEEK_END);
  g_output.clear();
  if (end > 0) {
    g_output.resize((size_t)end);
    lseek(fd, 0, SEEK_SET);
    ssize_t got = read(fd, &g_output[0], (size_t)end);
    g_output.resize(got > 0 ? (size_t)got : 0);
  }
  fclose(cap);
}

} // namespace idakit_facade

using namespace idakit_facade;

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

// Record acceptance of the IDA end-user license agreement in the registry -- exactly
// what the GUI writes when the user clicks Accept. Without it, headless idalib refuses
// to open a database ("License not yet accepted, cannot run in batch mode"). The key is
// "EULA <version>"; 90 is the version this IDA 9.3 runtime checks. Idempotent. Returns
// the key's value after writing (nonzero = accepted).
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
