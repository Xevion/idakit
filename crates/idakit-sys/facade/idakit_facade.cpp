// idakit facade implementation. Includes the IDA SDK (C++) and exposes a clean C
// ABI. qstrings live and die here; callers get plain copied-out C strings.
//
// Include order mirrors the SDK's own idalib example (idacli.cpp): pro.h, ida.hpp,
// then the specific subsystem headers.

#include <bytes.hpp> // get_bytes
#include <funcs.hpp>
#include <hexrays.hpp>
#include <ida.hpp>
#include <idp.hpp>    // HEXDSP / get_hexdsp
#include <intel.hpp>  // x86 operand types + REX-aware SIB accessors (x86_base_reg, ...)
#include <lines.hpp>  // tag_remove
#include <loader.hpp> // load_plugin
#include <nalt.hpp>   // get_input_file_path, get_root_filename, get_imagebase
#include <name.hpp>
#include <pro.h>
#include <registry.hpp> // reg_read_int/reg_write_bool (EULA acceptance)
#include <segment.hpp>
#include <typeinf.hpp> // tinfo_t, udt_type_data_t, print_type
#include <ua.hpp>      // decode_insn, insn_t, op_t
#include <xref.hpp>    // xrefblk_t

#include <auto.hpp>   // auto_wait
#include <idalib.hpp> // open_database

#include <csetjmp> // setjmp/longjmp exit trap
#include <cstdint> // uintptr_t
#include <cstdio>  // fflush, tmpfile
#include <cstdlib> // std::abort
#include <cstring>
#include <dlfcn.h> // dlsym
#include <elf.h>   // ELF64_R_SYM
#include <fcntl.h> // open (O_WRONLY, /dev/null redirect)
#include <link.h>  // dl_iterate_phdr, ElfW
#include <set>
#include <string>
#include <sys/mman.h> // mprotect
#include <unistd.h>   // dup/dup2/read/lseek
#include <vector>

#include "idakit_facade.h"

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
namespace {
// libida's verror/qexit frames carry no unwind info -- a C++ exception thrown from our
// exit() stand-in aborts (SIGABRT) trying to propagate through them. longjmp does not
// rely on unwind info (it just restores the stack pointer), so it is the only mechanism
// that escapes a fatal exit. It must jump back to a setjmp in the *same C call chain*,
// with no Rust frame in between (Rust frames have no longjmp support and would leak/UB).
thread_local jmp_buf g_exit_jmp;
thread_local bool g_exit_guarded = false;
thread_local int g_exit_code = 0;

typedef void (*exit_fn)(int);
exit_fn g_real_exit = nullptr;

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

bool g_trap_installed = false;

// Point libida's exit() at our handler. Idempotent; safe to call before every guarded
// entry (the work happens once).
void install_exit_trap() {
  if (g_trap_installed)
    return;
  g_trap_installed = true;
  g_real_exit = reinterpret_cast<exit_fn>(dlsym(RTLD_DEFAULT, "exit"));
  dl_iterate_phdr(patch_cb, nullptr);
}

// Captured stdout+stderr from the last guarded call. IDA writes diagnostics (the
// "License not yet accepted" line, analysis chatter) straight to the process's stdout;
// we redirect both fds to a temp file around the call so nothing leaks to the caller's
// console and the text can ride along with the error instead.
thread_local std::string g_output;

// Redirect fd 1 and 2 to a fresh temp file, saving the originals. Returns the capture
// FILE* (nullptr if capture could not be set up, in which case fds are untouched).
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

// libida prints a farewell ("Thank you for using IDA. Have a nice day!") on stdout from a
// load-time exit hook, during process teardown -- after the program's own output has
// flushed. That corrupts any machine-readable stdout (a test runner enumerating tests, JSON
// on stdout, ...). Point fd 1 at /dev/null so the farewell goes nowhere; stderr is left
// alone, so a genuine teardown diagnostic still surfaces. Registered via atexit from a
// load-time constructor: libida is a link dependency, so its constructors -- and thus its
// farewell-hook registration -- run before ours, and atexit's LIFO order then runs ours
// first, before the farewell is written.
void squelch_exit_banner() {
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull < 0)
    return;
  fflush(stdout);
  dup2(devnull, 1);
  close(devnull);
}

__attribute__((constructor)) void install_exit_squelch() { atexit(squelch_exit_banner); }
} // namespace

namespace {
// True if the most recent guarded call trapped a fatal exit() rather than completing.
thread_local bool g_trapped = false;

// Run fn() with the exit trap armed: if IDA tries to exit() during the call, longjmp back
// here and return `trapval` instead of letting the process die. `capture` redirects IDA's
// stdout+stderr for the duration (worth it on one-shot calls like open, where the license
// diagnostic appears; skipped on hot paths like decompile). After a trap,
// idakit_last_exit_code() holds the code, idakit_was_trapped() is true, and (when captured)
// idakit_last_output() holds what IDA printed. The longjmp stays within this C call chain --
// fn() is a facade lambda calling the SDK directly, with no Rust frame to unwind.
template <class T, class F> T guarded(T trapval, bool capture, F &&fn) {
  install_exit_trap();
  g_trapped = false;
  // Drop any capture from a prior call so idakit_last_output() never reports stale text:
  // an uncaptured call that traps (e.g. decompile) would otherwise surface a *previous*
  // captured call's output as its diagnostic. A capturing call refills this via end_capture.
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
} // namespace

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

extern "C" size_t idakit_func_qty(void) { return get_func_qty(); }

extern "C" idakit_ea_t idakit_func_ea(size_t n) {
  func_t *f = getn_func(n);
  return f != nullptr ? (idakit_ea_t)f->start_ea : (idakit_ea_t)BADADDR;
}

extern "C" int64_t idakit_func_name(idakit_ea_t ea, char *buf, size_t cap) {
  // A C++ exception (e.g. std::bad_alloc from qstring/STL growth) must never unwind across
  // an extern "C" boundary into Rust frames -- that is undefined behavior. Every facade
  // body that can allocate traps it here and aborts rather than letting it escape.
  try {
    qstring out;
    ssize_t r = get_func_name(&out, (ea_t)ea);
    if (r <= 0) {
      if (cap > 0)
        buf[0] = 0;
      return r;
    }
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

extern "C" int idakit_func_chunk_qty(idakit_ea_t ea) {
  func_t *pfn = get_func((ea_t)ea);
  if (pfn == nullptr)
    return 0;
  int n = 0;
  func_tail_iterator_t fti(pfn);
  for (bool ok = fti.main(); ok; ok = fti.next())
    n++;
  return n;
}

// main() yields the entry chunk first, then next() walks the tails; a single-chunk function
// is just the entry chunk. get_func locks nothing lasting -- the iterator's dtor unlocks.
extern "C" int idakit_func_chunk(idakit_ea_t ea, int idx, idakit_ea_t *start, idakit_ea_t *end) {
  func_t *pfn = get_func((ea_t)ea);
  if (pfn == nullptr)
    return 0;
  int n = 0;
  func_tail_iterator_t fti(pfn);
  for (bool ok = fti.main(); ok; ok = fti.next(), n++) {
    if (n == idx) {
      const range_t &r = fti.chunk();
      *start = (idakit_ea_t)r.start_ea;
      *end = (idakit_ea_t)r.end_ea;
      return 1;
    }
  }
  return 0;
}

extern "C" int idakit_seg_qty(void) { return get_segm_qty(); }

extern "C" int64_t idakit_seg_name(int n, char *buf, size_t cap) {
  try {
    segment_t *s = getnseg(n);
    if (s == nullptr) {
      if (cap > 0)
        buf[0] = 0;
      return -1;
    }
    qstring out;
    get_visible_segm_name(&out, s);
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

extern "C" idakit_ea_t idakit_seg_start(int n) {
  segment_t *s = getnseg(n);
  return s != nullptr ? (idakit_ea_t)s->start_ea : (idakit_ea_t)BADADDR;
}

extern "C" idakit_ea_t idakit_seg_end(int n) {
  segment_t *s = getnseg(n);
  return s != nullptr ? (idakit_ea_t)s->end_ea : (idakit_ea_t)BADADDR;
}

extern "C" int64_t idakit_get_bytes(idakit_ea_t ea, void *buf, size_t size) {
  return (int64_t)get_bytes(buf, (ssize_t)size, (ea_t)ea, GMB_READALL);
}

extern "C" uint64_t idakit_get_flags(idakit_ea_t ea) { return (uint64_t)get_flags((ea_t)ea); }

extern "C" idakit_ea_t idakit_get_item_head(idakit_ea_t ea) {
  return (idakit_ea_t)get_item_head((ea_t)ea);
}

extern "C" idakit_ea_t idakit_get_item_end(idakit_ea_t ea) {
  return (idakit_ea_t)get_item_end((ea_t)ea);
}

extern "C" idakit_ea_t idakit_get_next_head(idakit_ea_t ea, idakit_ea_t maxea) {
  return (idakit_ea_t)next_head((ea_t)ea, (ea_t)maxea);
}

extern "C" idakit_ea_t idakit_get_prev_head(idakit_ea_t ea, idakit_ea_t minea) {
  return (idakit_ea_t)prev_head((ea_t)ea, (ea_t)minea);
}

extern "C" int idakit_bitness(void) { return (int)inf_get_app_bitness(); }

extern "C" idakit_ea_t idakit_image_base(void) { return (idakit_ea_t)get_imagebase(); }

extern "C" int64_t idakit_proc_name(char *buf, size_t cap) {
  try {
    qstring out = inf_get_procname();
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

extern "C" int64_t idakit_file_type_name(char *buf, size_t cap) {
  // get_file_type_name writes directly and returns the length it produced.
  return (int64_t)get_file_type_name(buf, cap);
}

extern "C" int64_t idakit_input_path(char *buf, size_t cap) {
  // get_input_file_path goes through getinf_buf, whose count includes the trailing NUL;
  // report the string length like the other getters so read_string slices it cleanly.
  ssize_t n = get_input_file_path(buf, cap);
  return n > 0 ? (int64_t)(n - 1) : -1;
}

extern "C" int64_t idakit_root_filename(char *buf, size_t cap) {
  return (int64_t)get_root_filename(buf, cap);
}

extern "C" int64_t idakit_get_ea_name(idakit_ea_t ea, char *buf, size_t cap) {
  try {
    qstring out;
    if (get_ea_name(&out, (ea_t)ea) <= 0) {
      if (cap > 0)
        buf[0] = 0;
      return -1;
    }
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

extern "C" idakit_ea_t idakit_get_name_ea(const char *name) {
  return (idakit_ea_t)get_name_ea(BADADDR, name);
}

// Full demangle (disable_mask 0). An unmangled name leaves `out` empty, reported as -1 so
// the caller sees "not mangled" rather than an empty string.
extern "C" int64_t idakit_demangle_name(const char *name, char *buf, size_t cap) {
  try {
    qstring out;
    demangle_name(&out, name, 0);
    if (out.empty()) {
      if (cap > 0)
        buf[0] = 0;
      return -1;
    }
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

extern "C" size_t idakit_nlist_size(void) { return get_nlist_size(); }

extern "C" idakit_ea_t idakit_nlist_ea(size_t idx) { return (idakit_ea_t)get_nlist_ea(idx); }

extern "C" int64_t idakit_nlist_name(size_t idx, char *buf, size_t cap) {
  const char *nm = get_nlist_name(idx);
  if (nm == nullptr) {
    if (cap > 0)
      buf[0] = 0;
    return -1;
  }
  qstrncpy(buf, nm, cap);
  return (int64_t)qstrlen(nm);
}

// Cursor state for a streaming xref walk. `started` distinguishes the first_* call
// (which seeds the block) from subsequent next_* steps.
struct idakit_xref_cursor {
  xrefblk_t xb;
  ea_t ea;
  bool is_to;
  bool started;
};

extern "C" void *idakit_xref_open(idakit_ea_t ea, uint8_t is_to) {
  auto *c = new idakit_xref_cursor;
  c->ea = (ea_t)ea;
  c->is_to = is_to != 0;
  c->started = false;
  return c;
}

extern "C" uint8_t idakit_xref_next(void *cursor, idakit_ea_t *from, idakit_ea_t *to, uint8_t *type,
                                    uint8_t *iscode) {
  auto *c = (idakit_xref_cursor *)cursor;
  bool ok;
  if (!c->started) {
    c->started = true;
    ok = c->is_to ? c->xb.first_to(c->ea, XREF_NOFLOW) : c->xb.first_from(c->ea, XREF_NOFLOW);
  } else {
    ok = c->is_to ? c->xb.next_to() : c->xb.next_from();
  }
  if (!ok)
    return 0;
  *from = (idakit_ea_t)c->xb.from;
  *to = (idakit_ea_t)c->xb.to;
  *type = c->xb.type;
  *iscode = c->xb.iscode;
  return 1;
}

extern "C" void idakit_xref_close(void *cursor) { delete (idakit_xref_cursor *)cursor; }

extern "C" int64_t idakit_func_type(idakit_ea_t ea, char *buf, size_t cap) {
  try {
    qstring out;
    if (!print_type(&out, (ea_t)ea, PRTYPE_1LINE | PRTYPE_SEMI)) {
      if (cap > 0)
        buf[0] = 0;
      return -1;
    }
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

// A resolved named type plus its expanded member layout (if it is a struct/union).
struct idakit_type_t {
  tinfo_t tif;
  udt_type_data_t udt;
  bool is_udt = false;
};

extern "C" void *idakit_type_open(const char *name) {
  try {
    idakit_type_t *t = new idakit_type_t;
    if (!t->tif.get_named_type(get_idati(), name)) {
      delete t;
      return nullptr;
    }
    t->is_udt = t->tif.get_udt_details(&t->udt);
    return t;
  } catch (...) {
    std::abort();
  }
}

extern "C" void idakit_type_dispose(void *h) { delete reinterpret_cast<idakit_type_t *>(h); }

extern "C" int64_t idakit_type_size(void *h) {
  size_t s = reinterpret_cast<idakit_type_t *>(h)->tif.get_size();
  return s == BADSIZE ? -1 : (int64_t)s;
}

extern "C" int64_t idakit_type_print(void *h, char *buf, size_t cap) {
  try {
    qstring out;
    if (!reinterpret_cast<idakit_type_t *>(h)->tif.print(&out)) {
      if (cap > 0)
        buf[0] = 0;
      return -1;
    }
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

extern "C" size_t idakit_type_nmembers(void *h) {
  idakit_type_t *t = reinterpret_cast<idakit_type_t *>(h);
  return t->is_udt ? t->udt.size() : 0;
}

// Split into a metadata call + two length-returning string getters so the caller
// can detect truncation and re-read; a combined call could only return a bool.
extern "C" int idakit_type_member_info(void *h, size_t i, uint64_t *offset, uint64_t *size) {
  idakit_type_t *t = reinterpret_cast<idakit_type_t *>(h);
  if (!t->is_udt || i >= t->udt.size())
    return 0;
  const udm_t &m = t->udt[i];
  *offset = m.offset / 8; // SDK reports member offset/size in bits
  *size = m.size / 8;
  return 1;
}

extern "C" int64_t idakit_type_member_name(void *h, size_t i, char *buf, size_t cap) {
  idakit_type_t *t = reinterpret_cast<idakit_type_t *>(h);
  if (!t->is_udt || i >= t->udt.size()) {
    if (cap > 0)
      buf[0] = 0;
    return -1;
  }
  const qstring &name = t->udt[i].name;
  qstrncpy(buf, name.c_str(), cap);
  return (int64_t)name.length();
}

extern "C" int64_t idakit_type_member_type(void *h, size_t i, char *buf, size_t cap) {
  try {
    idakit_type_t *t = reinterpret_cast<idakit_type_t *>(h);
    if (!t->is_udt || i >= t->udt.size()) {
      if (cap > 0)
        buf[0] = 0;
      return -1;
    }
    qstring ts;
    t->udt[i].type.print(&ts);
    qstrncpy(buf, ts.c_str(), cap);
    return (int64_t)ts.length();
  } catch (...) {
    std::abort();
  }
}

extern "C" size_t idakit_type_ordinal_count(void) { return get_ordinal_count(get_idati()); }

extern "C" int64_t idakit_type_ordinal_name(uint32_t ordinal, char *buf, size_t cap) {
  const char *nm = get_numbered_type_name(get_idati(), ordinal);
  if (nm == nullptr) {
    if (cap > 0)
      buf[0] = 0;
    return -1;
  }
  qstrncpy(buf, nm, cap);
  return (int64_t)qstrlen(nm);
}

// The decompiler is a plugin; init_hexrays_plugin() wires HEXDSP via callui
// broadcast once the plugin is loaded. Headless, load hexx64 explicitly if needed.
extern "C" int idakit_hexrays_init(void) {
  if (init_hexrays_plugin())
    return 1;
  load_plugin("hexx64");
  return init_hexrays_plugin() ? 1 : 0;
}

// On failure returns NULL and copies the reason into errbuf (the Hex-Rays
// `hexrays_failure_t`, which is the real channel for decompile errors -- IDA's
// thread-local `qerrno` is not set on this path).
extern "C" void *idakit_decompile(idakit_ea_t ea, char *errbuf, size_t cap) {
  // decompile_func runs the Hex-Rays microcode pipeline, which can hit a fatal exit() of
  // its own; guard it so that surfaces as a trap (idakit_was_trapped) rather than a crash.
  void *result = guarded<void *>(nullptr, false, [&]() -> void * {
    try {
      if (cap > 0)
        errbuf[0] = 0;
      func_t *pfn = get_func((ea_t)ea);
      if (pfn == nullptr) {
        qstrncpy(errbuf, "no function at address", cap);
        return nullptr;
      }
      hexrays_failure_t hf;
      cfuncptr_t cf = decompile_func(pfn, &hf, 0);
      if (cf == nullptr) {
        qstring desc = hf.desc();
        qstrncpy(errbuf, desc.c_str(), cap);
        return nullptr;
      }
      // Own a ref on the heap so the result survives past this call.
      return new cfuncptr_t(cf);
    } catch (...) {
      std::abort();
    }
  });
  if (result == nullptr && g_trapped)
    qstrncpy(errbuf, "the IDA kernel aborted during decompilation", cap);
  return result;
}

extern "C" void idakit_cfunc_dispose(void *h) { delete reinterpret_cast<cfuncptr_t *>(h); }

extern "C" int64_t idakit_cfunc_pseudocode(void *h, char *buf, size_t cap) {
  if (h == nullptr)
    return -1;
  try {
    cfunc_t *cf = *reinterpret_cast<cfuncptr_t *>(h);
    const strvec_t &sv = cf->get_pseudocode();
    qstring out;
    for (size_t i = 0; i < sv.size(); ++i) {
      qstring line;
      tag_remove(&line, sv[i].line);
      out.append(line);
      out.append('\n');
    }
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

// Read-only ctree traversal: count statements, expressions, and call sites.
// CV_FAST = don't maintain a parent stack (we don't need it here).
struct ctree_counter_t : public ctree_visitor_t {
  int n_insn = 0;
  int n_expr = 0;
  int n_calls = 0;
  ctree_counter_t() : ctree_visitor_t(CV_FAST) {}
  int idaapi visit_insn(cinsn_t *) override {
    ++n_insn;
    return 0;
  }
  int idaapi visit_expr(cexpr_t *e) override {
    ++n_expr;
    if (e->op == cot_call)
      ++n_calls;
    return 0;
  }
};

extern "C" void idakit_cfunc_ctree_counts(void *h, int *n_insn, int *n_expr, int *n_calls) {
  if (h == nullptr) {
    *n_insn = *n_expr = *n_calls = 0;
    return;
  }
  try {
    cfunc_t *cf = *reinterpret_cast<cfuncptr_t *>(h);
    ctree_counter_t v;
    v.apply_to(&cf->body, nullptr);
    *n_insn = v.n_insn;
    *n_expr = v.n_expr;
    *n_calls = v.n_calls;
  } catch (...) {
    std::abort();
  }
}

// Streaming ctree walk. The facade reads the SDK ctree depth-first and, per node, calls
// one Rust callback in `v` to mint the owned node; children are emitted before parents,
// so each call receives its children as the handles their own callbacks returned. The
// facade interns nothing: named types are referenced by name (recursion-safe) and filled
// once, guarded by `defined`. All identity, dedup, and meaning live on the Rust side.
namespace {

struct walker_t {
  const idakit_emit_vtbl_t *v;
  void *ctx;
  std::set<std::string> defined; // named types already filled (recursion + dedup guard)

  // Mint the handle for a type, recursing into its components. Named aggregates resolve
  // through a by-name placeholder so a recursive member can point back before the body
  // is filled; structural types (ptr/array/func/scalar) are emitted directly.
  // A typedef alias resolves all structural predicates through to its target, so it must
  // be intercepted before them; everything else dispatches on the resolved shape.
  uint32_t ty(const tinfo_t &t) {
    if (!t.empty() && t.is_typedef())
      return ty_typedef(t);
    return ty_resolved(t);
  }

  uint32_t ty_resolved(const tinfo_t &t) {
    size_t sz = t.get_size();
    uint32_t has_size = (sz != BADSIZE && sz != 0) ? 1 : 0;
    uint64_t size = has_size ? (uint64_t)sz : 0;
    // BADSIZE is (size_t)-1; without has_size, report 0 bytes rather than the sentinel.
    uint32_t bytes = has_size ? (uint32_t)sz : 0;

    if (t.empty())
      return v->t_scalar(ctx, 0, 0, 0, size, has_size);
    if (t.is_ptr())
      return v->t_ptr(ctx, ty(t.get_pointed_object()), size, has_size);
    if (t.is_array())
      return v->t_array(ctx, ty(t.get_array_element()), (uint64_t)t.get_array_nelems(), size,
                        has_size);
    if (t.is_func())
      return ty_func(t);
    if (t.is_udt())
      return ty_udt(t, size, has_size);
    if (t.is_enum())
      return ty_enum(t, size, has_size);
    if (t.is_bool())
      return v->t_scalar(ctx, 2, 0, 0, size, has_size);
    if (t.is_void())
      return v->t_scalar(ctx, 1, 0, 0, size, has_size);
    if (t.is_floating())
      return v->t_scalar(ctx, 4, bytes, 0, size, has_size);
    if (t.is_integral())
      return v->t_scalar(ctx, 3, bytes, t.is_signed() ? 1 : 0, size, has_size);
    return v->t_scalar(ctx, 0, 0, 0, size, has_size); // unknown
  }

  // Mint a placeholder: by name (deduped, recursion-safe) for a named aggregate, fresh
  // for an anonymous one. `*first` reports whether the body still needs filling.
  uint32_t placeholder(const tinfo_t &t, bool *first) {
    qstring nm;
    if (t.get_type_name(&nm) && !nm.empty()) {
      uint32_t id = v->t_named_ref(ctx, nm.c_str(), nm.length());
      *first = defined.insert(std::string(nm.c_str(), nm.length())).second;
      return id;
    }
    *first = true;
    return v->t_anon(ctx);
  }

  uint32_t ty_udt(const tinfo_t &t, uint64_t size, uint32_t has_size) {
    bool first;
    uint32_t id = placeholder(t, &first);
    if (first) {
      udt_type_data_t udt;
      std::vector<idakit_member_t> ms;
      if (t.get_udt_details(&udt)) {
        ms.reserve(udt.size());
        for (const udm_t &m : udt) {
          idakit_member_t md;
          md.name = m.name.c_str();
          md.name_len = m.name.length();
          md.bit_offset = m.offset;
          md.ty = ty(m.type);
          md.bitfield_width = m.is_bitfield() ? (uint32_t)m.size : 0;
          ms.push_back(md);
        }
      }
      v->t_fill_struct(ctx, id, t.is_union() ? 1 : 0, ms.data(), ms.size(), size, has_size);
    }
    return id;
  }

  uint32_t ty_enum(const tinfo_t &t, uint64_t size, uint32_t has_size) {
    bool first;
    uint32_t id = placeholder(t, &first);
    if (first) {
      enum_type_data_t ed;
      std::vector<idakit_enum_const_t> cs;
      bool sgn = false;
      if (t.get_enum_details(&ed)) {
        sgn = ed.is_number_signed();
        cs.reserve(ed.size());
        for (const edm_t &m : ed)
          cs.push_back({m.name.c_str(), m.name.length(), m.value});
      }
      uint32_t base_bytes = has_size ? (uint32_t)size : 4;
      uint32_t underlying = v->t_scalar(ctx, 3, base_bytes, sgn ? 1 : 0, size, has_size);
      v->t_fill_enum(ctx, id, underlying, cs.data(), cs.size(), size, has_size);
    }
    return id;
  }

  // A typedef link (`typedef T alias;`). Keep the alias name and peel exactly one level to
  // its target, so a chain (alias -> alias -> base) unwinds link by link. A named target
  // (another typedef, a struct/enum) is reached by name; an unnamed structural target has
  // no name to conflate with the alias, so it resolves straight off this same tinfo.
  uint32_t ty_typedef(const tinfo_t &t) {
    bool first;
    uint32_t id = placeholder(t, &first); // keyed by the alias name
    if (first) {
      qstring next;
      tinfo_t und;
      uint32_t under;
      if (t.get_next_type_name(&next) &&
          und.get_named_type(get_idati(), next.c_str(), BTF_TYPEDEF, false))
        under = ty(und);
      else
        under = ty_resolved(t);
      v->t_fill_typedef(ctx, id, under);
    }
    return id;
  }

  uint32_t ty_func(const tinfo_t &t) {
    func_type_data_t fd;
    std::vector<uint32_t> params;
    uint32_t ret;
    uint32_t vararg = 0;
    if (t.get_func_details(&fd)) {
      ret = ty(fd.rettype);
      params.reserve(fd.size());
      for (const funcarg_t &a : fd)
        params.push_back(ty(a.type));
      vararg = fd.is_vararg_cc() ? 1 : 0;
    } else {
      ret = v->t_scalar(ctx, 0, 0, 0, 0, 0);
    }
    return v->t_func(ctx, ret, params.data(), params.size(), vararg);
  }

  uint32_t expr(const cexpr_t *e) {
    ea_t ea = e->ea;
    uint32_t t = ty(e->type);
    switch (e->op) {
    case cot_num:
      return v->e_num(ctx, ea, e->n->value(e->type), t);
    case cot_fnum: {
      double d = 0.0;
      e->fpc->fnum.to_double(&d);
      return v->e_fnum(ctx, ea, d, t);
    }
    case cot_obj: {
      qstring nm;
      get_name(&nm, e->obj_ea);
      return v->e_obj(ctx, ea, (uint64_t)e->obj_ea, nm.c_str(), nm.length(), t);
    }
    case cot_var:
      return v->e_var(ctx, ea, (uint32_t)e->v.idx, t);
    case cot_str:
      return v->e_str(ctx, ea, e->string != nullptr ? e->string : "",
                      e->string != nullptr ? strlen(e->string) : 0, t);
    case cot_helper:
      return v->e_helper(ctx, ea, e->helper != nullptr ? e->helper : "",
                         e->helper != nullptr ? strlen(e->helper) : 0, t);
    case cot_ptr:
      return v->e_deref(ctx, ea, expr(e->x), (uint32_t)e->ptrsize, t);
    case cot_memref:
      return v->e_memref(ctx, ea, expr(e->x), e->m, t);
    case cot_memptr:
      return v->e_memptr(ctx, ea, expr(e->x), e->m, t);
    case cot_call: {
      uint32_t callee = expr(e->x);
      std::vector<uint32_t> args;
      if (e->a != nullptr) {
        args.reserve(e->a->size());
        for (const carg_t &arg : *e->a)
          args.push_back(expr(&arg));
      }
      return v->e_call(ctx, ea, callee, args.data(), args.size(), t);
    }
    default: {
      // Binary/assign/unary/ternary/cast/index/sizeof/empty/type/insn: operands by the
      // SDK's own predicates, ctype passed raw for the Rust side to classify.
      uint32_t x = op_uses_x(e->op) ? expr(e->x) : IDAKIT_NONE;
      uint32_t y = op_uses_y(e->op) ? expr(e->y) : IDAKIT_NONE;
      uint32_t z = op_uses_z(e->op) ? expr(e->z) : IDAKIT_NONE;
      return v->e_op(ctx, ea, (uint32_t)e->op, x, y, z, t);
    }
    }
  }

  uint32_t opt_expr(const cexpr_t *e) {
    return (e == nullptr || e->op == cot_empty) ? IDAKIT_NONE : expr(e);
  }

  uint32_t block(const cinsn_list_t &list, ea_t ea) {
    std::vector<uint32_t> kids;
    kids.reserve(list.size());
    for (const cinsn_t &child : list)
      kids.push_back(stmt(&child));
    return v->s_block(ctx, ea, kids.data(), kids.size());
  }

  uint32_t stmt(const cinsn_t *i) {
    ea_t ea = i->ea;
    switch (i->op) {
    case cit_block:
      return block(*i->cblock, ea);
    case cit_expr:
      return v->s_expr(ctx, ea, expr(i->cexpr));
    case cit_if: {
      uint32_t c = expr(&i->cif->expr);
      uint32_t th = stmt(i->cif->ithen);
      uint32_t el = i->cif->ielse != nullptr ? stmt(i->cif->ielse) : IDAKIT_NONE;
      return v->s_if(ctx, ea, c, th, el);
    }
    case cit_for: {
      uint32_t in = opt_expr(&i->cfor->init);
      uint32_t co = opt_expr(&i->cfor->expr);
      uint32_t st = opt_expr(&i->cfor->step);
      return v->s_for(ctx, ea, in, co, st, stmt(i->cfor->body));
    }
    case cit_while: {
      uint32_t c = expr(&i->cwhile->expr);
      return v->s_while(ctx, ea, c, stmt(i->cwhile->body));
    }
    case cit_do: {
      uint32_t b = stmt(i->cdo->body);
      return v->s_do(ctx, ea, b, expr(&i->cdo->expr));
    }
    case cit_switch: {
      uint32_t ex = expr(&i->cswitch->expr);
      // Reserve so element addresses stay stable while `cs` references into `vals`.
      std::vector<std::vector<uint64_t>> vals;
      std::vector<idakit_case_t> cs;
      vals.reserve(i->cswitch->cases.size());
      cs.reserve(i->cswitch->cases.size());
      for (const ccase_t &c : i->cswitch->cases) {
        std::vector<uint64_t> vv;
        vv.reserve(c.values.size());
        for (uint64 val : c.values)
          vv.push_back(val);
        uint32_t body = stmt(&c); // ccase_t is-a cinsn_t
        vals.push_back(std::move(vv));
        idakit_case_t cd;
        cd.values = vals.back().data();
        cd.nvalues = vals.back().size();
        cd.body = body;
        cs.push_back(cd);
      }
      return v->s_switch(ctx, ea, ex, cs.data(), cs.size());
    }
    case cit_return:
      return v->s_return(ctx, ea, opt_expr(&i->creturn->expr));
    case cit_goto:
      return v->s_goto(ctx, ea, (int32_t)i->cgoto->label_num);
    case cit_asm: {
      std::vector<uint64_t> addrs;
      addrs.reserve(i->casm->size());
      for (ea_t a : *i->casm)
        addrs.push_back((uint64_t)a);
      return v->s_asm(ctx, ea, addrs.data(), addrs.size());
    }
    case cit_throw:
      return v->s_throw(ctx, ea, opt_expr(&i->cthrow->expr));
    case cit_try: {
      // ctry is-a cblock (the guarded body); each catch is a cblock too.
      uint32_t body = block(*i->ctry, ea);
      std::vector<uint32_t> catches;
      catches.reserve(i->ctry->catchs.size());
      for (const ccatch_t &cat : i->ctry->catchs)
        catches.push_back(block(cat, ea));
      return v->s_try(ctx, ea, body, catches.data(), catches.size());
    }
    case cit_break:
      return v->s_break(ctx, ea);
    case cit_continue:
      return v->s_continue(ctx, ea);
    case cit_empty:
      return v->s_empty(ctx, ea);
    default:
      return v->s_empty(ctx, ea);
    }
  }

  // Emit the lvar table in index order, so `e_var.idx` resolves against it.
  void lvars(cfunc_t *cf) {
    lvars_t *lv = cf->get_lvars();
    if (lv == nullptr)
      return;
    for (const lvar_t &l : *lv) {
      uint32_t flags = (l.is_arg_var() ? 1u : 0u) | (l.is_result_var() ? 2u : 0u) |
                       (l.is_used_byref() ? 4u : 0u);
      uint32_t loc_kind = 0;
      int64_t loc_val = 0;
      if (l.is_stk_var()) {
        loc_kind = 2;
        loc_val = (int64_t)l.get_stkoff();
      } else if (l.is_reg_var()) {
        loc_kind = 1;
        loc_val = (int64_t)l.get_reg1();
      }
      v->l_lvar(ctx, l.name.c_str(), l.name.length(), ty(l.tif), flags, (uint32_t)l.width,
                l.cmt.c_str(), l.cmt.length(), loc_kind, loc_val);
    }
  }
};

} // namespace

extern "C" int idakit_cfunc_walk_ctree(void *h, const idakit_emit_vtbl_t *v, void *ctx,
                                       uint32_t *root) {
  if (h == nullptr || v == nullptr || root == nullptr)
    return 1;
  try {
    cfunc_t *cf = *reinterpret_cast<cfuncptr_t *>(h);

    walker_t w;
    w.v = v;
    w.ctx = ctx;
    w.lvars(cf);
    *root = w.stmt(&cf->body);
    return 0;
  } catch (...) {
    std::abort();
  }
}

// idakit RegClass discriminants -- must match the Rust `RegClass` enum.
#define RC_GPR 0
#define RC_SEGMENT 1
#define RC_XMM 2
#define RC_YMM 3
#define RC_ZMM 4
#define RC_MASK 5
#define RC_ST 6
#define RC_MMX 7
#define RC_CONTROL 8
#define RC_DEBUG 9
#define RC_TEST 10
#define RC_IP 11

// Classify an x86 RegNo by range. Used for plain o_reg operands and for a memory
// operand's base/index registers, whose numbers are always RegNo values.
static uint8_t reg_class_of(int r) {
  if (r < 0)
    return RC_GPR;
  if (is_segreg(r))
    return RC_SEGMENT;
  if (r == R_ip)
    return RC_IP;
  if (r >= R_st0 && r <= R_st7)
    return RC_ST;
  if (r >= R_mm0 && r <= R_mm7)
    return RC_MMX;
  if ((r >= R_xmm0 && r <= R_xmm15) || (r >= R_xmm16 && r <= R_xmm31))
    return RC_XMM;
  if ((r >= R_ymm0 && r <= R_ymm15) || (r >= R_ymm16 && r <= R_ymm31))
    return RC_YMM;
  if (r >= R_zmm0 && r <= R_zmm31)
    return RC_ZMM;
  if (r >= R_k0 && r <= R_k7)
    return RC_MASK;
  return RC_GPR;
}

// Class for a register carried by a processor-specific operand type, where op.reg is a
// class-relative index (control/debug/test) rather than a RegNo.
static uint8_t reg_class_for_optype(uint8_t t) {
  switch (t) {
  case o_trreg:
    return RC_TEST;
  case o_dbreg:
    return RC_DEBUG;
  case o_crreg:
    return RC_CONTROL;
  case o_fpreg:
    return RC_ST;
  case o_mmxreg:
    return RC_MMX;
  case o_xmmreg:
    return RC_XMM;
  case o_ymmreg:
    return RC_YMM;
  case o_zmmreg:
    return RC_ZMM;
  case o_kreg:
    return RC_MASK;
  default:
    return RC_GPR;
  }
}

static void fill_reg(idakit_reg_t *r, int num, uint8_t cls, int width) {
  r->num = (uint16_t)num;
  r->cls = cls;
  r->width = (uint8_t)width;
  r->name[0] = 0;
  qstring nm;
  if (num >= 0 && get_reg_name(&nm, num, width > 0 ? (size_t)width : 8) > 0)
    qstrncpy(r->name, nm.c_str(), sizeof(r->name));
}

static void clear_reg(idakit_reg_t *r) {
  r->num = IDAKIT_REG_NONE;
  r->cls = RC_GPR;
  r->width = 0;
  r->name[0] = 0;
}

// A memory operand's effective address width (for naming its base/index registers).
static int addr_width(const insn_t &insn) { return ad64(insn) ? 8 : (ad32(insn) ? 4 : 2); }

static void fill_mem(const insn_t &insn, const op_t &op, idakit_op_t *dst) {
  int aw = addr_width(insn);
  int base = x86_base_reg(insn, op);
  int index = x86_index_reg(insn, op);
  if (base != R_none)
    fill_reg(&dst->base, base, reg_class_of(base), aw);
  else
    clear_reg(&dst->base);
  if (index != R_none)
    fill_reg(&dst->index, index, reg_class_of(index), aw);
  else
    clear_reg(&dst->index);
  dst->scale = (uint8_t)(1 << x86_scale(op));
  // o_phrase is [reg(+reg)] with no displacement; o_mem/o_displ keep it in op.addr.
  dst->disp = op.type == o_phrase ? 0 : (int64_t)op.addr;
  // o_mem resolves to a static address (incl. RIP-relative IDA already folded).
  dst->addr = op.type == o_mem ? (uint64_t)op.addr : (uint64_t)BADADDR;
}

// Fold one raw op_t into a semantic idakit_op_t. Returns 0, or -3 for a type this decoder
// does not model (unreachable for x86, which enumerates all of its operand types).
static int classify_op(const insn_t &insn, const op_t &op, int idx, idakit_op_t *dst) {
  memset(dst, 0, sizeof(*dst));
  clear_reg(&dst->reg);
  clear_reg(&dst->base);
  clear_reg(&dst->index);
  dst->idx = (uint8_t)idx;
  dst->dtype = op.dtype;
  switch (op.type) {
  case o_reg:
    dst->kind = IDAKIT_OP_REG;
    fill_reg(&dst->reg, op.reg, reg_class_of(op.reg), get_dtype_size(op.dtype));
    return 0;
  case o_trreg:
  case o_dbreg:
  case o_crreg:
  case o_fpreg:
  case o_mmxreg:
  case o_xmmreg:
  case o_ymmreg:
  case o_zmmreg:
  case o_kreg:
    dst->kind = IDAKIT_OP_REG;
    fill_reg(&dst->reg, op.reg, reg_class_for_optype(op.type), get_dtype_size(op.dtype));
    return 0;
  case o_mem:
  case o_phrase:
  case o_displ:
    dst->kind = IDAKIT_OP_MEM;
    fill_mem(insn, op, dst);
    return 0;
  case o_imm:
    dst->kind = IDAKIT_OP_IMM;
    dst->value = (uint64_t)op.value;
    return 0;
  case o_near:
    dst->kind = IDAKIT_OP_NEAR;
    dst->addr = (uint64_t)op.addr;
    return 0;
  case o_far:
    dst->kind = IDAKIT_OP_FAR;
    dst->value = (uint64_t)op.addr;
    dst->sel = (uint16_t)op.segsel;
    return 0;
  default:
    return -3;
  }
}

extern "C" int idakit_decode_insn(idakit_ea_t ea, idakit_insn_t *out) {
  try {
    memset(out, 0, sizeof(*out));
    out->ea = ea;
    out->target = (uint64_t)BADADDR;

    // Only the x86 module's operand encoding is modelled; refuse other processors loudly
    // rather than fabricate operands from a foreign op_t layout.
    if (PH.id != PLFM_386)
      return -2;

    insn_t insn;
    if (decode_insn(&insn, (ea_t)ea) <= 0)
      return -1;

    out->len = (uint8_t)insn.size;
    out->isa = inf_is_64bit() ? 1 : 0;
    out->itype = insn.itype;
    const char *mnem = insn.get_canon_mnem(PH);
    if (mnem != nullptr)
      qstrncpy(out->mnemonic, mnem, sizeof(out->mnemonic));

    uint32 feature = insn.get_canon_feature(PH);
    ea_t tgt = BADADDR;
    int nops = 0;
    for (int i = 0; i < UA_MAXOP && nops < IDAKIT_MAX_OPS; i++) {
      const op_t &op = insn.ops[i];
      if (op.type == o_void)
        continue;
      idakit_op_t *dst = &out->ops[nops];
      int rc = classify_op(insn, op, i, dst);
      if (rc != 0) {
        out->err_optype = op.type;
        out->err_op = (uint8_t)i;
        return -3;
      }
      dst->access = (has_cf_use(feature, i) ? 1 : 0) | (has_cf_chg(feature, i) ? 2 : 0);
      if ((op.type == o_near || op.type == o_far) && tgt == BADADDR)
        tgt = op.addr;
      nops++;
    }
    out->nops = (uint8_t)nops;

    bool call = is_call_insn(insn);
    bool ret = is_ret_insn(insn);
    bool ijmp = is_indirect_jump_insn(insn);
    bool jcc = insn_jcc(insn);
    bool stops = (feature & CF_STOP) != 0;
    bool has_tgt = tgt != BADADDR;
    // A direct unconditional jump has a static code target, stops sequential flow, and is
    // neither a call nor a ret -- this catches `jmp` (incl. tail calls) without hardcoding
    // its itype.
    bool is_jump = jcc || ijmp || (has_tgt && stops && !call && !ret);
    bool indirect = (call || is_jump) && !has_tgt;

    uint8_t flow = 0;
    if (call)
      flow |= IDAKIT_FLOW_CALL;
    if (ret)
      flow |= IDAKIT_FLOW_RET;
    if (is_jump)
      flow |= IDAKIT_FLOW_JUMP;
    if (indirect)
      flow |= IDAKIT_FLOW_INDIRECT;
    if (stops)
      flow |= IDAKIT_FLOW_STOPS;
    out->flow = flow;
    out->target = has_tgt ? (uint64_t)tgt : (uint64_t)BADADDR;
    return 0;
  } catch (...) {
    std::abort();
  }
}
