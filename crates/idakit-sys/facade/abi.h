/* idakit facade: a clean C ABI over the C++ IDA SDK surface.
 * Opaque handles + free functions; strings copied out into caller buffers.
 * This header is what idakit-sys binds (hand-extern for now, bindgen later). */
#ifndef ABI_H
#define ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Force headless (TVHEADLESS) then init_library; returns its rc (0 = ok). Wrapping keeps
 * the setenv ordered before init and the side effect on the C++ side. */
int init_headless(void);

/* Set IDA's `batch` global: nonzero suppresses dialogs and auto-answers prompts (headless
 * default), zero restores interactive behavior (e.g. a GUI-plugin host). */
void set_batch(int on);

/* Fatal-exit trap. guarded_open returns the generated EXIT_TRAPPED sentinel (see
 * gen_facade_consts.h, instead of an open_database rc) when the kernel tried to terminate the
 * process mid-call; the intercepted exit code is then available from last_exit_code(). */
int guarded_open(const char *file_path, int run_auto);
int guarded_auto_wait(void); /* 1 ok / 0 fail / EXIT_TRAPPED */
int guarded_close(int save); /* 0 ok / EXIT_TRAPPED */
int last_exit_code(void);
int was_trapped(void);                     /* 1 if the last guarded call trapped a fatal exit */
size_t last_output(char *buf, size_t cap); /* captured stdout+stderr; len, snprintf-style */

int idakit_reg_read_int(const char *name, int defval); /* read an int/bool registry value */
int accept_eula(void); /* record EULA acceptance; returns its value */

/* Fault-injection hooks for the trap and cxx tests. Inert in normal use: test_fatal arms
 * its own guarded<> so it always traps and returns rather than terminating, and
 * trigger_fatal fires a fatal only when invoked with no guard on the stack. The Rust
 * bindings are #[doc(hidden)], keeping them off the published API. `kind` is one of the
 * generated FATAL_* constants (see gen_facade_consts.h). */
int test_fatal(int kind);
int get_batch(void); /* read back the `batch` global, to prove bring-up wired it */
/* Fire a fatal (FATAL_*) from any TU; the exit/abort stand-ins are file-local to
 * runtime.cpp, so the cxx probe body calls this to reach them. */
void trigger_fatal(int kind);
/* Arm guarded<>, then reproduce the shared production rust::behavior::trycatch landing pad
 * (trycatch.h) from inside it, so the fatal's longjmp must cross that frame. Returns
 * EXIT_TRAPPED when the longjmp fired (exit/abort), or 1 when trycatch caught the throw first
 * (interr). */
int test_fatal_through_cxx(int kind);

/* The zero-copy read into a caller buffer, <0 on fail. `addr` is IDA's ea_t (64-bit under
 * __EA64__). The owning twin (Vec), pattern search, and patching are cxx bridges in the generated
 * bytes domain. */
int64_t idakit_get_bytes(uint64_t addr, void *buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* ABI_H */
