//! idalib runtime lifecycle, kernel thread-affinity, error reporting, and the fatal-exit trap.

use std::ffi::{c_char, c_int};

// idalib lifecycle entry points (plain C ABI from libidalib.so)
unsafe extern "C" {
    pub fn init_library(argc: c_int, argv: *mut *mut c_char) -> c_int;
    /// Facade wrapper: force headless (`TVHEADLESS`) then [`init_library`]; returns its rc.
    pub fn idakit_init_library() -> c_int;
    /// Set IDA's `batch` global: nonzero suppresses dialogs/auto-answers prompts, zero restores
    /// interactive behavior.
    pub fn idakit_set_batch(on: c_int);
    pub fn get_library_version(major: *mut c_int, minor: *mut c_int, build: *mut c_int) -> bool;
    pub fn open_database(path: *const c_char, run_auto: bool, args: *const c_char) -> c_int;
    pub fn close_database(save: bool);
    pub fn enable_console_messages(enable: bool);
}

// kernel thread-affinity (plain C ABI from libida.so). `is_main_thread` reads
// libida's nullable `g_main`: non-null -> compares to caller; null -> claims caller.
unsafe extern "C" {
    pub fn is_main_thread() -> bool;
}

// auto-analysis (plain C ABI from libida.so). `open_database(run_auto=true)` only
// *enables* the analysis queue; `auto_wait` blocks until it drains, so a caller that
// wants a fully analyzed database calls it after opening (mirrors idalib).
unsafe extern "C" {
    pub fn auto_wait() -> bool;
}

// IDA's thread-safe error reporting (plain C ABI from libida.so). `error_t` is an
// `int`; `get_qerrno` reads the thread's last code and `qstrerror` describes one
// (folding in the C `errno` text for the `eOS` code).
unsafe extern "C" {
    pub fn get_qerrno() -> c_int;
    /// Describe an `error_t`. The returned pointer borrows IDA's static/thread-local
    /// storage: it must not be freed, and a later `qstrerror` call on the same thread may
    /// overwrite it. Copy it into a `CStr`/`String` before the next IDA call.
    pub fn qstrerror(code: c_int) -> *const c_char;
}

// Fatal trap. The guarded entry points (open, auto_wait, close, decompile) wrap their SDK
// call in a `setjmp` guard and redirect libida's GOT `exit`/`abort` slots to handlers that
// `longjmp` back, turning IDA's fatal paths (unaccepted license, LLVM/libc++ asserts) into a
// return value. A guarded call returns its normal rc, or `IDAKIT_EXIT_TRAPPED` (and sets
// `idakit_was_trapped`); `idakit_last_exit_code`/`idakit_last_output` then carry the detail.
pub const IDAKIT_EXIT_TRAPPED: c_int = -0x7FFF_FFFF;
unsafe extern "C" {
    pub fn idakit_guarded_open(path: *const c_char, run_auto: c_int) -> c_int;
    pub fn idakit_guarded_auto_wait() -> c_int;
    pub fn idakit_guarded_close(save: c_int) -> c_int;
    pub fn idakit_last_exit_code() -> c_int;
    pub fn idakit_was_trapped() -> c_int;
    pub fn idakit_last_output(buf: *mut c_char, cap: usize) -> usize;
    pub fn idakit_reg_read_int(name: *const c_char, defval: c_int) -> c_int;
    pub fn idakit_accept_eula() -> c_int;
}

/// [`idakit_test_fatal`] kind: run `exit()` inside the guarded call.
#[cfg(feature = "test-shims")]
pub const IDAKIT_FATAL_EXIT: c_int = 0;
/// [`idakit_test_fatal`] kind: run `abort()` inside the guarded call.
#[cfg(feature = "test-shims")]
pub const IDAKIT_FATAL_ABORT: c_int = 1;
/// [`idakit_test_fatal`] kind: run `interr()` inside the guarded call.
#[cfg(feature = "test-shims")]
pub const IDAKIT_FATAL_INTERR: c_int = 2;

// Fault-injection shim, compiled into the facade only under `test-shims`. Runs the chosen
// fatal inside `guarded<>` so the trap tests can prove it becomes `IDAKIT_EXIT_TRAPPED`.
#[cfg(feature = "test-shims")]
unsafe extern "C" {
    pub fn idakit_test_fatal(kind: c_int) -> c_int;
    /// Read back the `batch` global, to prove bring-up wired [`idakit_set_batch`].
    pub fn idakit_get_batch() -> c_int;
}
