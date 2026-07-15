//! idalib runtime lifecycle, kernel thread-affinity, error reporting, and the fatal-exit trap.

use std::ffi::{c_char, c_int};

// idalib lifecycle entry points (plain C ABI from libidalib.so)
unsafe extern "C" {
    /// Initialize idalib. `argc`/`argv` are forwarded from the process; returns 0 on success.
    pub fn init_library(argc: c_int, argv: *mut *mut c_char) -> c_int;
    /// Force headless (`TVHEADLESS`), then initialize idalib; returns its rc.
    pub fn init_headless() -> c_int;
    /// Set IDA's `batch` global: nonzero suppresses dialogs/auto-answers prompts, zero restores
    /// interactive behavior.
    pub fn set_batch(on: c_int);
    /// Read the running IDA's version into `major`/`minor`/`build`; returns whether it succeeded.
    pub fn get_library_version(major: *mut c_int, minor: *mut c_int, build: *mut c_int) -> bool;
    /// Open the database at `path`, optionally queuing auto-analysis (`run_auto`) with `args`
    /// forwarded to it; returns its rc.
    pub fn open_database(path: *const c_char, run_auto: bool, args: *const c_char) -> c_int;
    /// Close the current database, saving it first when `save` is set.
    pub fn close_database(save: bool);
    /// Enable or disable idalib's console message output.
    pub fn enable_console_messages(enable: bool);
}

// kernel thread-affinity (plain C ABI from libida.so). `is_main_thread` reads
// libida's nullable `g_main`: non-null -> compares to caller; null -> claims caller.
unsafe extern "C" {
    /// Whether the calling thread is IDA's main (kernel) thread.
    pub fn is_main_thread() -> bool;
}

// auto-analysis (plain C ABI from libida.so). `open_database(run_auto=true)` only
// *enables* the analysis queue; `auto_wait` blocks until it drains, so a caller that
// wants a fully analyzed database calls it after opening (mirrors idalib).
unsafe extern "C" {
    /// Block until the auto-analysis queue drains; returns whether it completed.
    pub fn auto_wait() -> bool;
}

// IDA's thread-safe error reporting (plain C ABI from libida.so). `error_t` is an
// `int`; `get_qerrno` reads the thread's last code and `qstrerror` describes one
// (folding in the C `errno` text for the `eOS` code).
unsafe extern "C" {
    /// The calling thread's last `error_t` code.
    pub fn get_qerrno() -> c_int;
    /// Describe an `error_t`. The returned pointer borrows IDA's static/thread-local
    /// storage: it must not be freed, and a later `qstrerror` call on the same thread may
    /// overwrite it. Copy it into a `CStr`/`String` before the next IDA call.
    pub fn qstrerror(code: c_int) -> *const c_char;
}

// Fatal trap. The guarded entry points (open, auto_wait, close, decompile) wrap their SDK
// call in a `setjmp` guard and redirect libida's GOT `exit`/`abort` slots to handlers that
// `longjmp` back, turning IDA's fatal paths (unaccepted license, LLVM/libc++ asserts) into a
// return value. A guarded call returns its normal rc, or `crate::EXIT_TRAPPED` (and sets
// `was_trapped`); `last_exit_code`/`last_output` then carry the detail.
unsafe extern "C" {
    /// Guarded [`open_database`]: same signature and rc, trapped against a fatal exit/abort.
    pub fn guarded_open(path: *const c_char, run_auto: c_int) -> c_int;
    /// Guarded [`auto_wait`], trapped against a fatal exit/abort; returns its rc.
    pub fn guarded_auto_wait() -> c_int;
    /// Guarded [`close_database`], trapped against a fatal exit/abort; returns its rc.
    pub fn guarded_close(save: c_int) -> c_int;
    /// The process exit code the most recent guarded call trapped, if any.
    pub fn last_exit_code() -> c_int;
    /// Whether the most recent guarded call trapped a fatal exit/abort.
    pub fn was_trapped() -> c_int;
    /// Copy the most recent guarded call's captured output into `buf`/`cap`, snprintf-style.
    pub fn last_output(buf: *mut c_char, cap: usize) -> usize;
    /// Read IDA registry integer `name`, or `defval` when unset.
    #[link_name = "idakit_reg_read_int"]
    pub fn reg_read_int(name: *const c_char, defval: c_int) -> c_int;
    /// Accept the EULA programmatically, so headless bring-up never blocks on it.
    pub fn accept_eula() -> c_int;
}

// Fault-injection hooks, always compiled but `#[doc(hidden)]` so they stay off the public API.
// `kind` is one of `crate::FATAL_EXIT`/`FATAL_ABORT`/`FATAL_INTERR`. Run the chosen fatal inside
// `guarded<>` so the trap tests can prove it becomes `crate::EXIT_TRAPPED`; `test_fatal` arms its
// own guard, so it can't terminate the process.
unsafe extern "C" {
    #[doc(hidden)]
    pub fn test_fatal(kind: c_int) -> c_int;
    /// Read back the `batch` global, to prove bring-up wired [`set_batch`].
    #[doc(hidden)]
    pub fn get_batch() -> c_int;
    /// Arm `guarded<>`, then reach the chosen fatal *through* a cxx `Result`-shim, so the trap's
    /// `longjmp` (exit/abort) must unwind across the shim's `try/catch` frame. Returns
    /// [`crate::EXIT_TRAPPED`] when the longjmp fired, or `1` when cxx caught the throw first
    /// (interr, which is a `std::exception`) and reported a Rust `Err` instead of trapping.
    #[doc(hidden)]
    pub fn test_fatal_through_cxx(kind: c_int) -> c_int;
}
