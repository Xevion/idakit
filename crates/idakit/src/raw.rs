//! The crate's kernel-global FFI boundary, as private [`Idb`] methods.
//!
//! Every `idakit-sys` call that operates on the implicit current database lives
//! here as one thin wrapper. The handle-scoped calls (`Cfunc`, `TypeInfo`) stay on
//! those types, since they own the handle they act on.
//!
//! # Safety
//!
//! Every method below is sound by one invariant, discharged here once: an [`Idb`]
//! is `!Send` and constructed only inside the kernel-thread pump of
//! [`Ida::run`](crate::Ida::run), so holding `&self` proves we are on the kernel
//! thread with the library initialized and a database open: exactly the
//! thread-affinity and live-database preconditions the kernel demands. `&mut self`
//! adds exclusivity for writes. Raw buffer pointers are valid for the call;
//! string getters fill `(buf, cap)` and return the value's full length.

use std::ffi::{c_char, c_int, c_void};

use idakit_sys as sys;

use crate::Idb;
use crate::ea::Ea;
use crate::error::Qerrno;
use crate::ffi::cstr;

impl Idb {
    // The three error helpers below read *thread-local* kernel state; `&self` is the
    // kernel-thread token (see module note), not a source of instance state.

    /// IDA's thread-local last error code.
    pub(crate) fn qerrno(&self) -> Qerrno {
        Qerrno::from_code(unsafe { sys::get_qerrno() })
    }

    /// Human-readable reason for `code` (`qstrerror` already folds in the C `errno`
    /// text for `eOS`). Never empty: falls back to the raw `error_t`.
    pub(crate) fn error_reason(&self, code: Qerrno) -> String {
        // SAFETY: qstrerror returns a borrowed thread-local string; copied now.
        let reason = unsafe { cstr(sys::qstrerror(code.code())) };
        if reason.is_empty() {
            format!("error_t {}", code.code())
        } else {
            reason
        }
    }

    /// The current `qerrno` plus its reason, but `None` reason when it is `eOk`: a
    /// failing path that set no code would otherwise borrow a stale, misleading one.
    pub(crate) fn last_reason(&self) -> (Qerrno, Option<String>) {
        let qerrno = self.qerrno();
        let reason = match qerrno {
            Qerrno::Ok => None,
            code => Some(self.error_reason(code)),
        };
        (qerrno, reason)
    }

    /// Open via the facade's guarded wrapper: IDA's fatal `exit()` path (an unaccepted
    /// license, a corrupt input it refuses) is trapped and surfaced as the
    /// [`sys::IDAKIT_EXIT_TRAPPED`] sentinel instead of killing the process.
    pub(crate) fn open_database(&mut self, path: *const c_char, run_auto: bool) -> c_int {
        unsafe { sys::idakit_guarded_open(path, run_auto as c_int) }
    }

    /// The exit code IDA passed to `exit()` on the last trapped fatal open.
    pub(crate) fn last_exit_code(&self) -> c_int {
        unsafe { sys::idakit_last_exit_code() }
    }

    /// The stdout+stderr IDA emitted during the last guarded open, captured by the
    /// facade instead of leaking to the caller's console.
    pub(crate) fn last_output(&self) -> String {
        crate::ffi::read_string(|buf, cap| unsafe { sys::idakit_last_output(buf, cap) as i64 })
            .unwrap_or_default()
    }

    /// Record EULA acceptance in IDA's registry; returns whether it now reads accepted.
    pub(crate) fn reg_accept_eula(&self) -> bool {
        unsafe { sys::idakit_accept_eula() != 0 }
    }

    /// Block until the auto-analysis queue drains. Only meaningful after an
    /// `open_database(run_auto = true)`, which enables but does not await analysis.
    /// Guarded: returns [`sys::IDAKIT_EXIT_TRAPPED`] if analysis hit a fatal exit().
    pub(crate) fn auto_wait(&self) -> c_int {
        unsafe { sys::idakit_guarded_auto_wait() }
    }

    /// Guarded close; a fatal during a save is trapped (returns the sentinel) rather than
    /// killing the process. Best-effort -- by the time we close, the result is moot.
    pub(crate) fn close_database(&mut self, save: bool) {
        unsafe { sys::idakit_guarded_close(save as c_int) };
    }

    /// Whether the most recent guarded facade call trapped a fatal exit().
    pub(crate) fn was_trapped(&self) -> bool {
        unsafe { sys::idakit_was_trapped() != 0 }
    }

    pub(crate) fn get_bytes(&self, ea: Ea, buf: *mut c_void, size: usize) -> i64 {
        unsafe { sys::idakit_get_bytes(ea.get(), buf, size) }
    }

    pub(crate) fn decode_insn(&self, ea: Ea, out: *mut sys::InsnRaw) -> c_int {
        unsafe { sys::idakit_decode_insn(ea.get(), out) }
    }

    /// Open an xref cursor over the current database; `is_to` selects xrefs targeting
    /// `ea` vs originating at it. The returned handle is owned by the [`Xrefs`] iterator,
    /// which closes it on drop.
    ///
    /// [`Xrefs`]: crate::Xrefs
    pub(crate) fn xref_open(&self, ea: Ea, is_to: bool) -> *mut c_void {
        unsafe { sys::idakit_xref_open(ea.get(), is_to as u8) }
    }

    pub(crate) fn type_open(&self, name: *const c_char) -> *mut c_void {
        unsafe { sys::idakit_type_open(name) }
    }

    pub(crate) fn hexrays_init(&self) -> c_int {
        unsafe { sys::idakit_hexrays_init() }
    }

    /// Decompile the function at `ea`. On failure the handle is null and the second
    /// element carries the Hex-Rays failure reason copied out of the facade buffer.
    pub(crate) fn decompile_at(&self, ea: Ea) -> (*mut c_void, String) {
        let mut err = [0u8; 256];
        // SAFETY: `err` is a writable buffer of `len`; the facade NUL-terminates
        // within it and reports the reason there when it returns null.
        let handle = unsafe { sys::idakit_decompile(ea.get(), err.as_mut_ptr().cast(), err.len()) };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        let reason = unsafe { cstr(err.as_ptr().cast()) };
        (handle, reason)
    }

    pub(crate) fn set_name(&mut self, ea: Ea, name: *const c_char) -> bool {
        unsafe { sys::set_name(ea.get(), name, 0) }
    }

    pub(crate) fn set_cmt(&mut self, ea: Ea, comment: *const c_char, repeatable: bool) -> bool {
        unsafe { sys::set_cmt(ea.get(), comment, repeatable) }
    }

    pub(crate) fn func_qty(&self) -> usize {
        unsafe { sys::idakit_func_qty() }
    }

    pub(crate) fn func_ea(&self, n: usize) -> sys::Ea {
        unsafe { sys::idakit_func_ea(n) }
    }

    pub(crate) fn func_name(&self, ea: Ea, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_func_name(ea.get(), buf, cap) }
    }

    pub(crate) fn func_type(&self, ea: Ea, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_func_type(ea.get(), buf, cap) }
    }

    pub(crate) fn seg_qty(&self) -> c_int {
        unsafe { sys::idakit_seg_qty() }
    }

    pub(crate) fn seg_name(&self, n: c_int, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_seg_name(n, buf, cap) }
    }

    pub(crate) fn seg_start(&self, n: c_int) -> sys::Ea {
        unsafe { sys::idakit_seg_start(n) }
    }

    pub(crate) fn seg_end(&self, n: c_int) -> sys::Ea {
        unsafe { sys::idakit_seg_end(n) }
    }
}
