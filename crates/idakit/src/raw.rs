//! The crate's kernel-global FFI boundary, as private [`Database`] methods.
//!
//! Every `idakit-sys` call that operates on the implicit current database lives
//! here as one thin wrapper. The handle-scoped calls (`DecompiledFunction`) stay on
//! that type, since it owns the handle it acts on.
//!
//! # Safety
//!
//! Every method below is sound by one invariant, discharged here once. A [`Database`]
//! is `!Send` and constructed only inside the kernel-thread pump of
//! [`Ida::run`](crate::Ida::run), so holding `&self` proves we are on the kernel
//! thread with the library initialized and a database open, exactly the
//! thread-affinity and live-database preconditions the kernel demands. `&mut self`
//! adds exclusivity for writes. Raw buffer pointers are valid for the call, and
//! string getters fill `(buf, cap)` and return the value's full length.

use std::ffi::{c_char, c_int, c_void};

use idakit_sys as sys;

use crate::Database;
use crate::address::Address;
use crate::error::Qerrno;
use crate::ffi::cstr;

impl Database {
    // The three error helpers below read *thread-local* kernel state; `&self` is the
    // kernel-thread token (see module note), not a source of instance state.

    /// IDA's thread-local last error code.
    pub(crate) fn qerrno(&self) -> Qerrno {
        Qerrno::from_code(unsafe { sys::get_qerrno() })
    }

    /// Human-readable reason for `code`; the C `errno` text is already folded in for an
    /// OS error. Never empty, since it falls back to the raw error code.
    pub(crate) fn error_reason(&self, code: Qerrno) -> String {
        // SAFETY: qstrerror returns a borrowed thread-local string; copied now.
        let reason = unsafe { cstr(sys::qstrerror(code.code())) };
        if reason.is_empty() {
            format!("error_t {}", code.code())
        } else {
            reason
        }
    }

    /// The current [`Qerrno`] plus its reason, but `None` reason when it is [`Qerrno::Ok`].
    ///
    /// A failing path that set no code would otherwise borrow a stale, misleading reason.
    pub(crate) fn last_reason(&self) -> (Qerrno, Option<String>) {
        let qerrno = self.qerrno();
        let reason = match qerrno {
            Qerrno::Ok => None,
            code => Some(self.error_reason(code)),
        };
        (qerrno, reason)
    }

    /// Opens via the facade's guarded wrapper.
    ///
    /// IDA's fatal `exit()` path (an unaccepted license, a corrupt input it refuses) is
    /// trapped and surfaced as the [`sys::IDAKIT_EXIT_TRAPPED`] sentinel instead of killing
    /// the process.
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

    /// Records EULA acceptance in IDA's registry, and returns whether it now reads accepted.
    pub(crate) fn reg_accept_eula(&self) -> bool {
        unsafe { sys::idakit_accept_eula() != 0 }
    }

    /// Blocks until the auto-analysis queue drains. Only meaningful after an
    /// `open_database(run_auto = true)`, which enables but does not await analysis.
    /// Guarded: returns [`sys::IDAKIT_EXIT_TRAPPED`] if analysis hit a fatal exit().
    pub(crate) fn auto_wait(&self) -> c_int {
        unsafe { sys::idakit_guarded_auto_wait() }
    }

    /// Guarded close, where a fatal during a save is trapped (returns the sentinel) rather
    /// than killing the process. Best-effort, since by the time we close, the result is
    /// moot.
    pub(crate) fn close_database(&mut self, save: bool) {
        unsafe { sys::idakit_guarded_close(save as c_int) };
    }

    /// Whether the most recent guarded facade call trapped a fatal exit().
    pub(crate) fn was_trapped(&self) -> bool {
        unsafe { sys::idakit_was_trapped() != 0 }
    }

    pub(crate) fn get_bytes(&self, address: Address, buf: *mut c_void, size: usize) -> i64 {
        unsafe { sys::idakit_get_bytes(address.get(), buf, size) }
    }

    pub(crate) fn get_u8(&self, address: Address, out: *mut u8) -> c_int {
        unsafe { sys::idakit_get_u8(address.get(), out) }
    }

    pub(crate) fn get_u16(&self, address: Address, out: *mut u16) -> c_int {
        unsafe { sys::idakit_get_u16(address.get(), out) }
    }

    pub(crate) fn get_u32(&self, address: Address, out: *mut u32) -> c_int {
        unsafe { sys::idakit_get_u32(address.get(), out) }
    }

    pub(crate) fn get_u64(&self, address: Address, out: *mut u64) -> c_int {
        unsafe { sys::idakit_get_u64(address.get(), out) }
    }

    pub(crate) fn get_strlit(
        &self,
        address: Address,
        strtype: c_int,
        buf: *mut c_char,
        cap: usize,
    ) -> i64 {
        unsafe { sys::idakit_get_strlit(address.get(), strtype, buf, cap) }
    }

    pub(crate) fn decode_insn(&self, address: Address, out: *mut sys::InstructionRaw) -> c_int {
        unsafe { sys::idakit_decode_insn(address.get(), out) }
    }

    pub(crate) fn get_flags(&self, address: Address) -> u64 {
        unsafe { sys::idakit_get_flags(address.get()) }
    }

    pub(crate) fn get_item_head(&self, address: Address) -> sys::Address {
        unsafe { sys::idakit_get_item_head(address.get()) }
    }

    pub(crate) fn get_item_end(&self, address: Address) -> sys::Address {
        unsafe { sys::idakit_get_item_end(address.get()) }
    }

    pub(crate) fn get_next_head(&self, address: Address, maxea: Address) -> sys::Address {
        unsafe { sys::idakit_get_next_head(address.get(), maxea.get()) }
    }

    pub(crate) fn get_prev_head(&self, address: Address, minea: Address) -> sys::Address {
        unsafe { sys::idakit_get_prev_head(address.get(), minea.get()) }
    }

    pub(crate) fn bitness_bits(&self) -> c_int {
        unsafe { sys::idakit_bitness() }
    }

    pub(crate) fn image_base(&self) -> sys::Address {
        unsafe { sys::idakit_image_base() }
    }

    pub(crate) fn min_ea(&self) -> sys::Address {
        unsafe { sys::idakit_min_ea() }
    }

    pub(crate) fn max_ea(&self) -> sys::Address {
        unsafe { sys::idakit_max_ea() }
    }

    pub(crate) fn proc_name(&self, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_proc_name(buf, cap) }
    }

    pub(crate) fn file_type_name(&self, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_file_type_name(buf, cap) }
    }

    pub(crate) fn input_path(&self, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_input_path(buf, cap) }
    }

    pub(crate) fn root_filename(&self, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_root_filename(buf, cap) }
    }

    pub(crate) fn get_ea_name(&self, address: Address, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_get_ea_name(address.get(), buf, cap) }
    }

    pub(crate) fn get_name_ea(&self, name: *const c_char) -> sys::Address {
        unsafe { sys::idakit_get_name_ea(name) }
    }

    pub(crate) fn demangle_name(&self, name: *const c_char, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_demangle_name(name, buf, cap) }
    }

    pub(crate) fn nlist_size(&self) -> usize {
        unsafe { sys::idakit_nlist_size() }
    }

    pub(crate) fn nlist_ea(&self, idx: usize) -> sys::Address {
        unsafe { sys::idakit_nlist_ea(idx) }
    }

    pub(crate) fn nlist_name(&self, idx: usize, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_nlist_name(idx, buf, cap) }
    }

    /// Opens a reference cursor over the current database.
    ///
    /// `is_to` selects xrefs targeting `address` vs originating at it. The returned handle
    /// is owned by the [`Xrefs`] iterator, which closes it on drop.
    ///
    /// [`Xrefs`]: crate::Xrefs
    pub(crate) fn xref_open(&self, address: Address, is_to: bool) -> *mut c_void {
        unsafe { sys::idakit_xref_open(address.get(), is_to as u8) }
    }

    pub(crate) fn hexrays_init(&self) -> c_int {
        unsafe { sys::idakit_hexrays_init() }
    }

    /// Decompiles the function at `address`.
    ///
    /// On failure the handle is null and the second element carries the Hex-Rays failure
    /// reason copied out of the facade buffer.
    pub(crate) fn decompile_at(&self, address: Address) -> (*mut c_void, String) {
        let mut err = [0u8; 256];
        // SAFETY: `err` is a writable buffer of `len`; the facade NUL-terminates
        // within it and reports the reason there when it returns null.
        let handle =
            unsafe { sys::idakit_decompile(address.get(), err.as_mut_ptr().cast(), err.len()) };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        let reason = unsafe { cstr(err.as_ptr().cast()) };
        (handle, reason)
    }

    pub(crate) fn set_name(&mut self, address: Address, name: *const c_char) -> bool {
        unsafe { sys::set_name(address.get(), name, 0) }
    }

    pub(crate) fn set_cmt(
        &mut self,
        address: Address,
        comment: *const c_char,
        repeatable: bool,
    ) -> bool {
        unsafe { sys::set_cmt(address.get(), comment, repeatable) }
    }

    pub(crate) fn get_cmt(
        &self,
        address: Address,
        repeatable: bool,
        buf: *mut c_char,
        cap: usize,
    ) -> i64 {
        unsafe { sys::idakit_get_cmt(address.get(), repeatable as u8, buf, cap) }
    }

    pub(crate) fn patch_bytes(
        &mut self,
        address: Address,
        buf: *const c_void,
        size: usize,
    ) -> c_int {
        unsafe { sys::idakit_patch_bytes(address.get(), buf, size) }
    }

    pub(crate) fn func_qty(&self) -> usize {
        unsafe { sys::idakit_func_qty() }
    }

    pub(crate) fn func_ea(&self, n: usize) -> sys::Address {
        unsafe { sys::idakit_func_ea(n) }
    }

    pub(crate) fn func_name(&self, address: Address, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_func_name(address.get(), buf, cap) }
    }

    pub(crate) fn func_chunk_qty(&self, address: Address) -> c_int {
        unsafe { sys::idakit_func_chunk_qty(address.get()) }
    }

    pub(crate) fn func_chunk(
        &self,
        address: Address,
        idx: c_int,
        start: *mut sys::Address,
        end: *mut sys::Address,
    ) -> c_int {
        unsafe { sys::idakit_func_chunk(address.get(), idx, start, end) }
    }

    pub(crate) fn func_type(&self, address: Address, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_func_type(address.get(), buf, cap) }
    }

    pub(crate) fn type_ordinal_limit(&self) -> u32 {
        unsafe { sys::idakit_type_ordinal_limit() }
    }

    pub(crate) fn type_name_at(&self, ordinal: u32, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_type_name_at(ordinal, buf, cap) }
    }

    pub(crate) fn func_start(&self, address: Address) -> sys::Address {
        unsafe { sys::idakit_func_start(address.get()) }
    }

    pub(crate) fn func_end(&self, address: Address) -> sys::Address {
        unsafe { sys::idakit_func_end(address.get()) }
    }

    /// Parses `decl` and applies the resulting type at `address`; the reason is copied out of the
    /// facade buffer on a parse or apply failure.
    pub(crate) fn apply_type_decl(
        &mut self,
        address: Address,
        decl: *const c_char,
        flags: c_int,
    ) -> (c_int, String) {
        let mut err = [0u8; 1024];
        // SAFETY: `err` is a writable buffer of `len`; the facade NUL-terminates within it.
        let code = unsafe {
            sys::idakit_apply_type_decl(
                address.get(),
                decl,
                flags,
                err.as_mut_ptr().cast(),
                err.len(),
            )
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        let reason = unsafe { cstr(err.as_ptr().cast()) };
        (code, reason)
    }

    /// Resolves the named type `name` and applies it at `address`.
    pub(crate) fn apply_named_type(&mut self, address: Address, name: *const c_char) -> c_int {
        unsafe { sys::idakit_apply_named_type(address.get(), name) }
    }

    /// Clears any type applied at `address` (idempotent).
    pub(crate) fn clear_type(&mut self, address: Address) -> c_int {
        unsafe { sys::idakit_clear_type(address.get()) }
    }

    /// Builds the type the serialized recipe `buf` encodes and applies it at `address`; the reason
    /// is copied out of the facade buffer on a build or apply failure.
    pub(crate) fn apply_type_recipe(
        &mut self,
        address: Address,
        buf: &[u8],
        flags: c_int,
    ) -> (c_int, String) {
        let mut err = [0u8; 1024];
        // SAFETY: `buf` is a readable slice of `buf.len()`; `err` is a writable buffer the facade
        // NUL-terminates within.
        let code = unsafe {
            sys::idakit_apply_type_recipe(
                address.get(),
                buf.as_ptr(),
                buf.len(),
                flags,
                err.as_mut_ptr().cast(),
                err.len(),
            )
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        let reason = unsafe { cstr(err.as_ptr().cast()) };
        (code, reason)
    }

    /// Parses `input` into the local type library; returns the error count and any diagnostics
    /// copied out of the facade buffer.
    pub(crate) fn define_type(&mut self, input: *const c_char) -> (c_int, String) {
        let mut err = [0u8; 4096];
        // SAFETY: `err` is a writable buffer of `len`; the facade NUL-terminates within it.
        let code = unsafe { sys::idakit_define_type(input, err.as_mut_ptr().cast(), err.len()) };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        let reason = unsafe { cstr(err.as_ptr().cast()) };
        (code, reason)
    }

    pub(crate) fn func_flags(&self, address: Address) -> u64 {
        unsafe { sys::idakit_func_flags(address.get()) }
    }

    pub(crate) fn seg_qty(&self) -> c_int {
        unsafe { sys::idakit_seg_qty() }
    }

    pub(crate) fn seg_name(&self, n: c_int, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_seg_name(n, buf, cap) }
    }

    pub(crate) fn seg_start(&self, n: c_int) -> sys::Address {
        unsafe { sys::idakit_seg_start(n) }
    }

    pub(crate) fn seg_end(&self, n: c_int) -> sys::Address {
        unsafe { sys::idakit_seg_end(n) }
    }

    pub(crate) fn seg_perm(&self, n: c_int) -> c_int {
        unsafe { sys::idakit_seg_perm(n) }
    }

    pub(crate) fn seg_bitness(&self, n: c_int) -> c_int {
        unsafe { sys::idakit_seg_bitness(n) }
    }

    pub(crate) fn seg_class(&self, n: c_int, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_seg_class(n, buf, cap) }
    }

    pub(crate) fn export_qty(&self) -> usize {
        unsafe { sys::idakit_export_qty() }
    }

    pub(crate) fn export_ea(&self, idx: usize) -> sys::Address {
        unsafe { sys::idakit_export_ea(idx) }
    }

    pub(crate) fn export_ordinal(&self, idx: usize) -> u64 {
        unsafe { sys::idakit_export_ordinal(idx) }
    }

    pub(crate) fn export_name(&self, idx: usize, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_export_name(idx, buf, cap) }
    }

    pub(crate) fn export_forwarder(&self, idx: usize, buf: *mut c_char, cap: usize) -> i64 {
        unsafe { sys::idakit_export_forwarder(idx, buf, cap) }
    }

    /// Materializes the import table into an owned snapshot handle.
    ///
    /// The [`Imports`] iterator owns it and frees it on drop.
    ///
    /// [`Imports`]: crate::Imports
    pub(crate) fn imports_build(&self) -> *mut c_void {
        unsafe { sys::idakit_imports_build() }
    }

    /// (Re)builds IDA's global string list, a query-time scan, not a database mutation.
    pub(crate) fn strlist_build(&self) {
        unsafe { sys::idakit_strlist_build() };
    }

    pub(crate) fn strlist_qty(&self) -> usize {
        unsafe { sys::idakit_strlist_qty() }
    }

    pub(crate) fn strlist_item(
        &self,
        n: usize,
        ea: *mut sys::Address,
        length: *mut c_int,
        ty: *mut c_int,
    ) -> c_int {
        unsafe { sys::idakit_strlist_item(n, ea, length, ty) }
    }

    pub(crate) fn strlit_contents(
        &self,
        address: Address,
        len: usize,
        ty: c_int,
        buf: *mut c_char,
        cap: usize,
    ) -> i64 {
        unsafe { sys::idakit_strlit_contents(address.get(), len, ty, buf, cap) }
    }
}
