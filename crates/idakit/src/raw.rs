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

    /// Zero-alloc read into `buf`; the generated `get_bytes` returns an owned `Vec`, so it can't
    /// back this buffer-fill twin, which stays on the raw facade. [`get_bytes_owned`] is the
    /// owning generated path.
    ///
    /// [`get_bytes_owned`]: Self::get_bytes_owned
    pub(crate) fn get_bytes(&self, address: Address, buf: *mut c_void, size: usize) -> i64 {
        unsafe { sys::idakit_get_bytes(address.get(), buf, size) }
    }

    pub(crate) fn get_bytes_owned(&self, address: Address, size: usize) -> Option<Vec<u8>> {
        sys::get_bytes(address.get(), size).ok()
    }

    pub(crate) fn get_u8(&self, address: Address) -> Option<u8> {
        sys::get_u8(address.get()).ok()
    }

    pub(crate) fn get_u16(&self, address: Address) -> Option<u16> {
        sys::get_u16(address.get()).ok()
    }

    pub(crate) fn get_u32(&self, address: Address) -> Option<u32> {
        sys::get_u32(address.get()).ok()
    }

    pub(crate) fn get_u64(&self, address: Address) -> Option<u64> {
        sys::get_u64(address.get()).ok()
    }

    pub(crate) fn get_strlit(&self, address: Address, strtype: c_int) -> Option<String> {
        sys::get_strlit(address.get(), strtype).ok()
    }

    pub(crate) fn decode_insn(&self, address: Address, out: *mut sys::InstructionRaw) -> c_int {
        unsafe { sys::idakit_decode_insn(address.get(), out) }
    }

    pub(crate) fn get_flags(&self, address: Address) -> u64 {
        sys::get_flags(address.get())
    }

    pub(crate) fn get_item_head(&self, address: Address) -> sys::Address {
        sys::get_item_head(address.get())
    }

    pub(crate) fn get_item_end(&self, address: Address) -> sys::Address {
        sys::get_item_end(address.get())
    }

    pub(crate) fn get_next_head(&self, address: Address, maxea: Address) -> sys::Address {
        sys::get_next_head(address.get(), maxea.get())
    }

    pub(crate) fn get_prev_head(&self, address: Address, minea: Address) -> sys::Address {
        sys::get_prev_head(address.get(), minea.get())
    }

    pub(crate) fn bitness_bits(&self) -> c_int {
        sys::bitness()
    }

    pub(crate) fn image_base(&self) -> sys::Address {
        sys::image_base()
    }

    pub(crate) fn min_ea(&self) -> sys::Address {
        sys::min_ea()
    }

    pub(crate) fn max_ea(&self) -> sys::Address {
        sys::max_ea()
    }

    pub(crate) fn proc_name(&self) -> Option<String> {
        sys::proc_name().ok()
    }

    pub(crate) fn file_type_name(&self) -> Option<String> {
        sys::file_type_name().ok()
    }

    pub(crate) fn input_path(&self) -> Option<String> {
        sys::input_path().ok()
    }

    pub(crate) fn root_filename(&self) -> Option<String> {
        sys::root_filename().ok()
    }

    pub(crate) fn get_ea_name(&self, address: Address) -> Option<String> {
        sys::get_ea_name(address.get()).ok()
    }

    pub(crate) fn get_name_ea(&self, name: &str) -> sys::Address {
        sys::get_name_ea(name)
    }

    pub(crate) fn demangle_name(&self, name: &str) -> Option<String> {
        sys::demangle_name(name).ok()
    }

    pub(crate) fn nlist_size(&self) -> usize {
        sys::nlist_size()
    }

    pub(crate) fn nlist_ea(&self, idx: usize) -> sys::Address {
        sys::nlist_ea(idx)
    }

    pub(crate) fn nlist_name(&self, idx: usize) -> Option<String> {
        sys::nlist_name(idx).ok()
    }

    /// Every cross-reference edge at `address`, as an owned snapshot.
    ///
    /// `is_to` selects xrefs targeting `address` vs originating at it. The [`Xrefs`] iterator owns
    /// the returned `Vec` and needs no kernel access to walk it.
    ///
    /// [`Xrefs`]: crate::Xrefs
    pub(crate) fn xrefs_build(&self, address: Address, is_to: bool) -> Vec<sys::XrefRec> {
        sys::xrefs_build(address.get(), is_to)
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

    pub(crate) fn get_cmt(&self, address: Address, repeatable: bool) -> Option<String> {
        sys::get_cmt(address.get(), repeatable).ok()
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
        sys::func_qty()
    }

    pub(crate) fn func_ea(&self, n: usize) -> sys::Address {
        sys::func_ea(n)
    }

    pub(crate) fn func_name(&self, address: Address) -> Option<String> {
        sys::func_name(address.get()).ok()
    }

    /// Every chunk of the function at `address` (entry chunk first), as an owned range snapshot;
    /// empty when no function lives there.
    pub(crate) fn range_all_chunks(&self, address: Address) -> Vec<sys::RangeT> {
        sys::range_all_chunks(address.get()).unwrap_or_default()
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
        sys::func_start(address.get())
    }

    pub(crate) fn func_end(&self, address: Address) -> sys::Address {
        sys::func_end(address.get())
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

    /// Replaces the return type of the function at `address` with the recipe `buf`; the reason is
    /// copied out of the facade buffer on a build or apply failure.
    pub(crate) fn func_set_rettype(&mut self, address: Address, buf: &[u8]) -> (c_int, String) {
        let mut err = [0u8; 1024];
        // SAFETY: `buf` is readable of `buf.len()`; `err` is a writable buffer the facade
        // NUL-terminates within.
        let code = unsafe {
            sys::idakit_func_set_rettype(
                address.get(),
                buf.as_ptr(),
                buf.len(),
                err.as_mut_ptr().cast(),
                err.len(),
            )
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        (code, unsafe { cstr(err.as_ptr().cast()) })
    }

    /// Replaces parameter `idx`'s type at `address` with the recipe `buf`, returning the code, the
    /// current parameter count (for an out-of-range diagnostic), and any reason.
    pub(crate) fn func_set_argtype(
        &mut self,
        address: Address,
        idx: usize,
        buf: &[u8],
    ) -> (c_int, usize, String) {
        let mut err = [0u8; 1024];
        let mut arity = 0usize;
        // SAFETY: `buf` is readable of `buf.len()`; `arity`/`err` are writable out-params the facade
        // fills, `err` NUL-terminated within.
        let code = unsafe {
            sys::idakit_func_set_argtype(
                address.get(),
                idx,
                buf.as_ptr(),
                buf.len(),
                &mut arity,
                err.as_mut_ptr().cast(),
                err.len(),
            )
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        (code, arity, unsafe { cstr(err.as_ptr().cast()) })
    }

    /// Renames parameter `idx` at `address`, returning the code, the current parameter count, and
    /// any reason.
    pub(crate) fn func_rename_arg(
        &mut self,
        address: Address,
        idx: usize,
        name: *const c_char,
    ) -> (c_int, usize, String) {
        let mut err = [0u8; 1024];
        let mut arity = 0usize;
        // SAFETY: `name` is a valid C string; `arity`/`err` are writable out-params the facade
        // fills, `err` NUL-terminated within.
        let code = unsafe {
            sys::idakit_func_rename_arg(
                address.get(),
                idx,
                name,
                &mut arity,
                err.as_mut_ptr().cast(),
                err.len(),
            )
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        (code, arity, unsafe { cstr(err.as_ptr().cast()) })
    }

    /// Sets the calling convention (a raw `CM_CC_*` code) of the function at `address`.
    pub(crate) fn func_set_cc(&mut self, address: Address, cc: c_int) -> (c_int, String) {
        let mut err = [0u8; 1024];
        // SAFETY: `err` is a writable buffer the facade NUL-terminates within.
        let code = unsafe {
            sys::idakit_func_set_cc(address.get(), cc, err.as_mut_ptr().cast(), err.len())
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        (code, unsafe { cstr(err.as_ptr().cast()) })
    }

    /// Inserts a leading implicit `this` parameter of recipe type `buf` at `address`.
    pub(crate) fn func_prepend_this(&mut self, address: Address, buf: &[u8]) -> (c_int, String) {
        let mut err = [0u8; 1024];
        // SAFETY: `buf` is readable of `buf.len()`; `err` is a writable buffer the facade
        // NUL-terminates within.
        let code = unsafe {
            sys::idakit_func_prepend_this(
                address.get(),
                buf.as_ptr(),
                buf.len(),
                err.as_mut_ptr().cast(),
                err.len(),
            )
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        (code, unsafe { cstr(err.as_ptr().cast()) })
    }

    /// Adds a member named `member_name` of recipe type `buf` to the named UDT `type_name` at
    /// `member_bit` (or [`sys::IDAKIT_MEMBER_APPEND`]); returns the code and any reason.
    pub(crate) fn udt_add_member(
        &mut self,
        type_name: *const c_char,
        member_name: *const c_char,
        buf: &[u8],
        member_bit: u64,
    ) -> (c_int, String) {
        let mut err = [0u8; 1024];
        // SAFETY: the name pointers are valid C strings; `buf` is readable of `buf.len()`; `err` is
        // a writable buffer the facade NUL-terminates within.
        let code = unsafe {
            sys::idakit_udt_add_member(
                type_name,
                member_name,
                buf.as_ptr(),
                buf.len(),
                member_bit,
                err.as_mut_ptr().cast(),
                err.len(),
            )
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        (code, unsafe { cstr(err.as_ptr().cast()) })
    }

    /// Replaces the type of the member selected by `member_name` (null selects by `member_bit`) in
    /// the named UDT `type_name` with recipe `buf`; returns the code and any reason.
    pub(crate) fn udt_set_member_type(
        &mut self,
        type_name: *const c_char,
        member_name: *const c_char,
        member_bit: u64,
        buf: &[u8],
    ) -> (c_int, String) {
        let mut err = [0u8; 1024];
        // SAFETY: name pointers are valid C strings; `buf` is readable of `buf.len()`; `err` is a
        // writable buffer the facade NUL-terminates within.
        let code = unsafe {
            sys::idakit_udt_set_member_type(
                type_name,
                member_name,
                member_bit,
                buf.as_ptr(),
                buf.len(),
                err.as_mut_ptr().cast(),
                err.len(),
            )
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        (code, unsafe { cstr(err.as_ptr().cast()) })
    }

    /// Renames the member selected by `member_name` (null selects by `member_bit`) in the named UDT
    /// `type_name` to `new_name`; returns the code and any reason.
    pub(crate) fn udt_rename_member(
        &mut self,
        type_name: *const c_char,
        member_name: *const c_char,
        member_bit: u64,
        new_name: *const c_char,
    ) -> (c_int, String) {
        let mut err = [0u8; 1024];
        // SAFETY: the name pointers are valid C strings; `err` is a writable buffer the facade
        // NUL-terminates within.
        let code = unsafe {
            sys::idakit_udt_rename_member(
                type_name,
                member_name,
                member_bit,
                new_name,
                err.as_mut_ptr().cast(),
                err.len(),
            )
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        (code, unsafe { cstr(err.as_ptr().cast()) })
    }

    /// Deletes the member selected by `member_name` (null selects by `member_bit`) from the named
    /// UDT `type_name`; returns the code and any reason.
    pub(crate) fn udt_del_member(
        &mut self,
        type_name: *const c_char,
        member_name: *const c_char,
        member_bit: u64,
    ) -> (c_int, String) {
        let mut err = [0u8; 1024];
        // SAFETY: the name pointers are valid C strings; `err` is a writable buffer the facade
        // NUL-terminates within.
        let code = unsafe {
            sys::idakit_udt_del_member(
                type_name,
                member_name,
                member_bit,
                err.as_mut_ptr().cast(),
                err.len(),
            )
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        (code, unsafe { cstr(err.as_ptr().cast()) })
    }

    /// Adds an enum constant `member_name` = `value` to the named enum `type_name`; returns the
    /// code and any reason.
    pub(crate) fn enum_add_member(
        &mut self,
        type_name: *const c_char,
        member_name: *const c_char,
        value: u64,
    ) -> (c_int, String) {
        let mut err = [0u8; 1024];
        // SAFETY: the name pointers are valid C strings; `err` is a writable buffer the facade
        // NUL-terminates within.
        let code = unsafe {
            sys::idakit_enum_add_member(
                type_name,
                member_name,
                value,
                err.as_mut_ptr().cast(),
                err.len(),
            )
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        (code, unsafe { cstr(err.as_ptr().cast()) })
    }

    /// Sets the value of enum constant `member_name` in the named enum `type_name`; returns the
    /// code and any reason.
    pub(crate) fn enum_set_member_value(
        &mut self,
        type_name: *const c_char,
        member_name: *const c_char,
        value: u64,
    ) -> (c_int, String) {
        let mut err = [0u8; 1024];
        // SAFETY: the name pointers are valid C strings; `err` is a writable buffer the facade
        // NUL-terminates within.
        let code = unsafe {
            sys::idakit_enum_set_member_value(
                type_name,
                member_name,
                value,
                err.as_mut_ptr().cast(),
                err.len(),
            )
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        (code, unsafe { cstr(err.as_ptr().cast()) })
    }

    /// Renames enum constant `member_name` in the named enum `type_name` to `new_name`; returns the
    /// code and any reason.
    pub(crate) fn enum_rename_member(
        &mut self,
        type_name: *const c_char,
        member_name: *const c_char,
        new_name: *const c_char,
    ) -> (c_int, String) {
        let mut err = [0u8; 1024];
        // SAFETY: the name pointers are valid C strings; `err` is a writable buffer the facade
        // NUL-terminates within.
        let code = unsafe {
            sys::idakit_enum_rename_member(
                type_name,
                member_name,
                new_name,
                err.as_mut_ptr().cast(),
                err.len(),
            )
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        (code, unsafe { cstr(err.as_ptr().cast()) })
    }

    /// Deletes enum constant `member_name` from the named enum `type_name`; returns the code and
    /// any reason.
    pub(crate) fn enum_del_member(
        &mut self,
        type_name: *const c_char,
        member_name: *const c_char,
    ) -> (c_int, String) {
        let mut err = [0u8; 1024];
        // SAFETY: the name pointers are valid C strings; `err` is a writable buffer the facade
        // NUL-terminates within.
        let code = unsafe {
            sys::idakit_enum_del_member(type_name, member_name, err.as_mut_ptr().cast(), err.len())
        };
        // SAFETY: `err` holds a NUL-terminated string written by the facade.
        (code, unsafe { cstr(err.as_ptr().cast()) })
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
        sys::func_flags(address.get())
    }

    pub(crate) fn seg_qty(&self) -> c_int {
        sys::gen_seg_qty() as c_int
    }

    pub(crate) fn seg_name(&self, n: c_int) -> Option<String> {
        sys::gen_seg_name(n).ok()
    }

    pub(crate) fn seg_start(&self, n: c_int) -> sys::Address {
        sys::gen_seg_start(n)
    }

    pub(crate) fn seg_end(&self, n: c_int) -> sys::Address {
        sys::gen_seg_end(n)
    }

    pub(crate) fn seg_perm(&self, n: c_int) -> c_int {
        sys::gen_seg_perm(n)
    }

    pub(crate) fn seg_bitness(&self, n: c_int) -> c_int {
        sys::gen_seg_bitness(n)
    }

    pub(crate) fn seg_class(&self, n: c_int) -> Option<String> {
        sys::gen_seg_class(n).ok()
    }

    pub(crate) fn export_qty(&self) -> usize {
        sys::export_qty()
    }

    pub(crate) fn export_ea(&self, idx: usize) -> sys::Address {
        sys::export_ea(idx)
    }

    pub(crate) fn export_ordinal(&self, idx: usize) -> u64 {
        sys::export_ordinal(idx)
    }

    pub(crate) fn export_name(&self, idx: usize) -> Option<String> {
        sys::export_name(idx).ok()
    }

    pub(crate) fn export_forwarder(&self, idx: usize) -> Option<String> {
        sys::export_forwarder(idx).ok()
    }

    /// The whole import table as an owned snapshot.
    ///
    /// The [`Imports`] iterator owns the returned `Vec` and needs no kernel access to walk it.
    ///
    /// [`Imports`]: crate::Imports
    pub(crate) fn imports_build(&self) -> Vec<sys::ImportRec> {
        sys::imports_build()
    }

    /// (Re)builds IDA's global string list, a query-time scan, not a database mutation.
    pub(crate) fn strlist_build(&self) {
        sys::strlist_build();
    }

    pub(crate) fn strlist_qty(&self) -> usize {
        sys::strlist_qty()
    }

    pub(crate) fn strlist_item(&self, n: usize) -> Option<sys::StrlistItem> {
        sys::strlist_item(n).ok()
    }

    pub(crate) fn strlit_contents(
        &self,
        address: Address,
        len: usize,
        ty: c_int,
    ) -> Option<String> {
        sys::strlit_contents(address.get(), len, ty).ok()
    }
}
