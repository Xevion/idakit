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

// `&self`/`&mut self` here is the kernel-thread token proven live by holding a `Database` (see
// the module doc above), not a source of instance state, so several forwarders never touch it.
#![expect(
    clippy::unused_self,
    reason = "&self is the kernel-thread/live-database proof token, not instance state"
)]
#![expect(
    clippy::needless_pass_by_ref_mut,
    reason = "&mut self proves write-exclusivity on the kernel thread, not a mutated field"
)]

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
        unsafe { sys::guarded_open(path, run_auto as c_int) }
    }

    /// The exit code IDA passed to `exit()` on the last trapped fatal open.
    pub(crate) fn last_exit_code(&self) -> c_int {
        unsafe { sys::last_exit_code() }
    }

    /// The stdout+stderr IDA emitted during the last guarded open, captured by the
    /// facade instead of leaking to the caller's console.
    pub(crate) fn last_output(&self) -> String {
        crate::ffi::read_string(|buf, cap| unsafe { sys::last_output(buf, cap) as i64 })
            .unwrap_or_default()
    }

    /// Records EULA acceptance in IDA's registry, and returns whether it now reads accepted.
    pub(crate) fn reg_accept_eula(&self) -> bool {
        unsafe { sys::accept_eula() != 0 }
    }

    /// Blocks until the auto-analysis queue drains. Only meaningful after an
    /// `open_database(run_auto = true)`, which enables but does not await analysis.
    /// Guarded: returns [`sys::IDAKIT_EXIT_TRAPPED`] if analysis hit a fatal exit().
    pub(crate) fn auto_wait(&self) -> c_int {
        unsafe { sys::guarded_auto_wait() }
    }

    /// Guarded close, where a fatal during a save is trapped (returns the sentinel) rather
    /// than killing the process. Best-effort, since by the time we close, the result is
    /// moot.
    pub(crate) fn close_database(&mut self, save: bool) {
        unsafe { sys::guarded_close(save as c_int) };
    }

    /// Whether the most recent guarded facade call trapped a fatal exit().
    pub(crate) fn was_trapped(&self) -> bool {
        unsafe { sys::was_trapped() != 0 }
    }

    /// Zero-alloc read into `buf`; the generated `get_bytes` returns an owned `Vec`, so it can't
    /// back this buffer-fill twin, which stays on the raw facade. [`get_bytes_owned`] is the
    /// owning generated path.
    ///
    /// [`get_bytes_owned`]: Self::get_bytes_owned
    pub(crate) fn get_bytes(&self, address: Address, buf: *mut c_void, size: usize) -> i64 {
        unsafe { sys::get_bytes_into(address.get(), buf, size) }
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

    // The remaining forwarders carry no logic beyond argument coercion (`address.get()`,
    // `.ok()`, casts) and a possibly-renamed `sys` symbol, so they collapse into `forward!`.
    forward! {
        fn get_bytes_owned(&self, address: Address, size: usize) -> Option<Vec<u8>>
            = sys::get_bytes(address.get(), size).ok();
        fn get_u8(&self, address: Address) -> Option<u8> = sys::get_u8(address.get()).ok();
        fn get_u16(&self, address: Address) -> Option<u16> = sys::get_u16(address.get()).ok();
        fn get_u32(&self, address: Address) -> Option<u32> = sys::get_u32(address.get()).ok();
        fn get_u64(&self, address: Address) -> Option<u64> = sys::get_u64(address.get()).ok();
        fn get_strlit(&self, address: Address, strtype: c_int) -> Option<String>
            = sys::get_strlit(address.get(), strtype).ok();
        fn decode_insn(&self, address: Address) -> sys::InstructionData
            = sys::decode_insn(address.get());
        fn get_flags(&self, address: Address) -> u64 = sys::get_flags(address.get());
        fn get_item_head(&self, address: Address) -> sys::Address
            = sys::get_item_head(address.get());
        fn get_item_end(&self, address: Address) -> sys::Address
            = sys::get_item_end(address.get());
        fn get_next_head(&self, address: Address, maxea: Address) -> sys::Address
            = sys::get_next_head(address.get(), maxea.get());
        fn get_prev_head(&self, address: Address, minea: Address) -> sys::Address
            = sys::get_prev_head(address.get(), minea.get());
    }

    forward! {
        fn bitness_bits(&self) -> c_int = sys::bitness();
        fn image_base(&self) -> sys::Address = sys::image_base();
        fn min_ea(&self) -> sys::Address = sys::min_ea();
        fn max_ea(&self) -> sys::Address = sys::max_ea();
        fn proc_name(&self) -> Option<String> = sys::proc_name().ok();
        fn file_type_name(&self) -> Option<String> = sys::file_type_name().ok();
        fn input_path(&self) -> Option<String> = sys::input_path().ok();
        fn root_filename(&self) -> Option<String> = sys::root_filename().ok();
        fn get_ea_name(&self, address: Address) -> Option<String>
            = sys::get_ea_name(address.get()).ok();
        fn get_name_ea(&self, name: &str) -> sys::Address = sys::get_name_ea(name);
        fn demangle_name(&self, name: &str) -> Option<String> = sys::demangle_name(name).ok();
        fn nlist_size(&self) -> usize = sys::nlist_size();
        fn nlist_ea(&self, idx: usize) -> sys::Address = sys::nlist_ea(idx);
        fn nlist_name(&self, idx: usize) -> Option<String> = sys::nlist_name(idx).ok();
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

    forward! {
        fn hexrays_init(&self) -> bool = sys::hexrays_init();
        fn mark_cfunc_dirty(&mut self, address: Address, close_views: bool) -> bool
            = sys::mark_cfunc_dirty(address.get(), close_views);
        fn clear_cached_cfuncs(&mut self) = sys::clear_cached_cfuncs();
        fn has_cached_cfunc(&self, address: Address) -> bool
            = sys::has_cached_cfunc(address.get());
        fn get_cmt(&self, address: Address, repeatable: bool) -> Option<String>
            = sys::get_cmt(address.get(), repeatable).ok();
        fn patch_bytes(&mut self, address: Address, bytes: &[u8]) -> bool
            = sys::patch_bytes(address.get(), bytes);
    }

    forward! {
        fn func_qty(&self) -> usize = sys::func_qty();
        fn func_ea(&self, n: usize) -> sys::Address = sys::func_ea(n);
        fn func_name(&self, address: Address) -> Option<String> = sys::func_name(address.get()).ok();
        fn func_type(&self, address: Address) -> Option<String> = sys::func_type(address.get()).ok();
        fn func_start(&self, address: Address) -> sys::Address = sys::func_start(address.get());
        fn func_end(&self, address: Address) -> sys::Address = sys::func_end(address.get());
        fn func_flags(&self, address: Address) -> u64 = sys::func_flags(address.get());
        fn type_ordinal_limit(&self) -> u32 = sys::type_ordinal_limit();
        fn type_name_at(&self, ordinal: u32) -> String = sys::type_name_at(ordinal).unwrap_or_default();
    }

    /// Every chunk of the function at `address` (entry chunk first), as an owned range snapshot;
    /// empty when no function lives there.
    pub(crate) fn range_all_chunks(&self, address: Address) -> Vec<sys::RangeT> {
        sys::range_all_chunks(address.get()).unwrap_or_default()
    }

    forward! {
        fn apply_type_decl(&mut self, address: Address, decl: &str, flags: c_int) -> sys::TypeWriteResult
            = sys::apply_type_decl(address.get(), decl, flags);
        fn apply_named_type(&mut self, address: Address, name: &str) -> sys::TypeWriteResult
            = sys::apply_named_type(address.get(), name);
        fn clear_type(&mut self, address: Address) -> sys::TypeWriteResult
            = sys::clear_type(address.get());
        fn apply_type_recipe(&mut self, address: Address, buf: &[u8], flags: c_int) -> sys::TypeWriteResult
            = sys::apply_type_recipe(address.get(), buf, flags);
        fn apply_tinfo(&mut self, address: Address, handle: &sys::TInfo, flags: c_int) -> sys::TypeWriteResult
            = sys::tinfo_apply(address.get(), handle, flags);
        fn func_set_rettype(&mut self, address: Address, buf: &[u8]) -> sys::TypeWriteResult
            = sys::func_set_rettype(address.get(), buf);
        fn func_set_argtype(&mut self, address: Address, idx: usize, buf: &[u8]) -> sys::SigWriteResult
            = sys::func_set_argtype(address.get(), idx, buf);
        fn func_rename_arg(&mut self, address: Address, idx: usize, name: &str) -> sys::SigWriteResult
            = sys::func_rename_arg(address.get(), idx, name);
        fn func_set_cc(&mut self, address: Address, cc: c_int) -> sys::TypeWriteResult
            = sys::func_set_cc(address.get(), cc);
        fn func_prepend_this(&mut self, address: Address, buf: &[u8]) -> sys::TypeWriteResult
            = sys::func_prepend_this(address.get(), buf);
    }

    forward! {
        fn udt_add_member(&mut self, type_name: &str, member_name: &str, buf: &[u8], member_bit: u64) -> sys::TypeWriteResult
            = sys::udt_add_member(type_name, member_name, buf, member_bit);
        fn udt_set_member_type(&mut self, type_name: &str, member_name: &str, member_bit: u64, buf: &[u8], etf_flags: u32) -> sys::TypeWriteResult
            = sys::udt_set_member_type(type_name, member_name, member_bit, buf, etf_flags);
        fn udt_rename_member(&mut self, type_name: &str, member_name: &str, member_bit: u64, new_name: &str) -> sys::TypeWriteResult
            = sys::udt_rename_member(type_name, member_name, member_bit, new_name);
        fn udt_set_member_comment(&mut self, type_name: &str, member_name: &str, member_bit: u64, comment: &str) -> sys::TypeWriteResult
            = sys::udt_set_member_comment(type_name, member_name, member_bit, comment);
        fn udt_set_member_repr(&mut self, type_name: &str, member_name: &str, member_bit: u64, vtype: u32, is_signed: bool, leading_zeros: bool) -> sys::TypeWriteResult
            = sys::udt_set_member_repr(type_name, member_name, member_bit, vtype, is_signed, leading_zeros);
        fn udt_del_member(&mut self, type_name: &str, member_name: &str, member_bit: u64) -> sys::TypeWriteResult
            = sys::udt_del_member(type_name, member_name, member_bit);
    }

    forward! {
        fn enum_add_member(&mut self, type_name: &str, member_name: &str, value: u64, bmask: u64, etf_flags: u32) -> sys::TypeWriteResult
            = sys::enum_add_member(type_name, member_name, value, bmask, etf_flags);
        fn enum_set_bitmask(&mut self, type_name: &str, on: bool) -> sys::TypeWriteResult
            = sys::enum_set_bitmask(type_name, on);
        fn enum_set_repr(&mut self, type_name: &str, vtype: u32, is_signed: bool, leading_zeros: bool) -> sys::TypeWriteResult
            = sys::enum_set_repr(type_name, vtype, is_signed, leading_zeros);
        fn enum_set_width(&mut self, type_name: &str, nbytes: i32) -> sys::TypeWriteResult
            = sys::enum_set_width(type_name, nbytes);
        fn enum_set_member_value(&mut self, type_name: &str, member_name: &str, value: u64) -> sys::TypeWriteResult
            = sys::enum_set_member_value(type_name, member_name, value);
        fn enum_rename_member(&mut self, type_name: &str, member_name: &str, new_name: &str, etf_flags: u32) -> sys::TypeWriteResult
            = sys::enum_rename_member(type_name, member_name, new_name, etf_flags);
        fn enum_del_member(&mut self, type_name: &str, member_name: &str) -> sys::TypeWriteResult
            = sys::enum_del_member(type_name, member_name);
        fn enum_del_member_by_value(&mut self, type_name: &str, value: u64) -> sys::TypeWriteResult
            = sys::enum_del_member_by_value(type_name, value);
        fn define_type(&mut self, input: &str) -> sys::TypeWriteResult = sys::define_type(input);
        fn delete_type(&mut self, type_name: &str) -> sys::TypeWriteResult = sys::delete_type(type_name);
        fn rename_type(&mut self, type_name: &str, new_name: &str) -> sys::TypeWriteResult
            = sys::rename_type(type_name, new_name);
        fn forward_declare_type(&mut self, type_name: &str, decl_type: u32) -> sys::TypeWriteResult
            = sys::forward_declare_type(type_name, decl_type);
    }

    forward! {
        fn seg_qty(&self) -> c_int = sys::gen_seg_qty() as c_int;
        fn seg_name(&self, n: c_int) -> Option<String> = sys::gen_seg_name(n).ok();
        fn seg_start(&self, n: c_int) -> sys::Address = sys::gen_seg_start(n);
        fn seg_end(&self, n: c_int) -> sys::Address = sys::gen_seg_end(n);
        fn seg_perm(&self, n: c_int) -> c_int = sys::gen_seg_perm(n);
        fn seg_bitness(&self, n: c_int) -> c_int = sys::gen_seg_bitness(n);
        fn seg_class(&self, n: c_int) -> Option<String> = sys::gen_seg_class(n).ok();
        fn export_qty(&self) -> usize = sys::export_qty();
        fn export_ea(&self, idx: usize) -> sys::Address = sys::export_ea(idx);
        fn export_ordinal(&self, idx: usize) -> u64 = sys::export_ordinal(idx);
        fn export_name(&self, idx: usize) -> Option<String> = sys::export_name(idx).ok();
        fn export_forwarder(&self, idx: usize) -> Option<String> = sys::export_forwarder(idx).ok();
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

    forward! {
        fn strlist_qty(&self) -> usize = sys::strlist_qty();
        fn strlist_item(&self, n: usize) -> Option<sys::StrlistItem> = sys::strlist_item(n).ok();
        fn strlit_contents(&self, address: Address, len: usize, ty: c_int) -> Option<String>
            = sys::strlit_contents(address.get(), len, ty).ok();
    }

    forward! {
        fn netnode_open(&self, name: &str) -> u64 = sys::netnode_by_name(name, false);
        fn netnode_create(&mut self, name: &str) -> u64 = sys::netnode_by_name(name, true);
        fn netnode_exists(&self, node: u64) -> bool = sys::netnode_exists(node);
        fn netnode_get_name(&self, node: u64) -> Option<String> = sys::netnode_get_name(node).ok();
        fn netnode_rename(&mut self, node: u64, name: &str) -> bool = sys::netnode_rename(node, name);
        fn netnode_kill(&mut self, node: u64) = sys::netnode_kill(node);
        fn netnode_first(&self) -> u64 = sys::netnode_first();
        fn netnode_next(&self, cur: u64) -> u64 = sys::netnode_next(cur);
        fn netnode_value(&self, node: u64) -> Option<Vec<u8>> = sys::netnode_value(node).ok();
        fn netnode_value_str(&self, node: u64) -> Option<String> = sys::netnode_value_str(node).ok();
        fn netnode_set_value(&mut self, node: u64, value: &[u8]) -> bool = sys::netnode_set_value(node, value);
        fn netnode_del_value(&mut self, node: u64) -> bool = sys::netnode_del_value(node);
    }

    forward! {
        fn netnode_altval(&self, node: u64, idx: u64, tag: u32) -> u64 = sys::netnode_altval(node, idx, tag);
        fn netnode_altset(&mut self, node: u64, idx: u64, value: u64, tag: u32) -> bool = sys::netnode_altset(node, idx, value, tag);
        fn netnode_altdel(&mut self, node: u64, idx: u64, tag: u32) -> bool = sys::netnode_altdel(node, idx, tag);
        fn netnode_altdel_all(&mut self, node: u64, tag: u32) -> bool = sys::netnode_altdel_all(node, tag);
        fn netnode_altfirst(&self, node: u64, tag: u32) -> u64 = sys::netnode_altfirst(node, tag);
        fn netnode_altnext(&self, node: u64, cur: u64, tag: u32) -> u64 = sys::netnode_altnext(node, cur, tag);
        fn netnode_supval(&self, node: u64, idx: u64, tag: u32) -> Option<Vec<u8>> = sys::netnode_supval(node, idx, tag).ok();
        fn netnode_supset(&mut self, node: u64, idx: u64, value: &[u8], tag: u32) -> bool = sys::netnode_supset(node, idx, value, tag);
        fn netnode_supdel(&mut self, node: u64, idx: u64, tag: u32) -> bool = sys::netnode_supdel(node, idx, tag);
        fn netnode_supdel_all(&mut self, node: u64, tag: u32) -> bool = sys::netnode_supdel_all(node, tag);
        fn netnode_supfirst(&self, node: u64, tag: u32) -> u64 = sys::netnode_supfirst(node, tag);
        fn netnode_supnext(&self, node: u64, cur: u64, tag: u32) -> u64 = sys::netnode_supnext(node, cur, tag);
    }

    forward! {
        fn netnode_hashval(&self, node: u64, key: &str, tag: u32) -> Option<Vec<u8>> = sys::netnode_hashval(node, key, tag).ok();
        fn netnode_hashval_long(&self, node: u64, key: &str, tag: u32) -> u64 = sys::netnode_hashval_long(node, key, tag);
        fn netnode_hashset(&mut self, node: u64, key: &str, value: &[u8], tag: u32) -> bool = sys::netnode_hashset(node, key, value, tag);
        fn netnode_hashset_long(&mut self, node: u64, key: &str, value: u64, tag: u32) -> bool = sys::netnode_hashset_long(node, key, value, tag);
        fn netnode_hashdel(&mut self, node: u64, key: &str, tag: u32) -> bool = sys::netnode_hashdel(node, key, tag);
        fn netnode_hashdel_all(&mut self, node: u64, tag: u32) -> bool = sys::netnode_hashdel_all(node, tag);
        fn netnode_hashfirst(&self, node: u64, tag: u32) -> Option<String> = sys::netnode_hashfirst(node, tag).ok();
        fn netnode_hashnext(&self, node: u64, key: &str, tag: u32) -> Option<String> = sys::netnode_hashnext(node, key, tag).ok();
        fn netnode_blobsize(&self, node: u64, start: u64, tag: u32) -> usize = sys::netnode_blobsize(node, start, tag);
        fn netnode_getblob(&self, node: u64, start: u64, tag: u32) -> Option<Vec<u8>> = sys::netnode_getblob(node, start, tag).ok();
        fn netnode_setblob(&mut self, node: u64, value: &[u8], start: u64, tag: u32) -> bool = sys::netnode_setblob(node, value, start, tag);
        fn netnode_delblob(&mut self, node: u64, start: u64, tag: u32) -> i32 = sys::netnode_delblob(node, start, tag);
    }
}
