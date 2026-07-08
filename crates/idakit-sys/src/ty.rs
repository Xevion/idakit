//! Type-information facade (`idakit_func_type`, `idakit_type_*`).

use std::ffi::{c_char, c_int, c_void};

use crate::Address;
use crate::hexrays::TypeVtbl;

unsafe extern "C" {
    pub fn idakit_func_type(address: Address, buf: *mut c_char, cap: usize) -> i64;

    /// Resolve the local named type `name` and walk it into one interned table via `v` (with
    /// `ctx`), writing its root handle to `*root`. Returns 0 on success, non-zero if no such type.
    pub fn idakit_type_walk(
        name: *const c_char,
        v: *const TypeVtbl,
        ctx: *mut c_void,
        root: *mut u32,
    ) -> c_int;

    /// Walk the stored prototype of the function at `address` into one interned table via `v`
    /// (with `ctx`), writing its root handle to `*root`. Returns 0 on success, non-zero if the
    /// function has no type info.
    pub fn idakit_func_type_walk(
        address: Address,
        v: *const TypeVtbl,
        ctx: *mut c_void,
        root: *mut u32,
    ) -> c_int;

    /// Exclusive upper bound on local-type ordinals: valid ordinals run `1..limit`.
    pub fn idakit_type_ordinal_limit() -> u32;

    /// Name of the type at `ordinal` into `(buf, cap)`, returning its full length (0 for an
    /// anonymous type, negative if the ordinal holds no type).
    pub fn idakit_type_name_at(ordinal: u32, buf: *mut c_char, cap: usize) -> i64;

    /// Walk the type at `ordinal` into one interned table via `v` (with `ctx`), writing its root
    /// handle to `*root`. The ordinal counterpart to [`idakit_type_walk`]; non-zero if empty.
    pub fn idakit_type_walk_ordinal(
        ordinal: u32,
        v: *const TypeVtbl,
        ctx: *mut c_void,
        root: *mut u32,
    ) -> c_int;

    /// Parse `decl` against the local til and apply it at `ea` (`apply_tinfo`, `TINFO_DEFINITE |
    /// flags`). Returns [`IDAKIT_TYPE_OK`]/[`IDAKIT_TYPE_ERR_INPUT`] (parse failed)/
    /// [`IDAKIT_TYPE_ERR_APPLY`]; any captured IDA diagnostic is copied to `errbuf` (truncated to
    /// `cap`).
    pub fn idakit_apply_type_decl(
        ea: Address,
        decl: *const c_char,
        flags: c_int,
        errbuf: *mut c_char,
        cap: usize,
    ) -> c_int;

    /// Resolve the existing named type `name` in the local til and apply it at `ea`. The code
    /// distinguishes not-found ([`IDAKIT_TYPE_ERR_INPUT`]) from an apply rejection
    /// ([`IDAKIT_TYPE_ERR_APPLY`]); there is no error text.
    pub fn idakit_apply_named_type(ea: Address, name: *const c_char) -> c_int;

    /// Parse C declaration(s) in `input` into the database's local til, returning the error count
    /// (0 = ok) with any diagnostics copied to `errbuf` (truncated to `cap`).
    pub fn idakit_define_type(input: *const c_char, errbuf: *mut c_char, cap: usize) -> c_int;
}

/// Result of a successful type apply ([`idakit_apply_type_decl`]/[`idakit_apply_named_type`]).
pub const IDAKIT_TYPE_OK: c_int = 0;
/// A bad input to a type apply: an unparseable declaration, or a named type that does not exist.
pub const IDAKIT_TYPE_ERR_INPUT: c_int = 1;
/// `apply_tinfo` rejected the parsed/resolved type at the address.
pub const IDAKIT_TYPE_ERR_APPLY: c_int = 2;
