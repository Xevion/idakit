//! Type-write facade (`idakit_apply_*`, `idakit_define_type`, `idakit_apply_type_recipe`, the
//! granular `idakit_tinfo_*` builders).

use std::ffi::{c_char, c_int, c_void};

use crate::Address;

unsafe extern "C" {
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

    /// Clear any type applied at `address` (`set_tinfo` to null). Idempotent:
    /// [`IDAKIT_TYPE_OK`] when there was nothing to clear, [`IDAKIT_TYPE_ERR_APPLY`] only if the
    /// kernel refuses to remove an existing type.
    pub fn idakit_clear_type(ea: Address) -> c_int;

    /// Build the `tinfo` the postfix recipe in `(buf, len)` encodes and apply it at `ea`
    /// (`apply_tinfo`, `TINFO_DEFINITE | flags`). idakit's preferred lowering path: one crossing,
    /// no handle threading. Same codes as [`idakit_apply_type_decl`]; [`IDAKIT_TYPE_ERR_INPUT`] is
    /// a malformed buffer, an unresolved named leaf, or an unparseable embedded decl. The opcodes
    /// are the `IDAKIT_RECIPE_*` constants; multi-byte operands are little-endian.
    pub fn idakit_apply_type_recipe(
        ea: Address,
        buf: *const u8,
        len: usize,
        flags: c_int,
        errbuf: *mut c_char,
        cap: usize,
    ) -> c_int;

    /// The `void` type as a fresh owned handle, freed with [`idakit_tinfo_free`].
    pub fn idakit_tinfo_void() -> *mut c_void;

    /// The boolean type as a fresh owned handle, freed with [`idakit_tinfo_free`].
    pub fn idakit_tinfo_bool() -> *mut c_void;

    /// A `bytes`-wide integer (1/2/4/8/16), signed when `is_signed` is non-zero, as a fresh owned
    /// handle. Null if the width is unsupported.
    pub fn idakit_tinfo_int(bytes: u8, is_signed: c_int) -> *mut c_void;

    /// A `bytes`-wide float (4 or 8) as a fresh owned handle. Null if the width is not 4 or 8.
    pub fn idakit_tinfo_float(bytes: u8) -> *mut c_void;

    /// The existing named type `name`, resolved as a typedef ref into a fresh owned handle. Null if
    /// the local til has no such type.
    pub fn idakit_tinfo_named(name: *const c_char) -> *mut c_void;

    /// The type `decl` parses to against the local til, as a fresh owned handle. Null on a parse
    /// failure, with the reason copied to `errbuf` (truncated to `cap`).
    pub fn idakit_tinfo_decl(decl: *const c_char, errbuf: *mut c_char, cap: usize) -> *mut c_void;

    /// A pointer to `inner` as a fresh owned handle. `inner` is copied, not consumed; both handles
    /// must be freed. Null if `inner` is null.
    pub fn idakit_tinfo_ptr(inner: *const c_void) -> *mut c_void;

    /// An `nelems`-element array of `inner` as a fresh owned handle. `inner` is copied, not
    /// consumed. Null if `inner` is null or `nelems` exceeds `u32`.
    pub fn idakit_tinfo_array(inner: *const c_void, nelems: u64) -> *mut c_void;

    /// A `const`-qualified copy of `inner` as a fresh owned handle. `inner` is not consumed. Null
    /// if `inner` is null.
    pub fn idakit_tinfo_const(inner: *const c_void) -> *mut c_void;

    /// A `volatile`-qualified copy of `inner` as a fresh owned handle. `inner` is not consumed.
    /// Null if `inner` is null.
    pub fn idakit_tinfo_volatile(inner: *const c_void) -> *mut c_void;

    /// Apply the built `handle` at `ea` (`apply_tinfo`, `TINFO_DEFINITE | flags`). Returns
    /// [`IDAKIT_TYPE_OK`]/[`IDAKIT_TYPE_ERR_APPLY`] ([`IDAKIT_TYPE_ERR_INPUT`] if `handle` is null),
    /// with any captured diagnostic copied to `errbuf`. Does not free the handle.
    pub fn idakit_tinfo_apply(
        ea: Address,
        handle: *const c_void,
        flags: c_int,
        errbuf: *mut c_char,
        cap: usize,
    ) -> c_int;

    /// Dispose a handle from any `idakit_tinfo_*` builder. Null is tolerated.
    pub fn idakit_tinfo_free(handle: *mut c_void);
}

/// Result of a successful type apply ([`idakit_apply_type_decl`]/[`idakit_apply_named_type`]/
/// [`idakit_apply_type_recipe`]/[`idakit_tinfo_apply`]).
pub const IDAKIT_TYPE_OK: c_int = 0;
/// A bad input to a type apply: an unparseable declaration, a named type that does not exist, or a
/// malformed recipe.
pub const IDAKIT_TYPE_ERR_INPUT: c_int = 1;
/// `apply_tinfo` rejected the parsed/resolved/built type at the address.
pub const IDAKIT_TYPE_ERR_APPLY: c_int = 2;

/// Recipe opcode: push the `void` type. Kept in lockstep with `idakit_facade.h` by hand.
pub const IDAKIT_RECIPE_VOID: u8 = 0;
/// Recipe opcode: push the boolean type.
pub const IDAKIT_RECIPE_BOOL: u8 = 1;
/// Recipe opcode: push an integer, followed by a `u8` width in bytes and a `u8` signedness flag.
pub const IDAKIT_RECIPE_INT: u8 = 2;
/// Recipe opcode: push a float, followed by a `u8` width in bytes.
pub const IDAKIT_RECIPE_FLOAT: u8 = 3;
/// Recipe opcode: push a named-type reference, followed by a `u32` length and that many name bytes.
pub const IDAKIT_RECIPE_NAMED: u8 = 4;
/// Recipe opcode: push a parsed declaration, followed by a `u32` length and that many decl bytes.
pub const IDAKIT_RECIPE_DECL: u8 = 5;
/// Recipe opcode: pop one type, push a pointer to it.
pub const IDAKIT_RECIPE_PTR: u8 = 6;
/// Recipe opcode: pop one type, push an array of it, followed by a `u64` element count.
pub const IDAKIT_RECIPE_ARRAY: u8 = 7;
/// Recipe opcode: pop one type, push its `const`-qualified form.
pub const IDAKIT_RECIPE_CONST: u8 = 8;
/// Recipe opcode: pop one type, push its `volatile`-qualified form.
pub const IDAKIT_RECIPE_VOLATILE: u8 = 9;
