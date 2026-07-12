//! Type-write result codes and recipe opcodes shared with the generated type-build bridge.
//!
//! These constants pin idakit's decode of the generated bridge's `TypeWriteResult.code` and its
//! recipe serialization to the values the generated C++ (`gen_type_build.cc`) emits; the two sides
//! are kept aligned by hand.

use std::ffi::c_int;

/// A prototype-surgery edit succeeded.
pub const IDAKIT_SIG_OK: c_int = 0;
/// The address carries no function type to edit.
pub const IDAKIT_SIG_NO_PROTOTYPE: c_int = 1;
/// A parameter index was past the last parameter.
pub const IDAKIT_SIG_ARG_RANGE: c_int = 2;
/// A replacement-type recipe did not build.
pub const IDAKIT_SIG_BUILD: c_int = 3;
/// `create_func` or `apply_tinfo` rejected the rebuilt signature.
pub const IDAKIT_SIG_APPLY: c_int = 4;

/// Member-edit pre-failure: no such named type in the local til. A positive sentinel; a successful
/// edit is 0 and a kernel rejection is a negative `tinfo_code_t`.
pub const IDAKIT_TEDIT_NO_TYPE: c_int = 1;
/// Member-edit pre-failure: the member (by name or bit offset) did not resolve.
pub const IDAKIT_TEDIT_NO_MEMBER: c_int = 2;
/// Member-edit pre-failure: a member-type recipe did not build.
pub const IDAKIT_TEDIT_BUILD: c_int = 3;
/// `member_bit` value that appends a new member at the end rather than a fixed offset.
pub const IDAKIT_MEMBER_APPEND: u64 = u64::MAX;

/// Result of a successful type apply.
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
/// Recipe opcode: build a function type. Followed by a `u32` parameter count, a `u8` varargs flag,
/// a `u16` calling convention (0 = default), then that many `u32`-length-prefixed parameter names;
/// pops the parameter types then the return type (return pushed first) and pushes the function.
pub const IDAKIT_RECIPE_FUNCTION: u8 = 10;
/// Recipe opcode: build a bitfield member type, followed by a `u8` container width in bytes, a
/// `u8` field width in bits, and a `u8` signedness flag. Valid only as a struct member; the kernel
/// rejects a bitfield in a union.
pub const IDAKIT_RECIPE_BITFIELD: u8 = 11;
