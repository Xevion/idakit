//! Write path against a real database: comments, byte patching, and every type-write surgery
//! path, split by domain across `write/`. Each test closes with `save = false`, so the `.i64`
//! on disk is never touched.

mod common;

#[path = "write/location.rs"]
mod location;
#[path = "write/type_apply.rs"]
mod type_apply;
#[path = "write/type_enum.rs"]
mod type_enum;
#[path = "write/type_function.rs"]
mod type_function;
#[path = "write/type_member.rs"]
mod type_member;
