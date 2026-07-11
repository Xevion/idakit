//! Name-classification flag bits ([`FF_NAME`], [`FF_LABL`]) and the name write (`set_name`).

use std::ffi::{c_char, c_int};

use crate::Address;

/// `FF_NAME` (`bytes.hpp`): the address has an explicit or auto-generated name. With
/// [`FF_LABL`] it forms IDA's two-bit name classification. The SDK `#undef`s these at the end
/// of the header, so the values are mirrored here and pinned to IDA's own predicates by an
/// alignment test in `idakit`.
pub const FF_NAME: u64 = 1 << 14;
/// `FF_LABL` (`bytes.hpp`): the address has a dummy (address-derived) name. See [`FF_NAME`].
pub const FF_LABL: u64 = 1 << 15;

// name write (plain libida symbol)
unsafe extern "C" {
    pub fn set_name(address: Address, name: *const c_char, flags: c_int) -> bool;
}
