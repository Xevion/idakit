//! Byte-level access to the analyzed image, through [`Database`].
//!
//! Raw reads, item classification and linear navigation, and comments over the analyzed
//! image. Accessor-only, like the `raw` and `ffi` layers, so it defines no view type and
//! every entry point hangs off [`Database`].

use idakit_sys as sys;

use crate::Database;
use crate::address::Address;
use crate::ffi::read_string;

impl Database {
    /// Whether the kernel classifies the item at `address` as an instruction.
    ///
    /// This is the gate [`Function::instructions`](crate::function::Function::instructions) walks
    /// by. [`decode`](Self::decode) will happily turn arbitrary bytes into an
    /// [`Instruction`](crate::instruction::Instruction), so only `is_code` separates real
    /// instructions from data (or a function's alignment tail) that merely happens to decode.
    #[must_use]
    #[doc(alias("FF_CODE"))]
    pub fn is_code(&self, address: Address) -> bool {
        (self.get_flags(address) & sys::MS_CLS) == sys::FF_CODE
    }

    /// Whether the kernel classifies the item at `address` as a data definition.
    #[must_use]
    #[doc(alias("FF_DATA"))]
    pub fn is_data(&self, address: Address) -> bool {
        (self.get_flags(address) & sys::MS_CLS) == sys::FF_DATA
    }

    /// Start of the defined item (instruction or data) covering `address`, or `address` itself
    /// when it is already a head or falls in undefined bytes.
    #[must_use]
    #[doc(alias("get_item_head"))]
    pub fn item_head(&self, address: Address) -> Address {
        Address::try_new(self.get_item_head(address)).unwrap_or(address)
    }

    /// One-past-the-last address of the item at `address`.
    ///
    /// This is the next item's head, and the natural step to advance a linear walk. Undefined
    /// bytes advance one at a time.
    #[must_use]
    #[doc(alias("get_item_end"))]
    pub fn item_end(&self, address: Address) -> Address {
        Address::try_new(self.get_item_end(address)).unwrap_or(address)
    }

    /// Next defined item head after `address`, searching up to (but not reaching) `max`, or
    /// `None` when no head lies in that span.
    #[must_use]
    #[doc(alias("get_next_head"))]
    pub fn next_head(&self, address: Address, max: Address) -> Option<Address> {
        Address::try_new(self.get_next_head(address, max))
    }

    /// Previous defined item head before `address`, searching down to `min`, or `None` when no
    /// head lies in that span.
    #[must_use]
    #[doc(alias("get_prev_head"))]
    pub fn prev_head(&self, address: Address, min: Address) -> Option<Address> {
        Address::try_new(self.get_prev_head(address, min))
    }

    /// Read bytes at `address` into `buf`, returning how many were supplied.
    ///
    /// Zero-alloc, so it suits reusing one buffer across hot loops. [`bytes`](Self::bytes) is
    /// the owning shortcut.
    #[doc(alias("get_bytes"))]
    pub fn read_into(&self, address: Address, buf: &mut [u8]) -> usize {
        let got = self.get_bytes(address, buf.as_mut_ptr().cast(), buf.len());
        (got.max(0) as usize).min(buf.len())
    }

    /// Read up to `len` bytes at `address` into a fresh vector (empty on failure).
    #[must_use]
    #[doc(alias("get_bytes"))]
    pub fn bytes(&self, address: Address, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let got = self.read_into(address, &mut buf);
        buf.truncate(got);
        buf
    }

    /// Read the comment at `address`, or `None` when that channel carries none.
    ///
    /// `repeatable` selects the repeatable channel over the regular one. The write half is
    /// [`LocationMut::set_comment`](crate::LocationMut::set_comment).
    #[must_use]
    #[doc(alias("get_cmt"))]
    pub fn comment(&self, address: Address, repeatable: bool) -> Option<String> {
        read_string(|buf, cap| self.get_cmt(address, repeatable, buf, cap))
    }
}
