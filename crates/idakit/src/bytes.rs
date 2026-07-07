//! Byte-level access to the analyzed image, through [`Database`].
//!
//! Mirrors the SDK's `bytes.hpp`: raw reads, item classification and linear navigation, and
//! comments. Accessor-only, like the `raw` and `ffi` layers, so it defines no view type and
//! every entry point hangs off [`Database`].

use idakit_sys as sys;

use crate::Database;
use crate::address::Address;
use crate::error::{Error, Result};
use crate::ffi::{read_string, with_cstr};

impl Database {
    /// Whether the kernel classifies the item at `address` as an instruction.
    ///
    /// This is the gate [`Function::instructions`](crate::function::Function::instructions) walks
    /// by. [`decode`](Self::decode) will happily turn arbitrary bytes into an
    /// [`Instruction`](crate::instruction::Instruction), so only `is_code` separates real
    /// instructions from data (or a function's alignment tail) that merely happens to decode.
    #[must_use]
    pub fn is_code(&self, address: Address) -> bool {
        (self.get_flags(address) & sys::MS_CLS) == sys::FF_CODE
    }

    /// Whether the kernel classifies the item at `address` as a data definition.
    #[must_use]
    pub fn is_data(&self, address: Address) -> bool {
        (self.get_flags(address) & sys::MS_CLS) == sys::FF_DATA
    }

    /// Start of the defined item (instruction or data) covering `address`, or `address` itself
    /// when it is already a head or falls in undefined bytes.
    #[must_use]
    pub fn item_head(&self, address: Address) -> Address {
        Address::try_new(self.get_item_head(address)).unwrap_or(address)
    }

    /// One-past-the-last address of the item at `address`.
    ///
    /// This is the next item's head, and the natural step to advance a linear walk. Undefined
    /// bytes advance one at a time.
    #[must_use]
    pub fn item_end(&self, address: Address) -> Address {
        Address::try_new(self.get_item_end(address)).unwrap_or(address)
    }

    /// Next defined item head after `address`, searching up to (but not reaching) `max`, or
    /// `None` when no head lies in that span.
    #[must_use]
    pub fn next_head(&self, address: Address, max: Address) -> Option<Address> {
        Address::try_new(self.get_next_head(address, max))
    }

    /// Previous defined item head before `address`, searching down to `min`, or `None` when no
    /// head lies in that span.
    #[must_use]
    pub fn prev_head(&self, address: Address, min: Address) -> Option<Address> {
        Address::try_new(self.get_prev_head(address, min))
    }

    /// Read bytes at `address` into `buf`, returning how many were supplied.
    ///
    /// Zero-alloc, so it suits reusing one buffer across hot loops. [`bytes`](Self::bytes) is
    /// the owning shortcut.
    pub fn read_into(&self, address: Address, buf: &mut [u8]) -> usize {
        let got = self.get_bytes(address, buf.as_mut_ptr().cast(), buf.len());
        (got.max(0) as usize).min(buf.len())
    }

    /// Patch `bytes` over the image at `address`, saving the originals.
    ///
    /// IDA can recover the saved originals, and a later save writes the patch into the `.i64`.
    /// The write is all-or-nothing, so a bad address leaves the database untouched.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if any target byte is unmapped.
    pub fn patch(&mut self, address: Address, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let ok = self.patch_bytes(address, bytes.as_ptr().cast(), bytes.len());
        if ok != 0 {
            return Ok(());
        }
        // patch_bytes has no kernel error channel; the facade rejects an unmapped range, so
        // there is usually no qerrno -- fall back to naming the actual failure.
        let (qerrno, reason) = self.last_reason();
        Err(Error::WriteRejected {
            op: "patch",
            address: address.get(),
            qerrno,
            reason: reason.or_else(|| Some("target range is not fully mapped".to_owned())),
        })
    }

    /// Read up to `len` bytes at `address` into a fresh vector (empty on failure).
    #[must_use]
    pub fn bytes(&self, address: Address, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let got = self.read_into(address, &mut buf);
        buf.truncate(got);
        buf
    }

    /// Read the comment at `address`, or `None` when that channel carries none.
    ///
    /// `repeatable` selects the repeatable channel over the regular one. The write half is
    /// [`set_comment`](Self::set_comment).
    #[must_use]
    pub fn comment(&self, address: Address, repeatable: bool) -> Option<String> {
        read_string(|buf, cap| self.get_cmt(address, repeatable, buf, cap))
    }

    /// Set the comment at `address`.
    ///
    /// `repeatable` repeats it at every reference.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the write.
    pub fn set_comment(&mut self, address: Address, text: &str, repeatable: bool) -> Result<()> {
        let ok = with_cstr(text, "comment", |p| self.set_cmt(address, p, repeatable))?;
        if ok {
            Ok(())
        } else {
            let (qerrno, reason) = self.last_reason();
            Err(Error::WriteRejected {
                op: "set_comment",
                address: address.get(),
                qerrno,
                reason,
            })
        }
    }
}
