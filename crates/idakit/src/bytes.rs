//! Byte-level access to the analyzed image, mirroring the SDK's `bytes.hpp`: raw reads,
//! item classification and linear navigation, and comments. Accessor-only, like the `raw`
//! and `ffi` layers -- it defines no view type, so the entry points hang off [`Idb`].

use idakit_sys as sys;

use crate::Idb;
use crate::ea::Ea;
use crate::error::{Error, Result};
use crate::ffi::with_cstr;

impl Idb {
    /// Whether the kernel classifies the item at `ea` as an instruction. This is the gate
    /// [`Func::instructions`](crate::Func::instructions) walks by: [`decode`](Self::decode)
    /// will happily turn arbitrary bytes into an [`Insn`](crate::Insn), so only `is_code`
    /// separates real instructions from data (or a function's alignment tail) that merely
    /// happens to decode.
    #[must_use]
    pub fn is_code(&self, ea: Ea) -> bool {
        (self.get_flags(ea) & sys::MS_CLS) == sys::FF_CODE
    }

    /// Whether the kernel classifies the item at `ea` as a data definition.
    #[must_use]
    pub fn is_data(&self, ea: Ea) -> bool {
        (self.get_flags(ea) & sys::MS_CLS) == sys::FF_DATA
    }

    /// Start of the defined item (instruction or data) covering `ea`; `ea` itself when it is
    /// already a head or falls in undefined bytes.
    #[must_use]
    pub fn item_head(&self, ea: Ea) -> Ea {
        Ea::try_new(self.get_item_head(ea)).unwrap_or(ea)
    }

    /// One-past-the-last address of the item at `ea` -- the next item's head, and the natural
    /// step to advance a linear walk. Undefined bytes advance one at a time.
    #[must_use]
    pub fn item_end(&self, ea: Ea) -> Ea {
        Ea::try_new(self.get_item_end(ea)).unwrap_or(ea)
    }

    /// Next defined item head after `ea`, searching up to (but not reaching) `max`; `None`
    /// when no head lies in that span.
    #[must_use]
    pub fn next_head(&self, ea: Ea, max: Ea) -> Option<Ea> {
        Ea::try_new(self.get_next_head(ea, max))
    }

    /// Previous defined item head before `ea`, searching down to `min`; `None` when no head
    /// lies in that span.
    #[must_use]
    pub fn prev_head(&self, ea: Ea, min: Ea) -> Option<Ea> {
        Ea::try_new(self.get_prev_head(ea, min))
    }

    /// Read bytes at `ea` into `buf`, returning how many were supplied. Zero-alloc;
    /// reuse one buffer on hot loops. [`bytes`](Self::bytes) is the owning shortcut.
    pub fn read_into(&self, ea: Ea, buf: &mut [u8]) -> usize {
        let got = self.get_bytes(ea, buf.as_mut_ptr().cast(), buf.len());
        (got.max(0) as usize).min(buf.len())
    }

    // TODO: patch_bytes (the write half of read_into) and binary/pattern search over the image.

    /// Read up to `len` bytes at `ea` into a fresh vector (empty on failure).
    #[must_use]
    pub fn bytes(&self, ea: Ea, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let got = self.read_into(ea, &mut buf);
        buf.truncate(got);
        buf
    }

    // TODO: read comments back (the read half of set_comment).

    /// Set the comment at `ea`. `repeatable` repeats it at every reference.
    pub fn set_comment(&mut self, ea: Ea, text: &str, repeatable: bool) -> Result<()> {
        let ok = with_cstr(text, "comment", |p| self.set_cmt(ea, p, repeatable))?;
        if ok {
            Ok(())
        } else {
            let (qerrno, reason) = self.last_reason();
            Err(Error::WriteRejected {
                op: "set_comment",
                ea: ea.get(),
                qerrno,
                reason,
            })
        }
    }
}
