//! Cross-references: [`Xref`] and its [`XrefKind`] classification. The IDA
//! xref-type byte is in two overlapping spaces (code/data) split here into
//! [`CodeRef`]/[`DataRef`]; unknown bytes degrade to `Unknown`.

use std::ffi::c_void;
use std::marker::PhantomData;

use idakit_sys as sys;
use num_enum::FromPrimitive;

use crate::Idb;
use crate::ea::Ea;

impl Idb {
    /// Lazily iterate every cross-reference targeting `ea` -- its callers and the data
    /// that points at it (ordinary sequential flow excluded).
    #[inline]
    #[must_use]
    pub fn xrefs_to(&self, ea: Ea) -> Xrefs<'_> {
        Xrefs::new(self.xref_open(ea, true))
    }

    /// Lazily iterate every cross-reference originating at `ea` -- what the code there
    /// calls, jumps to, or reads (ordinary sequential flow excluded).
    #[inline]
    #[must_use]
    pub fn xrefs_from(&self, ea: Ea) -> Xrefs<'_> {
        Xrefs::new(self.xref_open(ea, false))
    }
}

/// A cross-reference edge, carrying both endpoints. For [`xrefs_to`](Idb::xrefs_to) the
/// `to` end is the queried address; for [`xrefs_from`](Idb::xrefs_from) the `from` end is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Xref {
    /// The referencing (source) address.
    pub from: Ea,
    /// The referenced (target) address.
    pub to: Ea,
    /// How the reference is classified -- code vs data, and its specific type.
    pub kind: XrefKind,
}

impl Xref {
    /// Build from the facade's `(from, to, type, iscode)` tuple. `None` if either
    /// endpoint is `BADADDR`.
    #[inline]
    #[must_use]
    pub(crate) fn from_raw(from: u64, to: u64, ty: u8, iscode: u8) -> Option<Self> {
        let from = Ea::try_new(from)?;
        let to = Ea::try_new(to)?;
        let kind = if iscode != 0 {
            XrefKind::Code(CodeRef::from_primitive(ty))
        } else {
            XrefKind::Data(DataRef::from_primitive(ty))
        };
        Some(Self { from, to, kind })
    }

    /// Whether this is a code reference rather than a data one.
    #[inline]
    #[must_use]
    pub const fn is_code(&self) -> bool {
        matches!(self.kind, XrefKind::Code(_))
    }
}

/// Lazy iterator over cross-references; closes the cursor on drop. Borrows `&Idb`, so it
/// can't outlive the database or coexist with a write.
pub struct Xrefs<'db> {
    cursor: *mut c_void,
    _db: PhantomData<&'db Idb>,
}

impl Xrefs<'_> {
    #[inline]
    pub(crate) fn new(cursor: *mut c_void) -> Self {
        Self {
            cursor,
            _db: PhantomData,
        }
    }
}

impl Iterator for Xrefs<'_> {
    type Item = Xref;

    fn next(&mut self) -> Option<Xref> {
        loop {
            let (mut from, mut to, mut ty, mut iscode) = (0u64, 0u64, 0u8, 0u8);
            // SAFETY: `cursor` came from `idakit_xref_open` and is live until our `Drop`;
            // the out-pointers are valid for this call.
            let ok = unsafe {
                sys::idakit_xref_next(self.cursor, &mut from, &mut to, &mut ty, &mut iscode)
            };
            if ok == 0 {
                return None;
            }
            // A `BADADDR` endpoint is not a usable edge; skip it and keep stepping.
            if let Some(xref) = Xref::from_raw(from, to, ty, iscode) {
                return Some(xref);
            }
        }
    }
}

impl Drop for Xrefs<'_> {
    fn drop(&mut self) {
        // SAFETY: `cursor` came from `idakit_xref_open` and is closed exactly once here.
        unsafe { sys::idakit_xref_close(self.cursor) };
    }
}

/// A reference classified into the code or data type space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XrefKind {
    /// A code reference (call, jump, or ordinary flow).
    Code(CodeRef),
    /// A data reference (read, write, offset, ...).
    Data(DataRef),
}

/// Code cross-reference type, mirroring IDA's `cref_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, FromPrimitive)]
#[repr(u8)]
pub enum CodeRef {
    /// A far call.
    CallFar = 16,
    /// A near call.
    CallNear = 17,
    /// A far jump.
    JumpFar = 18,
    /// A near jump.
    JumpNear = 19,
    /// Ordinary sequential flow into the next instruction.
    Flow = 21,
    /// An unrecognized code-xref type byte.
    #[num_enum(default)]
    Unknown = 0,
}

/// Data cross-reference type, mirroring IDA's `dref_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, FromPrimitive)]
#[repr(u8)]
pub enum DataRef {
    /// An offset (address-of) reference.
    Offset = 1,
    /// A write access.
    Write = 2,
    /// A read access.
    Read = 3,
    /// A textual reference.
    Text = 4,
    /// An informational reference.
    Informational = 5,
    /// An unrecognized data-xref type byte.
    #[num_enum(default)]
    Unknown = 0,
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    /// The `(type, iscode)` byte pair classifies into the right space and variant, and an
    /// unrecognized byte degrades to that space's `Unknown` rather than crossing over.
    #[rstest]
    #[case::call_near(17, 1, XrefKind::Code(CodeRef::CallNear))]
    #[case::jump_near(19, 1, XrefKind::Code(CodeRef::JumpNear))]
    #[case::flow(21, 1, XrefKind::Code(CodeRef::Flow))]
    #[case::data_write(2, 0, XrefKind::Data(DataRef::Write))]
    #[case::data_read(3, 0, XrefKind::Data(DataRef::Read))]
    #[case::unknown_in_code_space(99, 1, XrefKind::Code(CodeRef::Unknown))]
    #[case::unknown_in_data_space(99, 0, XrefKind::Data(DataRef::Unknown))]
    fn classifies_by_type_byte(#[case] ty: u8, #[case] iscode: u8, #[case] expect: XrefKind) {
        let x = Xref::from_raw(0x1000, 0x2000, ty, iscode).expect("valid edge");
        assert!(x.kind == expect);
        assert!(x.is_code() == matches!(expect, XrefKind::Code(_)));
        assert!(x.from.get() == 0x1000);
        assert!(x.to.get() == 0x2000);
    }

    /// A `BADADDR` at either endpoint is not a usable edge.
    #[test]
    fn badaddr_endpoint_is_rejected() {
        let bad = crate::ea::BADADDR;
        assert!(Xref::from_raw(bad, 0x2000, 3, 0).is_none());
        assert!(Xref::from_raw(0x1000, bad, 3, 0).is_none());
    }
}
