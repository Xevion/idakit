//! Cross-references: [`Reference`] and its [`ReferenceKind`] classification. The IDA
//! reference-type byte is in two overlapping spaces (code/data) split here into
//! [`CodeReference`]/[`DataReference`]; unknown bytes degrade to `Unknown`.

use std::ffi::c_void;
use std::marker::PhantomData;

use idakit_sys as sys;
use num_enum::FromPrimitive;

use crate::Idb;
use crate::address::Address;

impl Idb {
    /// Lazily iterate every cross-reference targeting `address` -- its callers and the data
    /// that points at it (ordinary sequential flow excluded).
    #[inline]
    #[must_use]
    pub fn references_to(&self, address: Address) -> References<'_> {
        References::new(self.xref_open(address, true))
    }

    /// Lazily iterate every cross-reference originating at `address` -- what the code there
    /// calls, jumps to, or reads (ordinary sequential flow excluded).
    #[inline]
    #[must_use]
    pub fn references_from(&self, address: Address) -> References<'_> {
        References::new(self.xref_open(address, false))
    }
}

/// A cross-reference edge, carrying both endpoints. For [`references_to`](Idb::references_to) the
/// `to` end is the queried address; for [`references_from`](Idb::references_from) the `from` end is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Reference {
    /// The referencing (source) address.
    pub from: Address,
    /// The referenced (target) address.
    pub to: Address,
    /// How the reference is classified -- code vs data, and its specific type.
    pub kind: ReferenceKind,
}

impl Reference {
    /// Build from the facade's `(from, to, type, iscode)` tuple. `None` if either
    /// endpoint is `BADADDR`.
    #[inline]
    #[must_use]
    pub(crate) fn from_raw(from: u64, to: u64, ty: u8, iscode: u8) -> Option<Self> {
        let from = Address::try_new(from)?;
        let to = Address::try_new(to)?;
        let kind = if iscode != 0 {
            ReferenceKind::Code(CodeReference::from_primitive(ty))
        } else {
            ReferenceKind::Data(DataReference::from_primitive(ty))
        };
        Some(Self { from, to, kind })
    }

    /// Whether this is a code reference rather than a data one.
    #[inline]
    #[must_use]
    pub const fn is_code(&self) -> bool {
        matches!(self.kind, ReferenceKind::Code(_))
    }
}

/// Lazy iterator over cross-references; closes the cursor on drop. Borrows `&Idb`, so it
/// can't outlive the database or coexist with a write.
pub struct References<'db> {
    cursor: *mut c_void,
    _db: PhantomData<&'db Idb>,
}

impl References<'_> {
    #[inline]
    pub(crate) fn new(cursor: *mut c_void) -> Self {
        Self {
            cursor,
            _db: PhantomData,
        }
    }
}

impl Iterator for References<'_> {
    type Item = Reference;

    fn next(&mut self) -> Option<Reference> {
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
            if let Some(reference) = Reference::from_raw(from, to, ty, iscode) {
                return Some(reference);
            }
        }
    }
}

impl Drop for References<'_> {
    fn drop(&mut self) {
        // SAFETY: `cursor` came from `idakit_xref_open` and is closed exactly once here.
        unsafe { sys::idakit_xref_close(self.cursor) };
    }
}

/// A reference classified into the code or data type space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReferenceKind {
    /// A code reference (call, jump, or ordinary flow).
    Code(CodeReference),
    /// A data reference (read, write, offset, ...).
    Data(DataReference),
}

/// Code cross-reference type, mirroring IDA's `cref_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, FromPrimitive)]
#[repr(u8)]
pub enum CodeReference {
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
    /// An unrecognized code-reference type byte.
    #[num_enum(default)]
    Unknown = 0,
}

/// Data cross-reference type, mirroring IDA's `dref_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, FromPrimitive)]
#[repr(u8)]
pub enum DataReference {
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
    /// An unrecognized data-reference type byte.
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
    #[case::call_near(17, 1, ReferenceKind::Code(CodeReference::CallNear))]
    #[case::jump_near(19, 1, ReferenceKind::Code(CodeReference::JumpNear))]
    #[case::flow(21, 1, ReferenceKind::Code(CodeReference::Flow))]
    #[case::data_write(2, 0, ReferenceKind::Data(DataReference::Write))]
    #[case::data_read(3, 0, ReferenceKind::Data(DataReference::Read))]
    #[case::unknown_in_code_space(99, 1, ReferenceKind::Code(CodeReference::Unknown))]
    #[case::unknown_in_data_space(99, 0, ReferenceKind::Data(DataReference::Unknown))]
    fn classifies_by_type_byte(#[case] ty: u8, #[case] iscode: u8, #[case] expect: ReferenceKind) {
        let x = Reference::from_raw(0x1000, 0x2000, ty, iscode).expect("valid edge");
        assert!(x.kind == expect);
        assert!(x.is_code() == matches!(expect, ReferenceKind::Code(_)));
        assert!(x.from.get() == 0x1000);
        assert!(x.to.get() == 0x2000);
    }

    /// A `BADADDR` at either endpoint is not a usable edge.
    #[test]
    fn badaddr_endpoint_is_rejected() {
        let bad = crate::address::BADADDR;
        assert!(Reference::from_raw(bad, 0x2000, 3, 0).is_none());
        assert!(Reference::from_raw(0x1000, bad, 3, 0).is_none());
    }
}
