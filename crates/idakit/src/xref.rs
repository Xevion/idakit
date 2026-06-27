//! Cross-references: [`Xref`] and its [`XrefKind`] classification. The IDA
//! xref-type byte is in two overlapping spaces (code/data) split here into
//! [`CodeRef`]/[`DataRef`]; unknown bytes degrade to `Unknown`.

use num_enum::FromPrimitive;

use crate::ea::Ea;

/// A cross-reference pointing *to* a queried address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Xref {
    /// Where the reference originates.
    pub from: Ea,
    pub kind: XrefKind,
}

impl Xref {
    /// Build from the facade's `(from, type, iscode)` triple.
    #[inline]
    #[must_use]
    pub(crate) fn from_raw(from: u64, ty: u8, iscode: u8) -> Option<Self> {
        let from = Ea::try_new(from)?;
        let kind = if iscode != 0 {
            XrefKind::Code(CodeRef::from_primitive(ty))
        } else {
            XrefKind::Data(DataRef::from_primitive(ty))
        };
        Some(Self { from, kind })
    }

    /// Whether this is a code reference rather than a data one.
    #[inline]
    #[must_use]
    pub const fn is_code(&self) -> bool {
        matches!(self.kind, XrefKind::Code(_))
    }
}

/// A reference classified into the code or data type space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XrefKind {
    Code(CodeRef),
    Data(DataRef),
}

/// Code cross-reference type, mirroring IDA's `cref_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromPrimitive)]
#[repr(u8)]
pub enum CodeRef {
    CallFar = 16,
    CallNear = 17,
    JumpFar = 18,
    JumpNear = 19,
    Flow = 21,
    #[num_enum(default)]
    Unknown = 0,
}

/// Data cross-reference type, mirroring IDA's `dref_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromPrimitive)]
#[repr(u8)]
pub enum DataRef {
    Offset = 1,
    Write = 2,
    Read = 3,
    Text = 4,
    Informational = 5,
    #[num_enum(default)]
    Unknown = 0,
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn code_byte_classifies_as_call() {
        let x = Xref::from_raw(0x1000, 17, 1).unwrap();
        assert!(x.kind == XrefKind::Code(CodeRef::CallNear));
        assert!(x.is_code());
        assert!(x.from.get() == 0x1000);
    }

    #[test]
    fn data_byte_classifies_as_read() {
        let x = Xref::from_raw(0x2000, 3, 0).unwrap();
        assert!(x.kind == XrefKind::Data(DataRef::Read));
        assert!(!x.is_code());
    }

    #[test]
    fn unknown_byte_degrades_per_space() {
        assert!(Xref::from_raw(0x1, 99, 1).unwrap().kind == XrefKind::Code(CodeRef::Unknown));
        assert!(Xref::from_raw(0x1, 99, 0).unwrap().kind == XrefKind::Data(DataRef::Unknown));
    }

    #[test]
    fn badaddr_source_is_rejected() {
        assert!(Xref::from_raw(crate::ea::BADADDR, 3, 0).is_none());
    }
}
