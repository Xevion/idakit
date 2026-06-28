//! Cross-references: [`Xref`] and its [`XrefKind`] classification. The IDA
//! xref-type byte is in two overlapping spaces (code/data) split here into
//! [`CodeRef`]/[`DataRef`]; unknown bytes degrade to `Unknown`.

use num_enum::FromPrimitive;

use crate::ea::Ea;

/// A cross-reference pointing *to* a queried address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Xref {
    /// Where the reference originates.
    pub from: Ea,
    /// How the reference is classified — code vs data, and its specific type.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XrefKind {
    /// A code reference (call, jump, or ordinary flow).
    Code(CodeRef),
    /// A data reference (read, write, offset, …).
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
        let x = Xref::from_raw(0x1000, ty, iscode).expect("valid source");
        assert!(x.kind == expect);
        assert!(x.is_code() == matches!(expect, XrefKind::Code(_)));
        assert!(x.from.get() == 0x1000);
    }

    #[test]
    fn badaddr_source_is_rejected() {
        assert!(Xref::from_raw(crate::ea::BADADDR, 3, 0).is_none());
    }
}
