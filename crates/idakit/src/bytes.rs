//! Byte-level access to the analyzed image, through [`Database`].
//!
//! Raw reads, item classification and linear navigation, and comments over the analyzed
//! image. Accessors hang off [`Database`]; the one type defined here is [`ByteClass`], the
//! four-way classification of a byte.

use idakit_sys as sys;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::VariantArray;

use crate::Database;
use crate::address::Address;

/// What the kernel classifies one byte as, from the class field of its flags word.
///
/// The four values are mutually exclusive and cover the whole field, so the common predicates
/// ([`Database::is_code`], [`Database::is_data`], [`Database::is_tail`],
/// [`Database::is_unknown`]) are views of this one value. Read from the database through
/// [`Database::byte_class`].
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    TryFromPrimitive,
    IntoPrimitive,
    VariantArray,
)]
#[repr(u64)]
pub enum ByteClass {
    /// Undefined byte (`FF_UNK`).
    #[doc(alias("FF_UNK"))]
    Unknown = 0x000,
    /// Non-head byte of a multi-byte item (`FF_TAIL`).
    #[doc(alias("FF_TAIL"))]
    Tail = 0x200,
    /// Head of a data item (`FF_DATA`).
    #[doc(alias("FF_DATA"))]
    Data = 0x400,
    /// Head of an instruction (`FF_CODE`).
    #[doc(alias("FF_CODE"))]
    Code = 0x600,
}

impl ByteClass {
    /// Extract the class field from a raw `flags_t` word.
    fn from_flags(flags: u64) -> Self {
        match flags & sys::MS_CLS {
            sys::FF_CODE => Self::Code,
            sys::FF_DATA => Self::Data,
            sys::FF_TAIL => Self::Tail,
            _ => Self::Unknown,
        }
    }
}

impl Database {
    /// The kernel's classification of the byte at `address`.
    ///
    /// Unlike [`is_code`](Self::is_code) and [`is_data`](Self::is_data), this tells a tail byte of
    /// a multi-byte item apart from an undefined one.
    #[must_use]
    #[doc(alias("get_flags"))]
    pub fn byte_class(&self, address: Address) -> ByteClass {
        ByteClass::from_flags(self.get_flags(address))
    }

    /// Whether the kernel classifies the item at `address` as an instruction.
    ///
    /// This is the gate [`Function::instructions`](crate::function::Function::instructions) walks
    /// by. [`decode`](Self::decode) will happily turn arbitrary bytes into an
    /// [`Instruction`](crate::instruction::Instruction), so only `is_code` separates real
    /// instructions from data (or a function's alignment tail) that merely happens to decode.
    #[must_use]
    #[doc(alias("FF_CODE"))]
    pub fn is_code(&self, address: Address) -> bool {
        self.byte_class(address) == ByteClass::Code
    }

    /// Whether the kernel classifies the item at `address` as a data definition.
    #[must_use]
    #[doc(alias("FF_DATA"))]
    pub fn is_data(&self, address: Address) -> bool {
        self.byte_class(address) == ByteClass::Data
    }

    /// Whether `address` is a non-head byte of a multi-byte item.
    #[must_use]
    pub fn is_tail(&self, address: Address) -> bool {
        self.byte_class(address) == ByteClass::Tail
    }

    /// Whether the byte at `address` is undefined.
    #[must_use]
    pub fn is_unknown(&self, address: Address) -> bool {
        self.byte_class(address) == ByteClass::Unknown
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
    #[doc(alias("get_bytes"))]
    pub fn read_into(&self, address: Address, buf: &mut [u8]) -> usize {
        let got = self.get_bytes(address, buf.as_mut_ptr().cast(), buf.len());
        (got.max(0) as usize).min(buf.len())
    }

    /// Read up to `len` bytes at `address` into a fresh vector (empty on failure).
    #[must_use]
    #[doc(alias("get_bytes"))]
    pub fn bytes(&self, address: Address, len: usize) -> Vec<u8> {
        self.get_bytes_owned(address, len).unwrap_or_default()
    }

    /// Read the comment at `address`, or `None` when that channel carries none.
    ///
    /// `repeatable` selects the repeatable channel over the regular one. The write half is
    /// [`LocationMut::set_comment`](crate::LocationMut::set_comment).
    #[must_use]
    #[doc(alias("get_cmt"))]
    pub fn comment(&self, address: Address, repeatable: bool) -> Option<String> {
        self.get_cmt(address, repeatable)
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    /// Pin the enum to the facade's SDK values: the facade lists them in discriminant order, so a
    /// header renumbering or a variant added without a facade entry fails here. Pure constant
    /// source, no kernel.
    #[test]
    fn byte_class_ids_align_with_the_facade() {
        let ids = sys::byte_class_ids();
        assert!(
            ids.len() == ByteClass::VARIANTS.len(),
            "facade lists {} ids for {} variants",
            ids.len(),
            ByteClass::VARIANTS.len()
        );
        for (&id, &variant) in ids.iter().zip(ByteClass::VARIANTS) {
            assert!(u64::from(id) == u64::from(variant), "{variant:?}");
        }
    }

    /// Only the class field decides the class; the rest of the wide flags word is ignored.
    #[rstest]
    #[case::code(0x0000_0600, ByteClass::Code)]
    #[case::data(0x0000_0400, ByteClass::Data)]
    #[case::tail(0x0000_0200, ByteClass::Tail)]
    #[case::unknown(0x0000_0000, ByteClass::Unknown)]
    #[case::code_with_other_bits(0xFFFF_F9FF | 0x600, ByteClass::Code)]
    #[case::unknown_with_other_bits(0xFFFF_F9FF, ByteClass::Unknown)]
    fn from_flags_reads_only_the_class_field(#[case] flags: u64, #[case] expect: ByteClass) {
        assert!(ByteClass::from_flags(flags) == expect);
    }
}
