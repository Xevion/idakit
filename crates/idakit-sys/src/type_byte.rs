//! [`TypeByte`], the SDK's packed `type_t`, decoded into its three fields.
//!
//! A `type_t` packs a base type (`TYPE_BASE_MASK`, the low nibble), a two-bit sub-type field
//! (`TYPE_FLAGS_MASK`) whose meaning depends on the base, and the `const`/`volatile` modifiers
//! (`TYPE_MODIF_MASK`). The `BTF_*` spellings are compositions of those fields, not members of one
//! set: `BTF_STRUCT` is `BT_COMPLEX | BTMT_STRUCT`, and `BTF_TYPEDEF | BTM_VOLATILE` is as valid as
//! `BTF_STRUCT`. So the byte decodes into a [`BaseType`], a [`Subtype`] read under that base, and
//! [`Qualifiers`], and every byte decodes: the nibble's sixteen values and each base's four
//! sub-type values are all named by the SDK.

use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::VariantArray;

/// The base-type nibble of a `type_t`.
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Debug, TryFromPrimitive, IntoPrimitive, VariantArray,
)]
#[repr(u8)]
#[doc(alias("TYPE_BASE_MASK"))]
pub enum BaseType {
    /// Unknown, possibly with a size class.
    #[doc(alias("BT_UNK"))]
    Unknown = 0x00,
    /// `void`, possibly with a size class.
    #[doc(alias("BT_VOID"))]
    Void = 0x01,
    /// `__int8`.
    #[doc(alias("BT_INT8"))]
    Int8 = 0x02,
    /// `__int16`.
    #[doc(alias("BT_INT16"))]
    Int16 = 0x03,
    /// `__int32`.
    #[doc(alias("BT_INT32"))]
    Int32 = 0x04,
    /// `__int64`.
    #[doc(alias("BT_INT64"))]
    Int64 = 0x05,
    /// `__int128`.
    #[doc(alias("BT_INT128"))]
    Int128 = 0x06,
    /// The natural `int`, sized by the processor module.
    #[doc(alias("BT_INT"))]
    Int = 0x07,
    /// `bool`.
    #[doc(alias("BT_BOOL"))]
    Bool = 0x08,
    /// A floating-point type.
    #[doc(alias("BT_FLOAT"))]
    Float = 0x09,
    /// A pointer.
    #[doc(alias("BT_PTR"))]
    Pointer = 0x0A,
    /// An array.
    #[doc(alias("BT_ARRAY"))]
    Array = 0x0B,
    /// A function.
    #[doc(alias("BT_FUNC"))]
    Function = 0x0C,
    /// A struct, union, enum, or typedef.
    #[doc(alias("BT_COMPLEX"))]
    Complex = 0x0D,
    /// A bitfield, only inside a struct.
    #[doc(alias("BT_BITFIELD"))]
    Bitfield = 0x0E,
    /// The SDK's reserved base value.
    #[doc(alias("BT_RESERVED"))]
    Reserved = 0x0F,
}

/// Generates one four-valued sub-type enum, its discriminants being the raw `BTMT_*` values.
macro_rules! subtype_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $( $(#[$vmeta:meta])* $variant:ident = $value:literal, )* }
    ) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, PartialEq, Eq, Hash, Debug, TryFromPrimitive, IntoPrimitive, VariantArray,
        )]
        #[repr(u8)]
        pub enum $name {
            $( $(#[$vmeta])* $variant = $value, )*
        }
    };
}

subtype_enum! {
    /// The size class of an [`Unknown`](BaseType::Unknown) or [`Void`](BaseType::Void) base.
    ///
    /// Each value names one size per base: `Size12` is 1 byte under `Void` and 2 under
    /// `Unknown`, for example.
    SizeClass {
        /// A plain `void`; unused under `Unknown`.
        #[doc(alias("BTMT_SIZE0"))]
        Size0 = 0x00,
        /// 1 byte under `Void`, 2 under `Unknown`.
        #[doc(alias("BTMT_SIZE12"))]
        Size12 = 0x10,
        /// 4 bytes under `Void`, 8 under `Unknown`.
        #[doc(alias("BTMT_SIZE48"))]
        Size48 = 0x20,
        /// 16 bytes under `Void`, an unknown size under `Unknown`.
        #[doc(alias("BTMT_SIZE128"))]
        Size128 = 0x30,
    }
}

subtype_enum! {
    /// The signedness of an integer base.
    IntSign {
        /// Signedness unknown.
        #[doc(alias("BTMT_UNKSIGN"))]
        Unknown = 0x00,
        /// Signed.
        #[doc(alias("BTMT_SIGNED"))]
        Signed = 0x10,
        /// Unsigned.
        #[doc(alias("BTMT_USIGNED", "BTMT_UNSIGNED"))]
        Unsigned = 0x20,
        /// `char` under [`Int8`](BaseType::Int8), a segment register under
        /// [`Int`](BaseType::Int); unused under the other integer bases.
        #[doc(alias("BTMT_CHAR"))]
        Char = 0x30,
    }
}

subtype_enum! {
    /// The size of a [`Bool`](BaseType::Bool).
    BoolSize {
        /// Model-specific or unknown.
        #[doc(alias("BTMT_DEFBOOL"))]
        Default = 0x00,
        /// 1 byte.
        #[doc(alias("BTMT_BOOL1"))]
        One = 0x10,
        /// 2 bytes in a 32-bit database, 8 in a 64-bit one.
        #[doc(alias("BTMT_BOOL2", "BTMT_BOOL8"))]
        TwoOrEight = 0x20,
        /// 4 bytes.
        #[doc(alias("BTMT_BOOL4"))]
        Four = 0x30,
    }
}

subtype_enum! {
    /// The kind of a [`Float`](BaseType::Float).
    FloatKind {
        /// `float`, 4 bytes.
        #[doc(alias("BTMT_FLOAT"))]
        Float = 0x00,
        /// `double`, 8 bytes.
        #[doc(alias("BTMT_DOUBLE"))]
        Double = 0x10,
        /// `long double`, compiler-specific.
        #[doc(alias("BTMT_LNGDBL"))]
        LongDouble = 0x20,
        /// A processor-sized float: the processor's `tbyte` size, else 2 bytes.
        #[doc(alias("BTMT_SPECFLT"))]
        Special = 0x30,
    }
}

subtype_enum! {
    /// The kind of a [`Pointer`](BaseType::Pointer).
    PointerKind {
        /// The memory model's default.
        #[doc(alias("BTMT_DEFPTR"))]
        Default = 0x00,
        /// A near pointer.
        #[doc(alias("BTMT_NEAR"))]
        Near = 0x10,
        /// A far pointer.
        #[doc(alias("BTMT_FAR"))]
        Far = 0x20,
        /// A `__closure`, or a pointer with an explicit size.
        #[doc(alias("BTMT_CLOSURE"))]
        Closure = 0x30,
    }
}

subtype_enum! {
    /// How a [`Function`](BaseType::Function) returns.
    CallMethod {
        /// The memory model's default, or unknown.
        #[doc(alias("BTMT_DEFCALL"))]
        Default = 0x00,
        /// Returns by `retn`.
        #[doc(alias("BTMT_NEARCALL"))]
        Near = 0x10,
        /// Returns by `retf`.
        #[doc(alias("BTMT_FARCALL"))]
        Far = 0x20,
        /// Returns by `iret`.
        #[doc(alias("BTMT_INTCALL"))]
        Interrupt = 0x30,
    }
}

subtype_enum! {
    /// The kind of a [`Complex`](BaseType::Complex).
    ComplexKind {
        /// A struct.
        #[doc(alias("BTMT_STRUCT", "BTF_STRUCT"))]
        Struct = 0x00,
        /// A union.
        #[doc(alias("BTMT_UNION", "BTF_UNION"))]
        Union = 0x10,
        /// An enum.
        #[doc(alias("BTMT_ENUM", "BTF_ENUM"))]
        Enum = 0x20,
        /// A named reference to another type.
        #[doc(alias("BTMT_TYPEDEF", "BTF_TYPEDEF"))]
        Typedef = 0x30,
    }
}

subtype_enum! {
    /// The storage type of a [`Bitfield`](BaseType::Bitfield).
    BitfieldStorage {
        /// `__int8`.
        #[doc(alias("BTMT_BFLDI8"))]
        Int8 = 0x00,
        /// `__int16`.
        #[doc(alias("BTMT_BFLDI16"))]
        Int16 = 0x10,
        /// `__int32`.
        #[doc(alias("BTMT_BFLDI32"))]
        Int32 = 0x20,
        /// `__int64`.
        #[doc(alias("BTMT_BFLDI64"))]
        Int64 = 0x30,
    }
}

bitflags! {
    /// The sub-type field of an [`Array`](BaseType::Array), which holds two flags rather than a
    /// value.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub struct ArrayFlags: u8 {
        /// Based at 0, which is a serialization detail.
        #[doc(alias("BTMT_NONBASED"))]
        const NON_BASED = 0x10;
        /// The SDK's reserved array bit.
        #[doc(alias("BTMT_ARRESERV"))]
        const RESERVED = 0x20;
    }
}

bitflags! {
    /// A type's `const` and `volatile` qualifiers.
    ///
    /// The SDK calls these modifiers and forbids both together.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias("TYPE_MODIF_MASK", "get_modifiers"))]
    pub struct Qualifiers: u8 {
        /// `const`.
        #[doc(alias("BTM_CONST"))]
        const CONST = 0x40;
        /// `volatile`.
        #[doc(alias("BTM_VOLATILE"))]
        const VOLATILE = 0x80;
    }
}

/// The sub-type field of a `type_t`, read under its base type.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[doc(alias("TYPE_FLAGS_MASK"))]
pub enum Subtype {
    /// Under [`Unknown`](BaseType::Unknown) or [`Void`](BaseType::Void).
    Size(SizeClass),
    /// Under any integer base.
    Integer(IntSign),
    /// Under [`Bool`](BaseType::Bool).
    Bool(BoolSize),
    /// Under [`Float`](BaseType::Float).
    Float(FloatKind),
    /// Under [`Pointer`](BaseType::Pointer).
    Pointer(PointerKind),
    /// Under [`Array`](BaseType::Array).
    Array(ArrayFlags),
    /// Under [`Function`](BaseType::Function).
    Function(CallMethod),
    /// Under [`Complex`](BaseType::Complex).
    Complex(ComplexKind),
    /// Under [`Bitfield`](BaseType::Bitfield).
    Bitfield(BitfieldStorage),
    /// Under [`Reserved`](BaseType::Reserved), the raw field.
    Reserved(u8),
}

/// The mask of a `type_t`'s base-type nibble.
pub const TYPE_BASE_MASK: u8 = 0x0F;
/// The mask of a `type_t`'s sub-type field.
pub const TYPE_FLAGS_MASK: u8 = 0x30;
/// The mask of a `type_t`'s qualifiers.
pub const TYPE_MODIF_MASK: u8 = 0xC0;

/// A `type_t`, the SDK's packed type byte.
///
/// Holds any byte. [`base`](Self::base), [`subtype`](Self::subtype), and
/// [`qualifiers`](Self::qualifiers) decode its three fields, and [`new`](Self::new) composes
/// one from fields that agree.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
#[doc(alias("type_t"))]
pub struct TypeByte(pub u8);

impl TypeByte {
    /// The byte for `base` with sub-type `subtype` and `qualifiers`, or `None` when `subtype`
    /// belongs to a different base (an [`IntSign`] under [`Bool`](BaseType::Bool), say).
    #[must_use]
    pub const fn new(base: BaseType, subtype: Subtype, qualifiers: Qualifiers) -> Option<Self> {
        let field = match (base, subtype) {
            (BaseType::Unknown | BaseType::Void, Subtype::Size(s)) => s as u8,
            (
                BaseType::Int8
                | BaseType::Int16
                | BaseType::Int32
                | BaseType::Int64
                | BaseType::Int128
                | BaseType::Int,
                Subtype::Integer(s),
            ) => s as u8,
            (BaseType::Bool, Subtype::Bool(s)) => s as u8,
            (BaseType::Float, Subtype::Float(s)) => s as u8,
            (BaseType::Pointer, Subtype::Pointer(s)) => s as u8,
            (BaseType::Array, Subtype::Array(s)) => s.bits(),
            (BaseType::Function, Subtype::Function(s)) => s as u8,
            (BaseType::Complex, Subtype::Complex(s)) => s as u8,
            (BaseType::Bitfield, Subtype::Bitfield(s)) => s as u8,
            (BaseType::Reserved, Subtype::Reserved(raw)) if raw & !TYPE_FLAGS_MASK == 0 => raw,
            _ => return None,
        };
        Some(Self(base as u8 | field | qualifiers.bits()))
    }

    /// The unqualified byte for a struct, union, enum, or typedef reference.
    #[must_use]
    pub const fn complex(kind: ComplexKind) -> Self {
        Self(BaseType::Complex as u8 | kind as u8)
    }

    /// The base-type nibble.
    #[must_use]
    pub fn base(self) -> BaseType {
        match BaseType::try_from(self.0 & TYPE_BASE_MASK) {
            Ok(base) => base,
            Err(_) => unreachable!("the nibble's sixteen values are all base types"),
        }
    }

    /// The sub-type field, read under [`base`](Self::base).
    #[must_use]
    pub fn subtype(self) -> Subtype {
        let field = self.0 & TYPE_FLAGS_MASK;
        // Each enum names all four values of the two-bit field, so every conversion succeeds.
        macro_rules! decode {
            ($ty:ident) => {
                match $ty::try_from(field) {
                    Ok(v) => v,
                    Err(_) => unreachable!("the field's four values are all named"),
                }
            };
        }
        match self.base() {
            BaseType::Unknown | BaseType::Void => Subtype::Size(decode!(SizeClass)),
            BaseType::Int8
            | BaseType::Int16
            | BaseType::Int32
            | BaseType::Int64
            | BaseType::Int128
            | BaseType::Int => Subtype::Integer(decode!(IntSign)),
            BaseType::Bool => Subtype::Bool(decode!(BoolSize)),
            BaseType::Float => Subtype::Float(decode!(FloatKind)),
            BaseType::Pointer => Subtype::Pointer(decode!(PointerKind)),
            BaseType::Array => Subtype::Array(ArrayFlags::from_bits_retain(field)),
            BaseType::Function => Subtype::Function(decode!(CallMethod)),
            BaseType::Complex => Subtype::Complex(decode!(ComplexKind)),
            BaseType::Bitfield => Subtype::Bitfield(decode!(BitfieldStorage)),
            BaseType::Reserved => Subtype::Reserved(field),
        }
    }

    /// The `const`/`volatile` qualifiers.
    #[must_use]
    pub const fn qualifiers(self) -> Qualifiers {
        Qualifiers::from_bits_retain(self.0 & TYPE_MODIF_MASK)
    }
}

impl From<u8> for TypeByte {
    fn from(raw: u8) -> Self {
        Self(raw)
    }
}

impl From<TypeByte> for u8 {
    fn from(byte: TypeByte) -> Self {
        byte.0
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use proptest::prelude::*;

    use super::*;

    /// The SDK's `BTF_*` shortcuts decode to their parts.
    #[test]
    fn shortcuts_decode_to_their_parts() {
        let typedef_volatile = TypeByte(0x3D | 0x80);
        assert!(typedef_volatile.base() == BaseType::Complex);
        assert!(typedef_volatile.subtype() == Subtype::Complex(ComplexKind::Typedef));
        assert!(typedef_volatile.qualifiers() == Qualifiers::VOLATILE);

        let uchar = TypeByte(0x22);
        assert!(uchar.subtype() == Subtype::Integer(IntSign::Unsigned));
        assert!(TypeByte(0x19).subtype() == Subtype::Float(FloatKind::Double));
        assert!(TypeByte::complex(ComplexKind::Enum) == TypeByte(0x2D));
    }

    #[test]
    fn new_rejects_a_subtype_from_another_base() {
        let sign = Subtype::Integer(IntSign::Signed);
        assert!(TypeByte::new(BaseType::Bool, sign, Qualifiers::empty()).is_none());
        assert!(TypeByte::new(BaseType::Int32, sign, Qualifiers::CONST) == Some(TypeByte(0x54)));
        let reserved = Subtype::Reserved(0x01);
        assert!(TypeByte::new(BaseType::Reserved, reserved, Qualifiers::empty()).is_none());
    }

    proptest! {
        /// Every byte decodes, and composing its decoded fields gives the byte back.
        #[test]
        fn every_byte_round_trips_through_its_fields(raw: u8) {
            let byte = TypeByte(raw);
            prop_assert_eq!(
                TypeByte::new(byte.base(), byte.subtype(), byte.qualifiers()),
                Some(byte)
            );
        }
    }
}
