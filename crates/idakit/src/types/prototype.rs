//! A function prototype's [`Parameter`]s and the facts decoded from its `FTI_*` word.
//!
//! `func_type_data_t::flags` packs independent flags beside a two-bit call-type field, so the
//! flags cross as [`FunctionTypeFlags`] with that field masked out, and [`CallType`] reads the
//! field on its own. A parameter's `FAI_*` word crosses whole as [`ParameterFlags`].

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use strum::VariantArray;

pub use idakit_sys::{FunctionTypeFlags, ParameterFlags};

use super::{StorageLocation, TypeId};

/// One parameter of a function prototype.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[doc(alias("funcarg_t"))]
pub struct Parameter {
    /// The parameter's name, or `None` when unnamed.
    pub name: Option<String>,
    /// The parameter's type.
    pub ty: TypeId,
    /// The parameter's comment, if any.
    #[doc(alias("cmt"))]
    pub comment: Option<String>,
    /// Where the parameter is passed, or [`Unallocated`](StorageLocation::Unallocated) when the
    /// prototype's locations were not computed.
    #[doc(alias("argloc"))]
    pub location: StorageLocation,
    /// The raw `FAI_*` word.
    #[serde(with = "super::attributes::parameter_bits")]
    pub flags: ParameterFlags,
}

impl Parameter {
    /// Whether the compiler, not the source, introduced this parameter.
    ///
    /// A return-value pointer counts even without the hidden bit, since the SDK defines it as
    /// implying hidden.
    #[inline]
    #[must_use]
    pub const fn is_hidden(&self) -> bool {
        self.flags
            .intersects(ParameterFlags::HIDDEN.union(ParameterFlags::RETURN_POINTER))
    }
}

/// How a function is called, the two-bit `FTI_CALLTYPE` field of a prototype's flags.
// raw FTI_*CALL values from typeinf.hpp (IDA 9.3)
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Default,
    Serialize,
    Deserialize,
    TryFromPrimitive,
    IntoPrimitive,
    VariantArray,
)]
#[repr(u32)]
#[doc(alias("FTI_CALLTYPE", "get_call_method"))]
pub enum CallType {
    /// The default call.
    #[default]
    #[doc(alias("FTI_DEFCALL"))]
    Default = 0x0000,
    /// A near call.
    #[doc(alias("FTI_NEARCALL"))]
    Near = 0x0040,
    /// A far call.
    #[doc(alias("FTI_FARCALL"))]
    Far = 0x0080,
    /// An interrupt call.
    #[doc(alias("FTI_INTCALL"))]
    Interrupt = 0x00C0,
}

impl CallType {
    /// The call type packed in a raw `FTI_*` word. Total, since the field's two bits name all four.
    pub(crate) fn from_flags(raw: u32) -> Self {
        match Self::try_from(raw & idakit_sys::CALL_TYPE_MASK) {
            Ok(call_type) => call_type,
            Err(_) => unreachable!("the field's two bits name all four call types"),
        }
    }
}

/// One register a prototype declares spoiled, and how many bytes of it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[doc(alias("reg_info_t"))]
pub struct SpoiledRegister {
    /// Register number.
    #[doc(alias("reg"))]
    pub register: u32,
    /// Size in bytes of the spoiled part.
    pub size: u32,
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use idakit_sys as sys;
    use rstest::rstest;

    use super::*;
    use crate::arena::Idx;

    #[rstest]
    #[case::function(sys::function_type_flag_ids(), FunctionTypeFlags::all().iter().map(|f| f.bits()).collect())]
    #[case::parameter(sys::parameter_flag_ids(), ParameterFlags::all().iter().map(|f| f.bits()).collect())]
    fn flag_ids_align_with_the_facade(#[case] facade: Vec<u32>, #[case] ours: Vec<u32>) {
        assert!(facade == ours);
    }

    #[test]
    fn call_type_ids_align_with_the_facade() {
        let ids = sys::call_type_ids();
        assert!(ids.len() == CallType::VARIANTS.len());
        for (&id, &v) in ids.iter().zip(CallType::VARIANTS) {
            assert!(id == u32::from(v));
        }
    }

    /// The call-type field reads independently of every flag bit around it.
    #[rstest]
    #[case::default(0x0101, CallType::Default)]
    #[case::near(0x0140, CallType::Near)]
    #[case::far(0x1F80, CallType::Far)]
    #[case::interrupt(0x00C0, CallType::Interrupt)]
    fn call_type_reads_the_two_bit_field(#[case] raw: u32, #[case] expected: CallType) {
        assert!(CallType::from_flags(raw) == expected);
    }

    #[test]
    fn the_call_type_field_is_not_a_flag() {
        assert!(FunctionTypeFlags::all().bits() & sys::CALL_TYPE_MASK == 0);
    }

    /// A return pointer is hidden with or without the hidden bit.
    #[rstest]
    #[case::plain(ParameterFlags::empty(), false)]
    #[case::hidden(ParameterFlags::HIDDEN, true)]
    #[case::return_pointer_alone(ParameterFlags::RETURN_POINTER | ParameterFlags::STRUCT, true)]
    #[case::unused(ParameterFlags::UNUSED, false)]
    fn is_hidden_counts_a_return_pointer(#[case] flags: ParameterFlags, #[case] hidden: bool) {
        let param = Parameter {
            name: None,
            ty: Idx::from_raw(0),
            comment: None,
            location: StorageLocation::Unallocated,
            flags,
        };
        assert!(param.is_hidden() == hidden);
    }
}
