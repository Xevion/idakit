//! The facade alignment tests for `idakit-sys`'s [`TypeByte`] model of the SDK's `type_t`.
//!
//! The model lives in `idakit-sys` beside the raw byte it decodes; the tests live here because
//! they call into the facade, which `idakit-sys`'s own unit tests do not link.

#[cfg(test)]
mod tests {
    use assert2::assert;
    use idakit_sys::{
        ArrayFlags, BaseType, BitfieldStorage, BoolSize, CallMethod, ComplexKind, FloatKind,
        IntSign, PointerKind, Qualifiers, SizeClass, TYPE_BASE_MASK, TYPE_FLAGS_MASK,
        TYPE_MODIF_MASK,
    };
    use strum::VariantArray;

    fn ids<T: Copy + Into<u8>>(variants: &[T]) -> Vec<u32> {
        variants.iter().map(|&v| u32::from(v.into())).collect()
    }

    #[test]
    fn base_type_ids_align_with_the_facade() {
        assert!(idakit_sys::base_type_ids() == ids(BaseType::VARIANTS));
    }

    /// Each sub-type enum, in `Subtype`'s variant order, against the facade's `BTMT_*` list.
    #[test]
    fn subtype_ids_align_with_the_facade() {
        let mut ours = Vec::new();
        ours.extend(ids(SizeClass::VARIANTS));
        ours.extend(ids(IntSign::VARIANTS));
        ours.extend(ids(BoolSize::VARIANTS));
        ours.extend(ids(FloatKind::VARIANTS));
        ours.extend(ids(PointerKind::VARIANTS));
        ours.extend(ArrayFlags::all().iter().map(|f| u32::from(f.bits())));
        ours.extend(ids(CallMethod::VARIANTS));
        ours.extend(ids(ComplexKind::VARIANTS));
        ours.extend(ids(BitfieldStorage::VARIANTS));
        assert!(idakit_sys::type_subtype_ids() == ours);
    }

    #[test]
    fn modifier_ids_align_with_the_facade() {
        let mut ours: Vec<u32> = Qualifiers::all()
            .iter()
            .map(|f| u32::from(f.bits()))
            .collect();
        ours.extend([TYPE_BASE_MASK, TYPE_FLAGS_MASK, TYPE_MODIF_MASK].map(u32::from));
        assert!(idakit_sys::type_modifier_ids() == ours);
    }
}
