//! Bridges the `cxx` type walk's [`TypeWalkSink`] to the idiomatic [`TypeSink`], shared by every
//! consumer that walks IDA types: the ctree walk and the bare type walks (frame, named types,
//! prototypes).
//!
//! A consumer supplies its `ctx` type's [`TypeBuilder`] via [`TypeSink`]; [`SinkAdapter`] wraps it
//! as the sys-side [`TypeWalkSink`] the `cxx` visitor drives, marshalling each borrowed span into
//! the owned form [`TypeSink`] takes, so each consumer implements only [`TypeSink`].

use idakit_sys::{EnumConstInfo, MemberInfo, TypeWalkSink};

use super::{EnumMember, NumberFormat, TypeBuilder, TypeId, TypeMember, ValueRepr};
use crate::arena::Idx;

/// A walk context the shared type callbacks push interned types into. The u32-handle methods
/// are defaults over [`type_builder`](Self::type_builder), so an implementor supplies only the
/// builder; [`SinkAdapter`] and unit tests call the methods, keeping handle marshalling in one
/// place.
pub(crate) trait TypeSink {
    /// The builder this sink accumulates types in.
    fn type_builder(&mut self) -> &mut TypeBuilder;

    fn scalar(&mut self, kind: u32, bytes: u32, signed: u32, size: u64, has_size: u32) -> u32 {
        raw(self
            .type_builder()
            .scalar(kind, bytes, signed, size, has_size))
    }
    fn ptr(&mut self, target: u32, size: u64, has_size: u32) -> u32 {
        raw(self.type_builder().ptr(tid(target), size, has_size))
    }
    fn array(&mut self, elem: u32, nelems: u64, size: u64, has_size: u32) -> u32 {
        raw(self.type_builder().array(tid(elem), nelems, size, has_size))
    }
    fn function(&mut self, ret: u32, params: &[u32], vararg: u32) -> u32 {
        let params = params.iter().map(|&p| tid(p)).collect();
        raw(self.type_builder().function(tid(ret), params, vararg))
    }
    fn opaque(&mut self, name: String) -> u32 {
        raw(self.type_builder().opaque(name))
    }
    fn named_ref(&mut self, name: String) -> u32 {
        raw(self.type_builder().named_ref(name))
    }
    fn anon(&mut self) -> u32 {
        raw(self.type_builder().anon())
    }
    fn fill_struct(
        &mut self,
        id: u32,
        is_union: bool,
        members: Vec<TypeMember>,
        size: u64,
        has_size: u32,
    ) {
        self.type_builder()
            .fill_struct(tid(id), is_union, members, size, has_size);
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the facade's flat fill_enum callback"
    )]
    fn fill_enum(
        &mut self,
        id: u32,
        underlying: u32,
        members: Vec<EnumMember>,
        size: u64,
        has_size: u32,
        is_bitmask: bool,
        repr_vtype: u32,
        repr_signed: bool,
        repr_leading_zeros: bool,
    ) {
        self.type_builder().fill_enum(
            tid(id),
            tid(underlying),
            members,
            size,
            has_size,
            is_bitmask,
            repr_vtype,
            repr_signed,
            repr_leading_zeros,
        );
    }
    fn fill_typedef(&mut self, id: u32, underlying: u32) {
        self.type_builder().fill_typedef(tid(id), tid(underlying));
    }
}

/// Adapts any [`TypeSink`] to the `cxx` type walk's [`TypeWalkSink`], so a consumer implements
/// only the idiomatic [`TypeSink`] and the `cxx` [`walk_type_named`](idakit_sys::walk_type_named)
/// drivers drive it. A newtype (not a blanket impl) because the orphan rule forbids implementing
/// the foreign [`TypeWalkSink`] for an arbitrary `T: TypeSink`. It owns the borrow for the one
/// walk, marshalling each borrowed span into the owned form [`TypeSink`] takes.
pub(crate) struct SinkAdapter<'a, T: TypeSink>(pub &'a mut T);

impl<T: TypeSink> TypeWalkSink for SinkAdapter<'_, T> {
    fn scalar(&mut self, kind: u32, bytes: u32, signed: u32, size: u64, has_size: u32) -> u32 {
        self.0.scalar(kind, bytes, signed, size, has_size)
    }
    fn ptr(&mut self, target: u32, size: u64, has_size: u32) -> u32 {
        self.0.ptr(target, size, has_size)
    }
    fn array(&mut self, elem: u32, nelems: u64, size: u64, has_size: u32) -> u32 {
        self.0.array(elem, nelems, size, has_size)
    }
    fn func(&mut self, ret: u32, params: &[u32], vararg: u32) -> u32 {
        self.0.function(ret, params, vararg)
    }
    fn opaque(&mut self, name: String) -> u32 {
        self.0.opaque(name)
    }
    fn named_ref(&mut self, name: String) -> u32 {
        self.0.named_ref(name)
    }
    fn anon(&mut self) -> u32 {
        self.0.anon()
    }
    fn fill_struct(
        &mut self,
        id: u32,
        is_union: bool,
        members: &[MemberInfo],
        size: u64,
        has_size: u32,
    ) {
        let members = members
            .iter()
            .map(|m| TypeMember {
                name: m.name.clone(),
                bit_offset: m.bit_offset,
                ty: tid(m.ty),
                bitfield_width: (m.bitfield_width != 0).then_some(m.bitfield_width),
                repr: NumberFormat::try_from(m.repr_vtype)
                    .ok()
                    .map(|format| ValueRepr {
                        format,
                        signed: m.repr_signed,
                        leading_zeros: m.repr_leading_zeros,
                    }),
            })
            .collect();
        self.0.fill_struct(id, is_union, members, size, has_size);
    }
    fn fill_enum(
        &mut self,
        id: u32,
        underlying: u32,
        consts: &[EnumConstInfo],
        size: u64,
        has_size: u32,
        is_bitmask: bool,
        repr_vtype: u32,
        repr_signed: bool,
        repr_leading_zeros: bool,
    ) {
        let members = consts
            .iter()
            .map(|c| EnumMember {
                name: c.name.clone(),
                value: c.value,
            })
            .collect();
        self.0.fill_enum(
            id,
            underlying,
            members,
            size,
            has_size,
            is_bitmask,
            repr_vtype,
            repr_signed,
            repr_leading_zeros,
        );
    }
    fn fill_typedef(&mut self, id: u32, underlying: u32) {
        self.0.fill_typedef(id, underlying);
    }
}

/// A [`TypeId`] from its raw FFI handle.
pub(crate) fn tid(raw: u32) -> TypeId {
    Idx::from_raw(raw)
}

/// The raw FFI handle for an arena index.
pub(crate) fn raw<X>(id: Idx<X>) -> u32 {
    id.index() as u32
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    struct TestSink(TypeBuilder);

    impl TypeSink for TestSink {
        fn type_builder(&mut self) -> &mut TypeBuilder {
            &mut self.0
        }
    }

    /// `anon` hands out a fresh placeholder handle on every call, both directly and through the
    /// adapter: a constant return would collide two anonymous types onto one handle.
    #[test]
    fn anon_handles_are_distinct() {
        let mut sink = TestSink(TypeBuilder::new());
        let a = sink.anon();
        let b = sink.anon();
        assert!(a != b, "TypeSink::anon reused a handle: {a} == {b}");

        let mut adapter = SinkAdapter(&mut sink);
        let c = TypeWalkSink::anon(&mut adapter);
        let d = TypeWalkSink::anon(&mut adapter);
        assert!(c != d, "SinkAdapter::anon reused a handle: {c} == {d}");
        assert!(
            [a, b].iter().all(|&x| x != c && x != d),
            "adapter handles collided with direct ones"
        );
    }
}
