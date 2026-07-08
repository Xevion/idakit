//! Drives the facade's [`TypeVtbl`] into any [`TypeSink`], shared by every consumer that walks
//! IDA types: the ctree walk and the bare type walks (frame, and later members and prototypes).
//!
//! A consumer supplies its `ctx` type's [`TypeBuilder`] via [`TypeSink`]; the generic
//! `extern "C"` shims below decode the FFI arguments and push into it, so each consumer reuses
//! one set of callbacks instead of duplicating ten shims.

use std::ffi::{c_char, c_void};

use idakit_sys::{EnumConstDesc, MemberDesc, TypeVtbl};

use super::{EnumMember, TypeBuilder, TypeId, TypeMember};
use crate::arena::Idx;
use crate::ffi::{lossy, slice};

/// A walk context the shared type callbacks push interned types into. The u32-handle methods
/// are defaults over [`type_builder`](Self::type_builder), so an implementor supplies only the
/// builder; the shims and unit tests call the methods, keeping handle marshalling in one place.
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
    fn fill_enum(
        &mut self,
        id: u32,
        underlying: u32,
        members: Vec<EnumMember>,
        size: u64,
        has_size: u32,
    ) {
        self.type_builder()
            .fill_enum(tid(id), tid(underlying), members, size, has_size);
    }
    fn fill_typedef(&mut self, id: u32, underlying: u32) {
        self.type_builder().fill_typedef(tid(id), tid(underlying));
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

/// Reborrow the opaque walk context as the sink it threads through every callback. Taken by
/// reference so the returned lifetime is tied to its (stack) holder and cannot be `'static`.
///
/// # Safety
/// `*ctx` must be the `*mut T` passed to the walk, unaliased for the call (walks are
/// single-threaded and never re-enter a callback).
// Reborrowing `&mut` from `&` (clippy::mut_from_ref) is intentional: taking `ctx` by reference
// bounds the returned lifetime, and the non-re-entrant walk guarantees it is unaliased.
#[allow(clippy::mut_from_ref)]
pub(crate) unsafe fn reborrow<T>(ctx: &*mut c_void) -> &mut T {
    unsafe { &mut *(*ctx as *mut T) }
}

unsafe extern "C" fn cb_scalar<T: TypeSink>(
    ctx: *mut c_void,
    kind: u32,
    bytes: u32,
    signed: u32,
    size: u64,
    has_size: u32,
) -> u32 {
    unsafe { reborrow::<T>(&ctx) }.scalar(kind, bytes, signed, size, has_size)
}
unsafe extern "C" fn cb_ptr<T: TypeSink>(
    ctx: *mut c_void,
    target: u32,
    size: u64,
    has_size: u32,
) -> u32 {
    unsafe { reborrow::<T>(&ctx) }.ptr(target, size, has_size)
}
unsafe extern "C" fn cb_array<T: TypeSink>(
    ctx: *mut c_void,
    elem: u32,
    nelems: u64,
    size: u64,
    has_size: u32,
) -> u32 {
    unsafe { reborrow::<T>(&ctx) }.array(elem, nelems, size, has_size)
}
unsafe extern "C" fn cb_func<T: TypeSink>(
    ctx: *mut c_void,
    ret: u32,
    params: *const u32,
    n: usize,
    vararg: u32,
) -> u32 {
    let params = unsafe { slice(&params, n) };
    unsafe { reborrow::<T>(&ctx) }.function(ret, params, vararg)
}
unsafe extern "C" fn cb_opaque<T: TypeSink>(
    ctx: *mut c_void,
    name: *const c_char,
    name_len: usize,
) -> u32 {
    let name = unsafe { lossy(name, name_len) }.unwrap_or_default();
    unsafe { reborrow::<T>(&ctx) }.opaque(name)
}
unsafe extern "C" fn cb_named_ref<T: TypeSink>(
    ctx: *mut c_void,
    name: *const c_char,
    name_len: usize,
) -> u32 {
    let name = unsafe { lossy(name, name_len) }.unwrap_or_default();
    unsafe { reborrow::<T>(&ctx) }.named_ref(name)
}
unsafe extern "C" fn cb_anon<T: TypeSink>(ctx: *mut c_void) -> u32 {
    unsafe { reborrow::<T>(&ctx) }.anon()
}
unsafe extern "C" fn cb_fill_struct<T: TypeSink>(
    ctx: *mut c_void,
    id: u32,
    is_union: u32,
    members: *const MemberDesc,
    n: usize,
    size: u64,
    has_size: u32,
) {
    let members = unsafe { slice(&members, n) }
        .iter()
        .map(|m| TypeMember {
            name: unsafe { lossy(m.name, m.name_len) }.unwrap_or_default(),
            bit_offset: m.bit_offset,
            ty: tid(m.ty),
            bitfield_width: (m.bitfield_width != 0).then_some(m.bitfield_width),
        })
        .collect();
    unsafe { reborrow::<T>(&ctx) }.fill_struct(id, is_union != 0, members, size, has_size);
}
unsafe extern "C" fn cb_fill_enum<T: TypeSink>(
    ctx: *mut c_void,
    id: u32,
    underlying: u32,
    consts: *const EnumConstDesc,
    n: usize,
    size: u64,
    has_size: u32,
) {
    let members = unsafe { slice(&consts, n) }
        .iter()
        .map(|c| EnumMember {
            name: unsafe { lossy(c.name, c.name_len) }.unwrap_or_default(),
            value: c.value,
        })
        .collect();
    unsafe { reborrow::<T>(&ctx) }.fill_enum(id, underlying, members, size, has_size);
}
unsafe extern "C" fn cb_fill_typedef<T: TypeSink>(ctx: *mut c_void, id: u32, underlying: u32) {
    unsafe { reborrow::<T>(&ctx) }.fill_typedef(id, underlying);
}

/// The facade type vtbl whose callbacks target a `ctx` of type `T`. `const`, so a consumer can
/// embed it in a `static` vtbl or build one on the stack per walk.
pub(crate) const fn type_vtbl<T: TypeSink>() -> TypeVtbl {
    TypeVtbl {
        t_scalar: cb_scalar::<T>,
        t_ptr: cb_ptr::<T>,
        t_array: cb_array::<T>,
        t_func: cb_func::<T>,
        t_opaque: cb_opaque::<T>,
        t_named_ref: cb_named_ref::<T>,
        t_anon: cb_anon::<T>,
        t_fill_struct: cb_fill_struct::<T>,
        t_fill_enum: cb_fill_enum::<T>,
        t_fill_typedef: cb_fill_typedef::<T>,
    }
}
