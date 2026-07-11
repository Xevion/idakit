//! `cxx` `extern "Rust"` opaque-visitor bridge for the tinfo type walk (`idakit_cxx::typewalk_*`).
//!
//! The raw type walk hands C++ a `#[repr(C)]` [`TypeVtbl`](crate::TypeVtbl): ten
//! `unsafe extern "C" fn(*mut c_void, ...) -> u32` pointers plus a `void* ctx`, kept in lockstep
//! with the facade header by hand. This bridge actuates the `cxx`-native replacement: an
//! [`extern "Rust"`] **opaque visitor** ([`TypeWalkVisitor`]) whose `&mut self` methods `cxx`
//! exposes to C++ as callable member functions. The C++ driver in `facade/typewalk_cxx.cc`
//! (`visit_walker_t`) walks a `tinfo_t` and calls `visitor.scalar(...)`, `visitor.named_ref(...)`,
//! `visitor.fill_struct(...)` in place of the vtbl slots. No function-pointer table, no `void*`
//! context, no offset-indexed struct.
//!
//! Per-call data crosses zero-copy, borrowed only for the duration of that one call:
//!
//! - names as `&str` (`rust::Str`), copied out into an owned [`String`] by the method body;
//! - child-handle arrays as `&[u32]` (`rust::Slice<const u32>`);
//! - struct members / enum constants as `&[MemberInfo]` / `&[EnumConstInfo]`
//!   (`rust::Slice<const T>`), where [`MemberInfo`]/[`EnumConstInfo`] are **lifetime-generic
//!   shared structs** carrying a borrowed `name: &str` field. That is the borrowed-name-in-array
//!   case zero-copy, no owned-`String` copy forced across the boundary.
//!
//! The recursion-safe placeholder + `defined`-set dedup stays C++-side in `visit_walker_t`, a
//! faithful mirror of the raw facade's `type_walker_t`. This coexists with the raw
//! `idakit_type_walk*` path rather than replacing it.
//!
//! # Cross-check
//!
//! Both paths record the same linear [`VisitEvent`] stream. [`typewalk_visit_ordinal`] drives the
//! new `cxx` visitor; [`typewalk_record_ordinal`] drives the *existing* production
//! [`idakit_type_walk_ordinal`](crate::idakit_type_walk_ordinal) with a hand-written recording
//! `TypeVtbl` (the old pattern). Because `visit_walker_t` mirrors `type_walker_t`, the two streams
//! are identical for a given type, which the roundtrip test asserts.
//!
//! # Panic safety
//!
//! A `cxx` `extern "Rust"` function (including an opaque type's methods) that panics is caught at
//! the boundary: `cxx` logs and calls `std::process::abort`, so a panic never unwinds into C++.
//! The visitor methods here are panic-free in the normal path regardless; this is the contract if
//! one ever did.

// TODO: graduate this visitor to production -- retire the coexisting raw `idakit_type_walk*` +
// TypeVtbl path once every consumer (type sink, frame, ctree) is flipped onto the cxx visitor.
use std::ffi::{c_char, c_void};

use crate::hexrays::{EnumConstDesc, MemberDesc, TypeVtbl};

/// One node the type walk emitted, recorded in visit order.
///
/// Both the `cxx` visitor and the recording `TypeVtbl` push this, so a walk is captured as a
/// plain, comparable stream. Handles (`id`, `target`, `elem`, `ret`, member `ty`) are the
/// walk-local indices each path allocates monotonically in call order; identical call orders
/// yield identical handles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VisitEvent {
    /// A scalar leaf (`kind`: 0 unknown, 1 void, 2 bool, 3 integral, 4 float).
    Scalar {
        /// Handle allocated for this node.
        id: u32,
        /// Scalar category discriminant.
        kind: u32,
        /// Width in bytes (0 when sizeless).
        bytes: u32,
        /// Nonzero when a signed integral.
        signed: u32,
        /// Size in bytes when known.
        size: u64,
        /// Nonzero when `size` is meaningful.
        has_size: u32,
    },
    /// A pointer to `target`.
    Ptr {
        /// Handle allocated for this node.
        id: u32,
        /// Handle of the pointed-to type.
        target: u32,
        /// Size in bytes when known.
        size: u64,
        /// Nonzero when `size` is meaningful.
        has_size: u32,
    },
    /// An array of `nelems` `elem`.
    Array {
        /// Handle allocated for this node.
        id: u32,
        /// Handle of the element type.
        elem: u32,
        /// Element count.
        nelems: u64,
        /// Size in bytes when known.
        size: u64,
        /// Nonzero when `size` is meaningful.
        has_size: u32,
    },
    /// A function type.
    Func {
        /// Handle allocated for this node.
        id: u32,
        /// Handle of the return type.
        ret: u32,
        /// Handles of the parameter types.
        params: Vec<u32>,
        /// Nonzero when variadic.
        vararg: u32,
    },
    /// A named-but-bodyless / unresolved leaf carrying its resolved name.
    Opaque {
        /// Handle allocated for this node.
        id: u32,
        /// The type's resolved name.
        name: String,
    },
    /// A by-name placeholder reference to a named aggregate/typedef.
    NamedRef {
        /// Handle allocated for this node.
        id: u32,
        /// The referenced type's name.
        name: String,
    },
    /// An anonymous-aggregate placeholder.
    Anon {
        /// Handle allocated for this node.
        id: u32,
    },
    /// Fills a struct/union placeholder `id` with its members.
    FillStruct {
        /// Placeholder handle being filled.
        id: u32,
        /// True for a union.
        is_union: bool,
        /// The members, in declaration order.
        members: Vec<MemberEvent>,
        /// Size in bytes when known.
        size: u64,
        /// Nonzero when `size` is meaningful.
        has_size: u32,
    },
    /// Fills an enum placeholder `id` with its constants.
    FillEnum {
        /// Placeholder handle being filled.
        id: u32,
        /// Handle of the underlying integer type.
        underlying: u32,
        /// The enum constants.
        consts: Vec<EnumConstEvent>,
        /// Size in bytes when known.
        size: u64,
        /// Nonzero when `size` is meaningful.
        has_size: u32,
    },
    /// Fills a typedef placeholder `id` with its underlying type.
    FillTypedef {
        /// Placeholder handle being filled.
        id: u32,
        /// Handle of the aliased type.
        underlying: u32,
    },
}

/// One struct/union member captured in a [`VisitEvent::FillStruct`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberEvent {
    /// The member's name (empty if IDA gave none).
    pub name: String,
    /// Offset from the aggregate start, in bits.
    pub bit_offset: u64,
    /// Handle of the member's type.
    pub ty: u32,
    /// Bit width for a bitfield member (0 for an ordinary field).
    pub bitfield_width: u32,
}

/// One enum constant captured in a [`VisitEvent::FillEnum`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumConstEvent {
    /// The constant's name.
    pub name: String,
    /// The constant's value.
    pub value: u64,
}

/// The shared event accumulator both walk paths push into, so their logic is identical by
/// construction. Handles are allocated monotonically by [`alloc`](Self::alloc) in call order.
#[derive(Default)]
struct EventLog {
    events: Vec<VisitEvent>,
    next: u32,
}

impl EventLog {
    fn alloc(&mut self) -> u32 {
        let id = self.next;
        self.next += 1;
        id
    }

    fn scalar(&mut self, kind: u32, bytes: u32, signed: u32, size: u64, has_size: u32) -> u32 {
        let id = self.alloc();
        self.events.push(VisitEvent::Scalar {
            id,
            kind,
            bytes,
            signed,
            size,
            has_size,
        });
        id
    }

    fn ptr(&mut self, target: u32, size: u64, has_size: u32) -> u32 {
        let id = self.alloc();
        self.events.push(VisitEvent::Ptr {
            id,
            target,
            size,
            has_size,
        });
        id
    }

    fn array(&mut self, elem: u32, nelems: u64, size: u64, has_size: u32) -> u32 {
        let id = self.alloc();
        self.events.push(VisitEvent::Array {
            id,
            elem,
            nelems,
            size,
            has_size,
        });
        id
    }

    fn func(&mut self, ret: u32, params: &[u32], vararg: u32) -> u32 {
        let id = self.alloc();
        self.events.push(VisitEvent::Func {
            id,
            ret,
            params: params.to_vec(),
            vararg,
        });
        id
    }

    fn opaque(&mut self, name: String) -> u32 {
        let id = self.alloc();
        self.events.push(VisitEvent::Opaque { id, name });
        id
    }

    fn named_ref(&mut self, name: String) -> u32 {
        let id = self.alloc();
        self.events.push(VisitEvent::NamedRef { id, name });
        id
    }

    fn anon(&mut self) -> u32 {
        let id = self.alloc();
        self.events.push(VisitEvent::Anon { id });
        id
    }

    fn fill_struct(
        &mut self,
        id: u32,
        is_union: bool,
        members: Vec<MemberEvent>,
        size: u64,
        has_size: u32,
    ) {
        self.events.push(VisitEvent::FillStruct {
            id,
            is_union,
            members,
            size,
            has_size,
        });
    }

    fn fill_enum(
        &mut self,
        id: u32,
        underlying: u32,
        consts: Vec<EnumConstEvent>,
        size: u64,
        has_size: u32,
    ) {
        self.events.push(VisitEvent::FillEnum {
            id,
            underlying,
            consts,
            size,
            has_size,
        });
    }

    fn fill_typedef(&mut self, id: u32, underlying: u32) {
        self.events.push(VisitEvent::FillTypedef { id, underlying });
    }
}

/// A `cxx` `extern "Rust"` opaque type the C++ type walk drives by calling its `&mut self`
/// methods, one per node kind.
///
/// This is the whole point of the round: it replaces the raw [`TypeVtbl`](crate::TypeVtbl)'s
/// function-pointer table plus `void* ctx`. `cxx` generates a C++ class with a member function
/// for each method below; `facade/typewalk_cxx.cc` receives a `TypeWalkVisitor&` and calls them.
/// The recorded [`VisitEvent`] stream is read back after the walk via [`typewalk_visit_ordinal`].
pub struct TypeWalkVisitor {
    log: EventLog,
}

impl TypeWalkVisitor {
    fn scalar(&mut self, kind: u32, bytes: u32, is_signed: u32, size: u64, has_size: u32) -> u32 {
        self.log.scalar(kind, bytes, is_signed, size, has_size)
    }
    fn ptr(&mut self, target: u32, size: u64, has_size: u32) -> u32 {
        self.log.ptr(target, size, has_size)
    }
    fn array(&mut self, elem: u32, nelems: u64, size: u64, has_size: u32) -> u32 {
        self.log.array(elem, nelems, size, has_size)
    }
    fn func(&mut self, ret: u32, params: &[u32], vararg: u32) -> u32 {
        self.log.func(ret, params, vararg)
    }
    fn opaque(&mut self, name: &str) -> u32 {
        self.log.opaque(name.to_owned())
    }
    fn named_ref(&mut self, name: &str) -> u32 {
        self.log.named_ref(name.to_owned())
    }
    fn anon(&mut self) -> u32 {
        self.log.anon()
    }
    fn fill_struct(
        &mut self,
        id: u32,
        is_union: bool,
        members: &[ffi::MemberInfo],
        size: u64,
        has_size: u32,
    ) {
        let members = members
            .iter()
            .map(|m| MemberEvent {
                name: m.name.to_owned(),
                bit_offset: m.bit_offset,
                ty: m.ty,
                bitfield_width: m.bitfield_width,
            })
            .collect();
        self.log.fill_struct(id, is_union, members, size, has_size);
    }
    fn fill_enum(
        &mut self,
        id: u32,
        underlying: u32,
        consts: &[ffi::EnumConstInfo],
        size: u64,
        has_size: u32,
    ) {
        let consts = consts
            .iter()
            .map(|c| EnumConstEvent {
                name: c.name.to_owned(),
                value: c.value,
            })
            .collect();
        self.log.fill_enum(id, underlying, consts, size, has_size);
    }
    fn fill_typedef(&mut self, id: u32, underlying: u32) {
        self.log.fill_typedef(id, underlying);
    }
}

#[cxx::bridge(namespace = "idakit_cxx")]
mod ffi {
    /// One struct/union member, a **lifetime-generic shared struct** whose `name` borrows a C++
    /// stack temporary for the duration of one [`fill_struct`](TypeWalkVisitor) call.
    ///
    /// The `name: &str` compiles to `rust::Str` on the C++ side; passed inside a
    /// `rust::Slice<const MemberInfo>`, it is the borrowed-name-in-array case with no owned-copy.
    struct MemberInfo<'a> {
        /// The member's name, borrowed for the call.
        name: &'a str,
        /// Offset from the aggregate start, in bits.
        bit_offset: u64,
        /// Walk-local handle of the member's type.
        ty: u32,
        /// Bit width for a bitfield member (0 for an ordinary field).
        bitfield_width: u32,
    }

    /// One enum constant, a lifetime-generic shared struct with a borrowed `name`, the enum twin
    /// of [`MemberInfo`].
    struct EnumConstInfo<'a> {
        /// The constant's name, borrowed for the call.
        name: &'a str,
        /// The constant's value.
        value: u64,
    }

    extern "Rust" {
        type TypeWalkVisitor;

        fn scalar(
            self: &mut TypeWalkVisitor,
            kind: u32,
            bytes: u32,
            is_signed: u32,
            size: u64,
            has_size: u32,
        ) -> u32;
        fn ptr(self: &mut TypeWalkVisitor, target: u32, size: u64, has_size: u32) -> u32;
        fn array(
            self: &mut TypeWalkVisitor,
            elem: u32,
            nelems: u64,
            size: u64,
            has_size: u32,
        ) -> u32;
        fn func(self: &mut TypeWalkVisitor, ret: u32, params: &[u32], vararg: u32) -> u32;
        fn opaque(self: &mut TypeWalkVisitor, name: &str) -> u32;
        fn named_ref(self: &mut TypeWalkVisitor, name: &str) -> u32;
        fn anon(self: &mut TypeWalkVisitor) -> u32;
        fn fill_struct(
            self: &mut TypeWalkVisitor,
            id: u32,
            is_union: bool,
            members: &[MemberInfo],
            size: u64,
            has_size: u32,
        );
        fn fill_enum(
            self: &mut TypeWalkVisitor,
            id: u32,
            underlying: u32,
            consts: &[EnumConstInfo],
            size: u64,
            has_size: u32,
        );
        fn fill_typedef(self: &mut TypeWalkVisitor, id: u32, underlying: u32);
    }

    unsafe extern "C++" {
        include!("typewalk_cxx.h");

        /// Walk the local type at `ordinal`, driving `visitor`'s methods per node; returns the
        /// root handle. `Err` when no type occupies the ordinal (or a thrown SDK error).
        fn type_walk_visit_ordinal(ordinal: u32, visitor: &mut TypeWalkVisitor) -> Result<u32>;

        /// Walk the stored prototype of the function at `ea`, driving `visitor`; returns the root
        /// handle. `Err` when the function has no type info.
        fn func_type_walk_visit(ea: u64, visitor: &mut TypeWalkVisitor) -> Result<u32>;
    }
}

/// Walk the local type at `ordinal` via the `cxx` opaque visitor, returning the recorded
/// [`VisitEvent`] stream, or `None` when the ordinal holds no type (or a name was not valid
/// UTF-8, surfaced as a thrown `Err`).
#[must_use]
pub fn typewalk_visit_ordinal(ordinal: u32) -> Option<Vec<VisitEvent>> {
    let mut vis = TypeWalkVisitor {
        log: EventLog::default(),
    };
    match ffi::type_walk_visit_ordinal(ordinal, &mut vis) {
        Ok(_root) => Some(vis.log.events),
        Err(_) => None,
    }
}

/// Walk the prototype of the function at `ea` via the `cxx` opaque visitor; `None` when it has no
/// type info. The function-address twin of [`typewalk_visit_ordinal`].
#[must_use]
pub fn typewalk_visit_func(ea: u64) -> Option<Vec<VisitEvent>> {
    let mut vis = TypeWalkVisitor {
        log: EventLog::default(),
    };
    match ffi::func_type_walk_visit(ea, &mut vis) {
        Ok(_root) => Some(vis.log.events),
        Err(_) => None,
    }
}

/// Walk the local type at `ordinal` via the *existing* raw
/// [`TypeVtbl`](crate::TypeVtbl)-driven path, recording the same [`VisitEvent`] stream through a
/// hand-written recording vtbl. The old-pattern reference the `cxx` visitor is cross-checked
/// against; `None` when the ordinal holds no type.
#[must_use]
pub fn typewalk_record_ordinal(ordinal: u32) -> Option<Vec<VisitEvent>> {
    let mut rec = EventLog::default();
    let vtbl = recording_vtbl();
    let mut root = 0u32;
    // SAFETY: `&vtbl` is a valid vtbl of `extern "C"` shims; the ctx is `&mut rec` for the call's
    // duration; the walk is single-threaded and non-reentrant, so the reborrows never alias.
    let rc = unsafe {
        crate::idakit_type_walk_ordinal(
            ordinal,
            &vtbl,
            (&mut rec as *mut EventLog).cast(),
            &mut root,
        )
    };
    (rc == 0).then_some(rec.events)
}

/// Walk the prototype of the function at `ea` via the raw `TypeVtbl` path, recording the same
/// stream. The function-address twin of [`typewalk_record_ordinal`].
#[must_use]
pub fn typewalk_record_func(ea: u64) -> Option<Vec<VisitEvent>> {
    let mut rec = EventLog::default();
    let vtbl = recording_vtbl();
    let mut root = 0u32;
    // SAFETY: see `typewalk_record_ordinal`; identical contract.
    let rc = unsafe {
        crate::idakit_func_type_walk(ea, &vtbl, (&mut rec as *mut EventLog).cast(), &mut root)
    };
    (rc == 0).then_some(rec.events)
}

/// Reborrow the walk `ctx` as the [`EventLog`] it threads through every callback.
///
/// # Safety
/// `ctx` must be the `*mut EventLog` passed to the walk, unaliased for the call (walks are
/// single-threaded and never re-enter a callback).
unsafe fn log<'a>(ctx: *mut c_void) -> &'a mut EventLog {
    unsafe { &mut *ctx.cast::<EventLog>() }
}

/// Decode a facade name span (`(*const c_char, len)`) into an owned [`String`], lossily, matching
/// the `cxx` visitor's `&str` copy for valid UTF-8.
///
/// # Safety
/// `(ptr, len)` must be a valid readable span or `ptr` null.
unsafe fn name(ptr: *const c_char, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    // SAFETY: caller guarantees `(ptr, len)` is readable for `len` bytes.
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    String::from_utf8_lossy(bytes).into_owned()
}

unsafe extern "C" fn r_scalar(
    ctx: *mut c_void,
    kind: u32,
    bytes: u32,
    signed: u32,
    size: u64,
    has_size: u32,
) -> u32 {
    unsafe { log(ctx) }.scalar(kind, bytes, signed, size, has_size)
}
unsafe extern "C" fn r_ptr(ctx: *mut c_void, target: u32, size: u64, has_size: u32) -> u32 {
    unsafe { log(ctx) }.ptr(target, size, has_size)
}
unsafe extern "C" fn r_array(
    ctx: *mut c_void,
    elem: u32,
    nelems: u64,
    size: u64,
    has_size: u32,
) -> u32 {
    unsafe { log(ctx) }.array(elem, nelems, size, has_size)
}
unsafe extern "C" fn r_func(
    ctx: *mut c_void,
    ret: u32,
    params: *const u32,
    n: usize,
    vararg: u32,
) -> u32 {
    // SAFETY: `(params, n)` is the facade's handle array, valid for this call.
    let params = if params.is_null() || n == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(params, n) }
    };
    unsafe { log(ctx) }.func(ret, params, vararg)
}
unsafe extern "C" fn r_opaque(ctx: *mut c_void, nm: *const c_char, nm_len: usize) -> u32 {
    let s = unsafe { name(nm, nm_len) };
    unsafe { log(ctx) }.opaque(s)
}
unsafe extern "C" fn r_named_ref(ctx: *mut c_void, nm: *const c_char, nm_len: usize) -> u32 {
    let s = unsafe { name(nm, nm_len) };
    unsafe { log(ctx) }.named_ref(s)
}
unsafe extern "C" fn r_anon(ctx: *mut c_void) -> u32 {
    unsafe { log(ctx) }.anon()
}
unsafe extern "C" fn r_fill_struct(
    ctx: *mut c_void,
    id: u32,
    is_union: u32,
    members: *const MemberDesc,
    n: usize,
    size: u64,
    has_size: u32,
) {
    // SAFETY: `(members, n)` is the facade's member array, valid for this call.
    let ms = if members.is_null() || n == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(members, n) }
            .iter()
            .map(|m| MemberEvent {
                name: unsafe { name(m.name, m.name_len) },
                bit_offset: m.bit_offset,
                ty: m.ty,
                bitfield_width: m.bitfield_width,
            })
            .collect()
    };
    unsafe { log(ctx) }.fill_struct(id, is_union != 0, ms, size, has_size);
}
unsafe extern "C" fn r_fill_enum(
    ctx: *mut c_void,
    id: u32,
    underlying: u32,
    consts: *const EnumConstDesc,
    n: usize,
    size: u64,
    has_size: u32,
) {
    // SAFETY: `(consts, n)` is the facade's constant array, valid for this call.
    let cs = if consts.is_null() || n == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(consts, n) }
            .iter()
            .map(|c| EnumConstEvent {
                name: unsafe { name(c.name, c.name_len) },
                value: c.value,
            })
            .collect()
    };
    unsafe { log(ctx) }.fill_enum(id, underlying, cs, size, has_size);
}
unsafe extern "C" fn r_fill_typedef(ctx: *mut c_void, id: u32, underlying: u32) {
    unsafe { log(ctx) }.fill_typedef(id, underlying);
}

/// The hand-written recording [`TypeVtbl`](crate::TypeVtbl): the old function-pointer-table
/// pattern this round is measured against. Its `ctx` is an [`EventLog`].
fn recording_vtbl() -> TypeVtbl {
    TypeVtbl {
        t_scalar: r_scalar,
        t_ptr: r_ptr,
        t_array: r_array,
        t_func: r_func,
        t_opaque: r_opaque,
        t_named_ref: r_named_ref,
        t_anon: r_anon,
        t_fill_struct: r_fill_struct,
        t_fill_enum: r_fill_enum,
        t_fill_typedef: r_fill_typedef,
    }
}
