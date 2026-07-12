//! `cxx` `extern "Rust"` opaque-visitor bridge for the tinfo type walk (`idakit_cxx::typewalk_*`).
//!
//! The production type walk drives an [`extern "Rust"`] **opaque visitor** ([`TypeWalkVisitor`])
//! whose `&mut self` methods `cxx` exposes to C++ as callable member functions. The C++ driver in
//! `facade/typewalk_cxx.cc` (`visit_walker_t`) walks a `tinfo_t` and calls `visitor.scalar(...)`,
//! `visitor.named_ref(...)`, `visitor.fill_struct(...)` per node. There is no function-pointer
//! table, no `void*` context, no offset-indexed struct: the visitor forwards each call straight
//! into a [`TypeWalkSink`] the consumer supplies, so `idakit` interns nodes into its own type table
//! without a C-ABI shim layer.
//!
//! Per-call data crosses zero-copy, borrowed only for the duration of that one call:
//!
//! - names as `&str` (`rust::Str`), copied out by the sink only if it keeps them;
//! - child-handle arrays as `&[u32]` (`rust::Slice<const u32>`);
//! - struct members / enum constants as `&[MemberInfo]` / `&[EnumConstInfo]`
//!   (`rust::Slice<const T>`), where [`MemberInfo`]/[`EnumConstInfo`] are **lifetime-generic
//!   shared structs** carrying a borrowed `name: &str` field, the borrowed-name-in-array case with
//!   no owned-`String` copy forced across the boundary.
//!
//! The recursion-safe placeholder + `defined`-set dedup stays C++-side in `visit_walker_t`.
//!
//! # Panic safety
//!
//! A `cxx` `extern "Rust"` function (including an opaque type's methods) that panics is caught at
//! the boundary: `cxx` logs and calls `std::process::abort`, so a panic never unwinds into C++.
//! The visitor methods here are panic-free in the normal path regardless; this is the contract if
//! one ever did.
use std::ptr::NonNull;

/// A walk target the type visitor drives inline, one method per tinfo node kind.
///
/// The consumer (`idakit`) implements it over its own interned type table, and
/// [`TypeWalkVisitor`] forwards every C++ call straight into it. Handle-returning methods mint
/// and return the walk-local id the parent will reference (children are visited before parents);
/// the `fill_*` methods complete a placeholder minted earlier by
/// [`named_ref`](Self::named_ref)/[`anon`](Self::anon). Names and slices are borrowed for the one
/// call only.
pub trait TypeWalkSink {
    /// A scalar leaf (`kind`: 0 unknown, 1 void, 2 bool, 3 integral, 4 float); returns its handle.
    fn scalar(&mut self, kind: u32, bytes: u32, signed: u32, size: u64, has_size: u32) -> u32;
    /// A pointer to the already-visited `target`; returns its handle.
    fn ptr(&mut self, target: u32, size: u64, has_size: u32) -> u32;
    /// An array of `nelems` of the already-visited `elem`; returns its handle.
    fn array(&mut self, elem: u32, nelems: u64, size: u64, has_size: u32) -> u32;
    /// A function of the already-visited `ret` and `params`; returns its handle.
    fn func(&mut self, ret: u32, params: &[u32], vararg: u32) -> u32;
    /// A named-but-bodyless / unresolved leaf carrying its resolved `name`; returns its handle.
    fn opaque(&mut self, name: &str) -> u32;
    /// A by-name placeholder for a named aggregate/typedef; returns its handle.
    fn named_ref(&mut self, name: &str) -> u32;
    /// An anonymous-aggregate placeholder; returns its handle.
    fn anon(&mut self) -> u32;
    /// Fills the struct/union placeholder `id` with its `members`.
    fn fill_struct(
        &mut self,
        id: u32,
        is_union: bool,
        members: &[ffi::MemberInfo],
        size: u64,
        has_size: u32,
    );
    /// Fills the enum placeholder `id` with its `consts` over the already-visited `underlying`.
    fn fill_enum(
        &mut self,
        id: u32,
        underlying: u32,
        consts: &[ffi::EnumConstInfo],
        size: u64,
        has_size: u32,
        is_bitmask: bool,
    );
    /// Fills the typedef placeholder `id` with its already-visited `underlying`.
    fn fill_typedef(&mut self, id: u32, underlying: u32);
}

/// The `cxx` `extern "Rust"` opaque the C++ type walk drives by calling its `&mut self` methods,
/// each forwarding into the [`TypeWalkSink`] it was built over.
///
/// `cxx` generates a C++ class with a member function per method below; `facade/typewalk_cxx.cc`
/// receives a `TypeWalkVisitor&` and calls them. The visitor holds the sink as a lifetime-erased
/// raw pointer: the [`walk_type_named`]/[`walk_type_ordinal`]/[`walk_func_type`] drivers are its
/// only constructors, and each keeps the borrowed sink alive across the one synchronous walk, so
/// the pointer is always valid and unaliased when a method reborrows it.
pub struct TypeWalkVisitor {
    sink: NonNull<dyn TypeWalkSink>,
}

impl TypeWalkVisitor {
    /// Wrap a sink for one walk. The visitor must not outlive `sink`; the drivers below enforce
    /// this by keeping `sink` borrowed for the whole `ffi` call and never letting the visitor
    /// escape.
    fn new(sink: &mut dyn TypeWalkSink) -> Self {
        // Erase the sink's lifetime into the visitor. Sound because the visitor is confined to the
        // driver call that borrows `sink`; the raw pointer never escapes it, so it cannot be used
        // after `sink` ends. The transmute changes only the lifetime of an otherwise identical fat
        // pointer.
        let sink: NonNull<dyn TypeWalkSink> = unsafe { std::mem::transmute(NonNull::from(sink)) };
        Self { sink }
    }

    /// Reborrow the erased sink for one callback.
    ///
    /// # Safety
    /// See the type docs: the pointer is valid and unaliased for the walk (single-threaded,
    /// non-reentrant, the walk holds the only borrow).
    fn sink(&mut self) -> &mut dyn TypeWalkSink {
        unsafe { self.sink.as_mut() }
    }

    fn scalar(&mut self, kind: u32, bytes: u32, is_signed: u32, size: u64, has_size: u32) -> u32 {
        self.sink().scalar(kind, bytes, is_signed, size, has_size)
    }
    fn ptr(&mut self, target: u32, size: u64, has_size: u32) -> u32 {
        self.sink().ptr(target, size, has_size)
    }
    fn array(&mut self, elem: u32, nelems: u64, size: u64, has_size: u32) -> u32 {
        self.sink().array(elem, nelems, size, has_size)
    }
    fn func(&mut self, ret: u32, params: &[u32], vararg: u32) -> u32 {
        self.sink().func(ret, params, vararg)
    }
    fn opaque(&mut self, name: &str) -> u32 {
        self.sink().opaque(name)
    }
    fn named_ref(&mut self, name: &str) -> u32 {
        self.sink().named_ref(name)
    }
    fn anon(&mut self) -> u32 {
        self.sink().anon()
    }
    fn fill_struct(
        &mut self,
        id: u32,
        is_union: bool,
        members: &[ffi::MemberInfo],
        size: u64,
        has_size: u32,
    ) {
        self.sink()
            .fill_struct(id, is_union, members, size, has_size);
    }
    fn fill_enum(
        &mut self,
        id: u32,
        underlying: u32,
        consts: &[ffi::EnumConstInfo],
        size: u64,
        has_size: u32,
        is_bitmask: bool,
    ) {
        self.sink()
            .fill_enum(id, underlying, consts, size, has_size, is_bitmask);
    }
    fn fill_typedef(&mut self, id: u32, underlying: u32) {
        self.sink().fill_typedef(id, underlying);
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
        /// `value_repr_t` FRB_* value-type nibble, or 0 (`FRB_UNK`) when unset or outside the
        /// numeric subset idakit models (an info-carrying, float, or segment representation).
        repr_vtype: u32,
        /// `FRB_SIGNED`; meaningless when `repr_vtype` is 0.
        repr_signed: bool,
        /// `FRB_LZERO`; meaningless when `repr_vtype` is 0.
        repr_leading_zeros: bool,
    }

    /// One enum constant, a lifetime-generic shared struct with a borrowed `name`, the enum twin
    /// of [`MemberInfo`].
    struct EnumConstInfo<'a> {
        /// The constant's name, borrowed for the call.
        name: &'a str,
        /// The constant's value.
        value: u64,
    }

    /// One stack-frame variable, an **owned** shared struct returned in a [`FrameWalk`].
    ///
    /// Unlike [`MemberInfo`], the frame walk returns its variables as a batch after the walk, so
    /// each `name` is copied into an owned `String` rather than borrowed for a call.
    struct FrameVar {
        /// The variable's name.
        name: String,
        /// Frame-pointer-relative byte offset.
        offset: i64,
        /// Size in bytes.
        size: u64,
        /// Reserved-slot flags (return address / saved registers); 0 for an ordinary variable.
        flags: u32,
        /// Walk-local handle of the variable's type, or `IDAKIT_NONE` for a reserved/untyped slot.
        ty: u32,
    }

    /// A walked stack frame: its total byte size and its variables, returned by
    /// [`frame_type_walk_visit`].
    struct FrameWalk {
        /// Total frame size in bytes.
        size: u64,
        /// The frame's variables, in frame order.
        vars: Vec<FrameVar>,
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
            is_bitmask: bool,
        );
        fn fill_typedef(self: &mut TypeWalkVisitor, id: u32, underlying: u32);
    }

    unsafe extern "C++" {
        include!("typewalk_cxx.h");

        /// Walk the local type named `name`, driving `visitor`'s methods per node; returns the
        /// root handle. `Err` when no such type exists (or a thrown SDK error).
        fn type_walk_visit_named(name: &str, visitor: &mut TypeWalkVisitor) -> Result<u32>;

        /// Walk the local type at `ordinal`, driving `visitor`'s methods per node; returns the
        /// root handle. `Err` when no type occupies the ordinal (or a thrown SDK error).
        fn type_walk_visit_ordinal(ordinal: u32, visitor: &mut TypeWalkVisitor) -> Result<u32>;

        /// Walk the stored prototype of the function at `ea`, driving `visitor`; returns the root
        /// handle. `Err` when the function has no type info.
        fn func_type_walk_visit(ea: u64, visitor: &mut TypeWalkVisitor) -> Result<u32>;

        /// Walk the stack frame of the function at `ea`: each variable's type through `visitor`,
        /// returning the frame size and variables. `Err` when there is no function or frame at
        /// `ea`.
        fn frame_type_walk_visit(ea: u64, visitor: &mut TypeWalkVisitor) -> Result<FrameWalk>;
    }
}

pub use ffi::{EnumConstInfo, FrameVar, FrameWalk, MemberInfo};

/// Walk the local type named `name` into `sink` via the `cxx` opaque visitor; returns the root
/// handle, or `None` when no such type exists (or a name was not valid UTF-8, surfaced as a thrown
/// `Err`).
pub fn walk_type_named(name: &str, sink: &mut dyn TypeWalkSink) -> Option<u32> {
    ffi::type_walk_visit_named(name, &mut TypeWalkVisitor::new(sink)).ok()
}

/// Walk the local type at `ordinal` into `sink`; the ordinal twin of [`walk_type_named`].
pub fn walk_type_ordinal(ordinal: u32, sink: &mut dyn TypeWalkSink) -> Option<u32> {
    ffi::type_walk_visit_ordinal(ordinal, &mut TypeWalkVisitor::new(sink)).ok()
}

/// Walk the prototype of the function at `ea` into `sink`; the function-address twin of
/// [`walk_type_named`]. `None` when the function has no type info.
pub fn walk_func_type(ea: u64, sink: &mut dyn TypeWalkSink) -> Option<u32> {
    ffi::func_type_walk_visit(ea, &mut TypeWalkVisitor::new(sink)).ok()
}

/// Walk the stack frame of the function at `ea`, interning each variable's type into `sink` and
/// returning the frame size and variables. `None` when there is no function or frame at `ea`. The
/// returned [`FrameVar::ty`] handles index the table `sink` built.
pub fn walk_frame_type(ea: u64, sink: &mut dyn TypeWalkSink) -> Option<FrameWalk> {
    ffi::frame_type_walk_visit(ea, &mut TypeWalkVisitor::new(sink)).ok()
}

/// Wrap a raw sink pointer as a [`TypeWalkVisitor`] for a walk driven outside this crate.
///
/// The self-contained `walk_*` drivers cover the standalone walks; this exists for the ctree walk,
/// where the visitor is handed to [`cfunc_walk_ctree`](crate::cfunc_walk_ctree) alongside a
/// [`CtreeVisitor`](crate::CtreeVisitor) that shares the same builder. Passing `sink` as a raw
/// pointer (not `&mut`) lets the caller derive both from one provenance, so per-callback reborrows
/// never conflict.
///
/// # Safety
/// `sink` must be non-null and point to a live [`TypeWalkSink`] that outlives every use of the
/// returned visitor, and stay unaliased for the duration of each callback (the walk is
/// single-threaded and non-reentrant).
#[must_use]
pub unsafe fn type_walk_visitor(sink: *mut dyn TypeWalkSink) -> TypeWalkVisitor {
    TypeWalkVisitor {
        sink: NonNull::new(sink).expect("sink pointer must be non-null"),
    }
}
