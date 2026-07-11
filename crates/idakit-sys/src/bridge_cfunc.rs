//! `cxx` + `moveit` bindings for the decompiler's intrusive-refcounted smart pointer
//! `cfuncptr_t` (`idakit_cxx::cfunc_*`, `test-shims` only).
//!
//! `cfuncptr_t` is the SDK typedef `qrefcnt_t<cfunc_t>`: a bare `cfunc_t*` whose **copy-ctor**
//! increments the pointee's intrusive `cfunc_t::refcnt` and whose **destructor** calls
//! `release()` (decrement, `delete` at zero). It is not `std::shared_ptr`, so `cxx`'s
//! `SharedPtr`/`UniquePtr` cannot model its value semantics, and it is not trivially relocatable,
//! so a `Trivial` [`ExternType`](cxx::ExternType) would corrupt the refcount. This module proves
//! the two paths that do work, and where they meet:
//!
//! - **Goal A** binds `cfuncptr_t` as an `Opaque` [`ExternType`](cxx::ExternType) ([`CfuncPtr`])
//!   owned by [`UniquePtr`](cxx::UniquePtr): [`cfunc_decompile`] hands back a
//!   `UniquePtr<CfuncPtr>` whose `cxx` deleter runs `~cfuncptr_t` (`release()`) on drop.
//! - **Goal B (composition)** layers `moveit`'s construction traits onto that *same* [`CfuncPtr`]
//!   type: [`MakeCppStorage`](moveit::MakeCppStorage) + [`CopyNew`](moveit::CopyNew) make
//!   `UniquePtr<CfuncPtr>` an [`Emplace`](moveit::Emplace) target, so
//!   [`moveit::new::copy`] clones one (C++ copy-ctor, refcount++) into a fresh `UniquePtr` on the
//!   C++ heap. This is the per-instantiation ExternType binding and `moveit`'s traits in one type.
//! - **Goal B (inline)** shows the pure-`moveit` value type [`CfuncVal`]: a `#[repr(C)]` mirror of
//!   `cfuncptr_t` held **inline on the Rust stack** (no heap, no `cxx`), with `CopyNew` on clone
//!   and [`Drop`] running the C++ destructor. It is a distinct Rust type from [`CfuncPtr`]: a
//!   `cxx` `Opaque` type is a ZST held only behind indirection, so it can never be the sized,
//!   stack-stored value `moveit`'s inline emplacement needs. That gap is the precise boundary.
//!
//! The bodies are hand-written in `facade/cfunc_cxx.cc`. Gated behind `test-shims` (it reads
//! `cfunc_t::refcnt` for the refcount probes), like [`bridge_probe`](crate::bridge_probe).

use std::ffi::{c_int, c_void};
use std::marker::PhantomPinned;
use std::mem::MaybeUninit;
use std::pin::Pin;

use cxx::UniquePtr;
use moveit::{CopyNew, Emplace, MakeCppStorage, New};

/// The SDK's `cfuncptr_t` (`qrefcnt_t<cfunc_t>`), an `Opaque` C++ type handled only behind
/// indirection.
///
/// Bound to the real global SDK typedef by the [`cxx::ExternType`] impl below (`Kind = Opaque`,
/// since `cfuncptr_t` has a nontrivial copy-ctor and destructor). The opaque body mirrors
/// `cxx`'s own generated representation, so the type is zero-sized, `!Unpin`, and never held by
/// value in Rust. The moveit impls further down give this same type C++ construction semantics.
#[repr(C)]
pub struct CfuncPtr {
    _private: cxx::private::Opaque,
}

// SAFETY: the type id names the real global SDK typedef cfuncptr_t; Opaque is correct because
// qrefcnt_t<cfunc_t> has a nontrivial copy-ctor + destructor, so it may only cross the bridge
// behind a reference or UniquePtr, never by value.
unsafe impl cxx::ExternType for CfuncPtr {
    type Id = cxx::type_id!("cfuncptr_t");
    type Kind = cxx::kind::Opaque;
}

#[cxx::bridge(namespace = "idakit_cxx")]
mod ffi {
    unsafe extern "C++" {
        include!("cfunc_cxx.h");

        /// The SDK's `cfuncptr_t`, bound by [`super::CfuncPtr`]'s hand-written `ExternType` impl.
        #[namespace = ""]
        #[cxx_name = "cfuncptr_t"]
        type CfuncPtr = super::CfuncPtr;

        /// Decompile the function at `ea` into a heap `cfuncptr_t` owned by a
        /// [`UniquePtr`](cxx::UniquePtr) (one owned ref); `Err` on any decompile failure. The
        /// `UniquePtr`'s `cxx` deleter runs `~cfuncptr_t` (`release()`) on drop.
        fn cfunc_decompile(ea: u64) -> Result<UniquePtr<CfuncPtr>>;

        /// The pointee `cfunc_t`'s intrusive `refcnt` (or `-1` if the `qrefcnt` is null); the
        /// refcount probe.
        fn cfunc_refcnt(cf: &CfuncPtr) -> i32;
    }

    // Force cxx to emit the UniquePtr<CfuncPtr> glue: a hand-written ExternType is not declared by
    // an in-bridge `type X;`, so this empty impl is what triggers its container support (the same
    // deleter glue moveit's Emplace-for-UniquePtr composition builds on).
    impl UniquePtr<CfuncPtr> {}
}

pub use ffi::{cfunc_decompile, cfunc_refcnt};

// Raw C-ABI placement shims backing moveit's traits (facade/cfunc_cxx.cc). They operate on a
// cfuncptr_t laid out at the given pointer -- C++ heap space (the UniquePtr path) or a repr(C)
// Rust mirror (the inline CfuncVal path).
unsafe extern "C" {
    fn idakit_cfuncptr_alloc() -> *mut c_void;
    fn idakit_cfuncptr_free(p: *mut c_void);
    fn idakit_cfuncptr_copy_ctor(dst: *mut c_void, src: *const c_void);
    fn idakit_cfuncptr_decompile_into(dst: *mut c_void, ea: u64) -> c_int;
    fn idakit_cfuncptr_dtor(p: *mut c_void);
    fn idakit_cfuncptr_refcnt_raw(p: *const c_void) -> i32;
    fn idakit_cfuncptr_is_null_raw(p: *const c_void) -> c_int;
}

// SAFETY: alloc returns operator-new'd storage the size of one cfuncptr_t; free operator-deletes
// it. Both match the eventual `delete` in cxx's UniquePtr deleter (destructor + operator delete),
// per MakeCppStorage's contract.
unsafe impl MakeCppStorage for CfuncPtr {
    unsafe fn allocate_uninitialized_cpp_storage() -> *mut Self {
        // SAFETY: FFI to the facade allocator; the cast reinterprets raw C++ storage as *mut Self.
        unsafe { idakit_cfuncptr_alloc().cast() }
    }
    unsafe fn free_uninitialized_cpp_storage(ptr: *mut Self) {
        // SAFETY: `ptr` came from allocate_uninitialized_cpp_storage and is not yet initialized.
        unsafe { idakit_cfuncptr_free(ptr.cast()) }
    }
}

// SAFETY: copy_new runs cfuncptr_t's copy-ctor from *src into the caller's uninitialized storage
// at `this`, which is exactly CopyNew's contract; both pointers address real cfuncptr_t-sized
// storage (C++ heap on the UniquePtr path). After the call the destination is initialized.
unsafe impl CopyNew for CfuncPtr {
    unsafe fn copy_new(src: &Self, this: Pin<&mut MaybeUninit<Self>>) {
        // SAFETY: `this` is uninitialized storage we are permitted to write; `src` points to a
        // live cfuncptr_t. The C++ shim placement-copy-constructs one (refcount++).
        unsafe {
            let dst = this.get_unchecked_mut().as_mut_ptr();
            idakit_cfuncptr_copy_ctor(dst.cast(), (src as *const Self).cast());
        }
    }
}

/// A [`moveit::New`] that decompiles the function at `ea` into caller-provided storage.
///
/// Feed it to an [`Emplace`](moveit::Emplace) target such as `UniquePtr<CfuncPtr>` to build the
/// initial owned handle. The decompiled slot is always initialized (a null `qrefcnt` on failure),
/// so a later copy or destructor is always sound; check [`cfunc_refcnt`] (`< 0`) for failure.
pub struct Decompile {
    /// Entry address of the function to decompile.
    pub ea: u64,
}

// SAFETY: new fully initializes `this` (the C++ shim always placement-constructs a cfuncptr_t,
// null-valued on failure), satisfying New's contract.
unsafe impl New for Decompile {
    type Output = CfuncPtr;
    unsafe fn new(self, this: Pin<&mut MaybeUninit<Self::Output>>) {
        // SAFETY: `this` is uninitialized storage of one cfuncptr_t; the shim constructs into it.
        unsafe {
            let dst = this.get_unchecked_mut().as_mut_ptr();
            idakit_cfuncptr_decompile_into(dst.cast(), self.ea);
        }
    }
}

/// Refcount probe for the `moveit` + `cxx` composition over `UniquePtr<CfuncPtr>`.
///
/// Builds an owned handle by [emplacing](moveit::Emplace) a [`Decompile`], clones it with
/// [`moveit::new::copy`] into a second `UniquePtr` (C++ copy-ctor), then drops the clone. Returns
/// `[after_create, after_clone, after_clone_dropped]` observed `cfunc_t::refcnt` values, or `None`
/// if decompilation failed. A correct intrusive count gives `after_clone == after_create + 1` and
/// `after_clone_dropped == after_create`.
#[must_use]
pub fn cfunc_moveit_uniqueptr_probe(ea: u64) -> Option<[i32; 3]> {
    let owned: UniquePtr<CfuncPtr> =
        <UniquePtr<CfuncPtr> as Emplace<CfuncPtr>>::emplace(Decompile { ea });
    let base = owned.as_ref().expect("emplaced UniquePtr is non-null");
    let after_create = cfunc_refcnt(base);
    if after_create < 0 {
        return None; // decompilation produced a null qrefcnt
    }

    let clone: UniquePtr<CfuncPtr> =
        <UniquePtr<CfuncPtr> as Emplace<CfuncPtr>>::emplace(moveit::new::copy(base));
    let after_clone = cfunc_refcnt(owned.as_ref().unwrap());
    drop(clone);
    let after_clone_dropped = cfunc_refcnt(owned.as_ref().unwrap());

    Some([after_create, after_clone, after_clone_dropped])
}

/// A `moveit`-managed value type mirroring `cfuncptr_t` **inline** (no `cxx`, no heap).
///
/// A `#[repr(C)]`, pointer-sized, `!Unpin` mirror of `qrefcnt_t<cfunc_t>`'s single `cfunc_t*`
/// field, stored directly in Rust (e.g. a stack slot via [`moveit::moveit!`]). Cloning runs the
/// C++ copy-ctor ([`CopyNew`](moveit::CopyNew), refcount++); [`Drop`] runs the C++ destructor
/// (`release()`, refcount--). The raw-pointer field makes it `!Send`/`!Sync`, matching the
/// kernel-thread-only constraint. Distinct from [`CfuncPtr`]: a `cxx` `Opaque` type is a ZST that
/// cannot be stored by value, so the inline value type must be its own hand-rolled mirror.
#[repr(C)]
pub struct CfuncVal {
    ptr: *mut c_void,
    _pin: PhantomPinned,
}

impl CfuncVal {
    /// The pointee `cfunc_t`'s intrusive `refcnt`, or `-1` if this holds a null `qrefcnt`.
    #[must_use]
    pub fn refcnt(&self) -> i32 {
        // SAFETY: `self` is a live cfuncptr_t mirror; the shim reads ptr->refcnt.
        unsafe { idakit_cfuncptr_refcnt_raw((self as *const Self).cast()) }
    }

    /// Whether this holds a null `qrefcnt` (decompilation failed).
    #[must_use]
    pub fn is_null(&self) -> bool {
        // SAFETY: `self` is a live cfuncptr_t mirror.
        unsafe { idakit_cfuncptr_is_null_raw((self as *const Self).cast()) != 0 }
    }
}

// SAFETY: copy_new placement-copy-constructs a cfuncptr_t (refcount++) into `this`; identical
// contract to the CfuncPtr impl, over the inline mirror's storage.
unsafe impl CopyNew for CfuncVal {
    unsafe fn copy_new(src: &Self, this: Pin<&mut MaybeUninit<Self>>) {
        // SAFETY: `this` is writable uninitialized storage; `src` a live cfuncptr_t mirror.
        unsafe {
            let dst = this.get_unchecked_mut().as_mut_ptr();
            idakit_cfuncptr_copy_ctor(dst.cast(), (src as *const Self).cast());
        }
    }
}

impl Drop for CfuncVal {
    fn drop(&mut self) {
        // SAFETY: `self` is a live cfuncptr_t mirror, destructed exactly once here (release()).
        unsafe { idakit_cfuncptr_dtor((self as *mut Self).cast()) };
    }
}

/// A [`moveit::New`] decompiling `ea` into an inline [`CfuncVal`] slot (the [`Decompile`] twin for
/// the inline value type).
pub struct DecompileVal {
    /// Entry address of the function to decompile.
    pub ea: u64,
}

// SAFETY: new always placement-constructs a cfuncptr_t into `this` (null-valued on failure).
unsafe impl New for DecompileVal {
    type Output = CfuncVal;
    unsafe fn new(self, this: Pin<&mut MaybeUninit<Self::Output>>) {
        // SAFETY: `this` is uninitialized storage of one cfuncptr_t mirror.
        unsafe {
            let dst = this.get_unchecked_mut().as_mut_ptr();
            idakit_cfuncptr_decompile_into(dst.cast(), self.ea);
        }
    }
}

/// Refcount probe for the inline `moveit` value type [`CfuncVal`] (no `cxx`, stack storage).
///
/// Emplaces a [`DecompileVal`] on the stack, reads its refcount, clones it in an inner scope with
/// [`moveit::new::copy`] (C++ copy-ctor), then lets the clone drop (C++ destructor). Returns
/// `[after_create, after_clone, after_clone_dropped]`, or `None` if decompilation failed. As for
/// the composition probe, a correct intrusive count gives `+1` on clone and back to base on drop.
#[must_use]
pub fn cfunc_moveit_inline_probe(ea: u64) -> Option<[i32; 3]> {
    moveit::moveit! {
        let a = DecompileVal { ea };
    }
    if a.is_null() {
        return None;
    }
    let after_create = a.refcnt();

    let after_clone;
    {
        moveit::moveit! {
            let b = moveit::new::copy(&*a);
        }
        after_clone = b.refcnt();
        // `b` drops at the end of this block (C++ destructor, refcount--).
    }
    let after_clone_dropped = a.refcnt();

    Some([after_create, after_clone, after_clone_dropped])
}
