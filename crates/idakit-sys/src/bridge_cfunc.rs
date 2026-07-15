//! The still-experimental inline `moveit` value type [`CfuncVal`] mirroring the decompiler's
//! intrusive-refcounted `cfuncptr_t`.
//!
//! `cfuncptr_t` is the SDK typedef `qrefcnt_t<cfunc_t>`: a bare `cfunc_t*` whose **copy-ctor**
//! increments the pointee's intrusive `cfunc_t::refcnt` and whose **destructor** calls `release()`
//! (decrement, `delete` at zero). The production decompiler path binds it as a `cxx` `Opaque`
//! `ExternType` under `UniquePtr` (the generated hexrays domain). This module keeps the alternative
//! `moveit` value-type path, not yet productionized: [`CfuncVal`] is a `#[repr(C)]` mirror of
//! `cfuncptr_t` held **inline on the Rust stack** (no `cxx`, no heap), cloning through the C++
//! copy-ctor ([`CopyNew`](moveit::CopyNew), refcount++) and running the C++ destructor on [`Drop`]
//! (`release()`, refcount--), all through the raw placement shims below.
//!
//! Kept off the public API by `#[doc(hidden)]` (it reads `cfunc_t::refcnt` for the refcount
//! probes), like [`bridge_probe`](crate::bridge_probe).

// TODO: decide the CfuncVal path's fate -- either productionize the inline moveit value type as a
// heap-free alternative to the UniquePtr<CFunc> decompiler handle, or drop it; proven but unused.
use std::ffi::{c_int, c_void};
use std::marker::PhantomPinned;
use std::mem::MaybeUninit;
use std::pin::Pin;

use moveit::{CopyNew, New};

// Raw C-ABI placement shims backing moveit's traits (facade/cfunc_shims.cpp). They operate on a
// cfuncptr_t laid out at the given pointer, here a repr(C) Rust mirror (the inline CfuncVal path).
unsafe extern "C" {
    fn cfuncptr_copy_ctor(dst: *mut c_void, src: *const c_void);
    fn cfuncptr_decompile_into(dst: *mut c_void, ea: u64) -> c_int;
    fn cfuncptr_dtor(p: *mut c_void);
    fn cfuncptr_refcnt_raw(p: *const c_void) -> i32;
    fn cfuncptr_is_null_raw(p: *const c_void) -> c_int;
}

/// A `moveit`-managed value type mirroring `cfuncptr_t` **inline** (no `cxx`, no heap).
///
/// A `#[repr(C)]`, pointer-sized, `!Unpin` mirror of `qrefcnt_t<cfunc_t>`'s single `cfunc_t*`
/// field, stored directly in Rust (e.g. a stack slot via [`moveit::moveit!`]). Cloning runs the
/// C++ copy-ctor ([`CopyNew`](moveit::CopyNew), refcount++); [`Drop`] runs the C++ destructor
/// (`release()`, refcount--). The raw-pointer field makes it `!Send`/`!Sync`, matching the
/// kernel-thread-only constraint.
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
        unsafe { cfuncptr_refcnt_raw((self as *const Self).cast()) }
    }

    /// Whether this holds a null `qrefcnt` (decompilation failed).
    #[must_use]
    pub fn is_null(&self) -> bool {
        // SAFETY: `self` is a live cfuncptr_t mirror.
        unsafe { cfuncptr_is_null_raw((self as *const Self).cast()) != 0 }
    }
}

// SAFETY: copy_new placement-copy-constructs a cfuncptr_t (refcount++) into `this` over the inline
// mirror's storage. After the call the destination is initialized.
unsafe impl CopyNew for CfuncVal {
    unsafe fn copy_new(src: &Self, this: Pin<&mut MaybeUninit<Self>>) {
        // SAFETY: `this` is writable uninitialized storage; `src` a live cfuncptr_t mirror.
        unsafe {
            let dst = this.get_unchecked_mut().as_mut_ptr();
            cfuncptr_copy_ctor(dst.cast(), (src as *const Self).cast());
        }
    }
}

impl Drop for CfuncVal {
    fn drop(&mut self) {
        // SAFETY: `self` is a live cfuncptr_t mirror, destructed exactly once here (release()).
        unsafe { cfuncptr_dtor((self as *mut Self).cast()) };
    }
}

/// A [`moveit::New`] decompiling `ea` into an inline [`CfuncVal`] slot.
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
            cfuncptr_decompile_into(dst.cast(), self.ea);
        }
    }
}

/// Refcount probe for the inline `moveit` value type [`CfuncVal`] (no `cxx`, stack storage).
///
/// Emplaces a [`DecompileVal`] on the stack, reads its refcount, clones it in an inner scope with
/// [`moveit::new::copy`] (C++ copy-ctor), then lets the clone drop (C++ destructor). Returns
/// `[after_create, after_clone, after_clone_dropped]`, or `None` if decompilation failed. A correct
/// intrusive count gives `+1` on clone and back to base on drop.
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
