//! [`TypeInfo`]: an owned resolved named type and its members; disposes on
//! [`Drop`]. Being `!Send`, it (like [`crate::Cfunc`]) can't leave the kernel
//! thread, so its kernel-touching `Drop` always runs there. Member offsets/sizes
//! are in bytes.

use std::ffi::c_void;
use std::marker::PhantomData;

use idakit_sys as sys;

use crate::Idb;
use crate::ffi::read_string;

/// One field of a struct/union type. Offset and size are in bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    /// Rendered field type, e.g. `char *`.
    pub type_repr: String,
}

/// An owned resolved type. Disposes its kernel handle on drop.
pub struct TypeInfo<'db> {
    handle: *mut c_void,
    _db: PhantomData<&'db Idb>,
}

impl<'db> TypeInfo<'db> {
    /// Take ownership of a non-null `idakit_type_open` handle.
    #[inline]
    pub(crate) fn from_handle(handle: *mut c_void, _db: &'db Idb) -> Self {
        debug_assert!(!handle.is_null(), "TypeInfo handle must be non-null");
        Self {
            handle,
            _db: PhantomData,
        }
    }

    /// The type's size in bytes, or `None` for an incomplete/sizeless type.
    #[inline]
    #[must_use]
    pub fn size(&self) -> Option<u64> {
        let s = unsafe { sys::idakit_type_size(self.handle) };
        (s >= 0).then_some(s as u64)
    }

    /// The full declaration, as IDA would print it.
    #[must_use]
    pub fn declaration(&self) -> Option<String> {
        read_string(|buf, cap| unsafe { sys::idakit_type_print(self.handle, buf, cap) })
    }

    /// Number of members (0 for non-aggregate types).
    #[inline]
    #[must_use]
    pub fn member_count(&self) -> usize {
        unsafe { sys::idakit_type_nmembers(self.handle) }
    }

    /// Lazily iterate the members, in declaration order.
    #[inline]
    #[must_use]
    pub fn members(&self) -> Members<'_> {
        Members {
            ty: self,
            next: 0,
            count: self.member_count(),
        }
    }

    /// Read member `i`, or `None` past the end / on rejection.
    fn member(&self, i: usize) -> Option<Member> {
        let (mut offset, mut size) = (0u64, 0u64);
        let exists =
            unsafe { sys::idakit_type_member_info(self.handle, i, &mut offset, &mut size) };
        if exists == 0 {
            return None;
        }
        Some(Member {
            name: read_string(|buf, cap| unsafe {
                sys::idakit_type_member_name(self.handle, i, buf, cap)
            })
            .unwrap_or_default(),
            offset,
            size,
            type_repr: read_string(|buf, cap| unsafe {
                sys::idakit_type_member_type(self.handle, i, buf, cap)
            })
            .unwrap_or_default(),
        })
    }
}

/// Lazy iterator over a [`TypeInfo`]'s members; see [`TypeInfo::members`].
pub struct Members<'t> {
    ty: &'t TypeInfo<'t>,
    next: usize,
    count: usize,
}

impl Iterator for Members<'_> {
    type Item = Member;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next < self.count {
            let i = self.next;
            self.next += 1;
            if let Some(m) = self.ty.member(i) {
                return Some(m);
            }
        }
        None
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.count - self.next))
    }
}

impl Drop for TypeInfo<'_> {
    #[inline]
    fn drop(&mut self) {
        unsafe { sys::idakit_type_dispose(self.handle) };
    }
}

impl std::fmt::Debug for TypeInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypeInfo")
            .field("size", &self.size())
            .field("members", &self.member_count())
            .finish()
    }
}
