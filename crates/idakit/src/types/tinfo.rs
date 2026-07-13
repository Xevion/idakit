//! Builds a live `tinfo_t` through [`TypeInfo`], a kernel type handle applied to an address.
//!
//! [`TypeInfo`] is the eager, node-at-a-time counterpart to the deferred [`TypeExpr`](super::TypeExpr)
//! recipe. A leaf constructor on [`Database`] ([`type_int`](Database::type_int),
//! [`type_ref`](Database::type_ref), [`parse_type`](Database::parse_type)) claims the kernel and
//! returns a live handle; composite methods ([`pointer`](TypeInfo::pointer),
//! [`array`](TypeInfo::array), [`const_`](TypeInfo::const_), [`volatile_`](TypeInfo::volatile_))
//! copy the base and wrap it; a write cursor's `apply_type` writes the handle to an address.
//!
//! A handle is built and applied within one kernel job. [`TypeInfo`] carries no `'db` lifetime,
//! deliberately: its terminal op is a `&mut Database` write through a cursor, and a shared
//! `&'db Database` borrow held by the handle would forbid that exclusive borrow. Confinement rests
//! on `!Send` instead: a `PhantomData<*const ()>` pins the handle to the kernel thread and blocks
//! it escaping [`Ida::call`](crate::kernel::Ida::call), whose return must be `Send`.
//!
//! Prefer [`TypeExpr`](super::TypeExpr) by default (`Send`, batchable, one kernel crossing at
//! apply, what [`set_type`](crate::LocationMut::set_type) takes); reach for [`TypeInfo`] to build a
//! subtree once and apply it to many addresses, reuse a base across composites, or hold a live
//! handle for inspection.

use std::marker::PhantomData;

use idakit_sys as sys;

use crate::Database;
use crate::error::{Error, Result};
use crate::ffi::{nul_checked, reason_or};
use crate::types::TypeWriteError;

impl Database {
    /// The `void` type as a live [`TypeInfo`] handle.
    #[must_use]
    #[doc(alias("BTF_VOID"))]
    pub fn type_void(&self) -> TypeInfo {
        TypeInfo::from_handle(sys::tinfo_void())
    }

    /// The `bool` type as a live [`TypeInfo`] handle.
    #[must_use]
    #[doc(alias("BTF_BOOL"))]
    pub fn type_bool(&self) -> TypeInfo {
        TypeInfo::from_handle(sys::tinfo_bool())
    }

    /// A `bytes`-wide integer (1, 2, 4, 8, or 16), signed when `signed`, as a live handle.
    ///
    /// # Errors
    /// [`TypeWriteError::BuildFailed`] if `bytes` is not one of 1, 2, 4, 8, or 16.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let entry = db.functions().next().unwrap().address();
    /// let int32 = db.type_int(4, true)?;
    /// // A scalar applies where the item can hold it; a code entry may reject a data type, so the
    /// // apply returns a `Result` either way.
    /// let _ = db.at_mut(entry).apply_type(&int32);
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[doc(alias("BTF_INT"))]
    pub fn type_int(&self, bytes: u32, signed: bool) -> Result<TypeInfo> {
        TypeInfo::from_nullable(sys::tinfo_int(bytes, signed)).ok_or_else(|| {
            TypeWriteError::BuildFailed {
                reason: format!("{bytes} is not a valid integer width (1, 2, 4, 8, or 16)"),
            }
            .into()
        })
    }

    /// A `bytes`-wide float (4 or 8) as a live handle.
    ///
    /// # Errors
    /// [`TypeWriteError::BuildFailed`] if `bytes` is not 4 or 8.
    #[doc(alias("BTF_FLOAT"))]
    pub fn type_float(&self, bytes: u32) -> Result<TypeInfo> {
        TypeInfo::from_nullable(sys::tinfo_float(bytes)).ok_or_else(|| {
            TypeWriteError::BuildFailed {
                reason: format!("{bytes} is not a valid float width (4 or 8)"),
            }
            .into()
        })
    }

    /// The existing named type `name`, resolved against the local til, as a live handle.
    ///
    /// The build-for-write counterpart to the read-side [`type_named`](Self::type_named): use it to
    /// wrap an already-defined type in a pointer or array before applying it.
    ///
    /// # Errors
    /// [`TypeWriteError::NoType`] if the local til has no type named `name`, or
    /// [`Error::InteriorNul`] if `name` contains a NUL byte.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// db.types_mut().define("struct idakit_doc_pt { int x; int y; };")?;
    /// let handle = db.type_ref("idakit_doc_pt")?;
    /// assert!(db.type_ref("idakit_no_such_zzz").is_err());
    /// # let _ = handle;
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[doc(alias("get_named_type"))]
    pub fn type_ref(&self, name: impl AsRef<str>) -> Result<TypeInfo> {
        let name = nul_checked(name.as_ref(), "name")?;
        // The facade builds a non-null forward reference even for an unknown name, so the read
        // side is the existence oracle: a name absent from the local til is NoType.
        match self.type_named(name) {
            Ok(_) => Ok(TypeInfo::from_handle(sys::tinfo_named(name))),
            Err(Error::TypeNotFound { .. }) => Err(TypeWriteError::NoType {
                name: name.to_owned(),
            }
            .into()),
            Err(e) => Err(e),
        }
    }

    /// The type that `decl` parses to against the local til, as a live handle.
    ///
    /// The eager-handle counterpart to [`expr::decl`](super::expr::decl): the declaration resolves
    /// local names (a struct defined through [`types_mut`](Self::types_mut) is in scope), and the
    /// result is a handle rather than a deferred recipe.
    ///
    /// # Errors
    /// [`TypeWriteError::ParseFailed`] if `decl` does not parse, carrying IDA's parser message, or
    /// [`Error::InteriorNul`] if `decl` contains a NUL byte.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let handle = db.parse_type("int *")?;
    /// assert!(db.parse_type("%%% not a type %%%").is_err());
    /// # let _ = handle;
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[doc(alias("parse_decl"))]
    pub fn parse_type(&self, decl: impl AsRef<str>) -> Result<TypeInfo> {
        let decl = nul_checked(decl.as_ref(), "decl")?;
        match sys::tinfo_decl(decl) {
            Ok(handle) => Ok(TypeInfo::from_handle(handle)),
            Err(e) => Err(TypeWriteError::ParseFailed {
                decl: decl.to_owned(),
                reason: reason_or(e.what(), "the declaration is not valid"),
            }
            .into()),
        }
    }
}

/// A live `tinfo_t` handle that frees its kernel type on [`Drop`].
///
/// Built by a [`Database`] leaf constructor ([`type_int`](Database::type_int),
/// [`type_ref`](Database::type_ref), [`parse_type`](Database::parse_type)) and grown by the
/// composite methods, then written to an address by [`LocationMut::apply_type`](crate::LocationMut::apply_type)
/// or [`FunctionEdit::apply_type`](crate::function::FunctionEdit::apply_type). The composites take
/// `&self` and copy the base, so one handle seeds many derivations and applies to many addresses.
///
/// `handle` is a [`UniquePtr`](cxx::UniquePtr) of [`TInfo`](sys::TInfo), non-null by
/// construction; cxx's deleter runs `~tinfo_t` on drop. A `PhantomData<*const ()>` keeps
/// [`TypeInfo`] `!Send`, so it lives only on the kernel thread and cannot escape
/// [`Ida::call`](crate::kernel::Ida::call).
///
/// ```
/// # idakit::doctest::with_db(|db| {
/// let entry = db.functions().next().unwrap().address();
/// // Build `int *` node-at-a-time; the apply returns a `Result` (a code entry may reject a data
/// // type), while a function prototype below applies cleanly at the entry.
/// let ptr = db.type_int(4, true)?.pointer()?;
/// let _ = db.at_mut(entry).apply_type(&ptr);
/// let proto = db.parse_type("int handler(int code)")?;
/// db.function_mut(entry).unwrap().apply_type(&proto)?;
/// # Ok(())
/// # }).unwrap();
/// ```
///
/// The `!Send` confinement is load-bearing, so it is pinned: a handle passed to a `Send` bound
/// must not compile.
///
/// ```compile_fail
/// # idakit::doctest::with_db(|db| {
/// fn require_send<T: Send>(_: T) {}
/// require_send(db.type_int(4, true)?); // TypeInfo is !Send; this must fail to compile.
/// # Ok(())
/// # }).unwrap();
/// ```
#[doc(alias("tinfo_t"))]
pub struct TypeInfo {
    handle: cxx::UniquePtr<sys::TInfo>,
    _not_send: PhantomData<*const ()>,
}

impl TypeInfo {
    /// Take ownership of a non-null builder handle.
    #[inline]
    fn from_handle(handle: cxx::UniquePtr<sys::TInfo>) -> Self {
        debug_assert!(!handle.is_null());
        Self {
            handle,
            _not_send: PhantomData,
        }
    }

    /// Take ownership of a builder handle that may be null, `None` when the builder rejected its
    /// input (a leaf width outside the set, a base type that cannot be pointed at or arrayed).
    #[inline]
    fn from_nullable(handle: cxx::UniquePtr<sys::TInfo>) -> Option<Self> {
        (!handle.is_null()).then_some(Self {
            handle,
            _not_send: PhantomData,
        })
    }

    /// The live `tinfo_t` behind the handle, non-null by construction (see the type docs).
    #[inline]
    pub(crate) fn tinfo(&self) -> &sys::TInfo {
        self.handle.as_ref().expect("live handle")
    }

    /// A pointer to this type: `T` becomes `T *`.
    ///
    /// Copies the base rather than consuming it, so `let p = base.pointer()?;` leaves `base`
    /// usable, and pointers stack (`base.pointer()?.pointer()` is `T **`).
    ///
    /// # Errors
    /// [`TypeWriteError::BuildFailed`] if the kernel could not build the pointer type.
    #[doc(alias("BT_PTR"))]
    pub fn pointer(&self) -> Result<Self> {
        Self::from_nullable(sys::tinfo_ptr(self.tinfo())).ok_or_else(|| {
            TypeWriteError::BuildFailed {
                reason: "could not build a pointer to the type".to_owned(),
            }
            .into()
        })
    }

    /// An array of `nelems` elements of this type: `T` becomes `T[nelems]`.
    ///
    /// # Errors
    /// [`TypeWriteError::BuildFailed`] if the base type cannot be arrayed (an array of a bare
    /// function type, for instance).
    #[doc(alias("BT_ARRAY"))]
    pub fn array(&self, nelems: u32) -> Result<Self> {
        Self::from_nullable(sys::tinfo_array(self.tinfo(), u64::from(nelems))).ok_or_else(|| {
            TypeWriteError::BuildFailed {
                reason: format!("could not build a {nelems}-element array of the type"),
            }
            .into()
        })
    }

    /// A `const`-qualified copy of this type.
    #[must_use]
    #[doc(alias("BTM_CONST"))]
    pub fn const_(&self) -> Self {
        Self::from_handle(sys::tinfo_const(self.tinfo()))
    }

    /// A `volatile`-qualified copy of this type.
    #[must_use]
    #[doc(alias("BTM_VOLATILE"))]
    pub fn volatile_(&self) -> Self {
        Self::from_handle(sys::tinfo_volatile(self.tinfo()))
    }
}

impl std::fmt::Debug for TypeInfo {
    // The handle is an opaque `tinfo_t`; there is no cheap field to render.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypeInfo").finish_non_exhaustive()
    }
}
