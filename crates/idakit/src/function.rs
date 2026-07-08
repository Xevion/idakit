//! Enumerates a database's functions, reads them through the [`Function`] view, and edits them
//! through the [`FunctionEdit`] cursor.
//!
//! [`FunctionEdit`] carries the whole-prototype writes ([`set_type`](FunctionEdit::set_type),
//! [`clear_type`](FunctionEdit::clear_type)) and the field-at-a-time surgery verbs
//! ([`set_return_type`](FunctionEdit::set_return_type),
//! [`set_arg_type`](FunctionEdit::set_arg_type), [`rename_arg`](FunctionEdit::rename_arg),
//! [`set_calling_convention`](FunctionEdit::set_calling_convention),
//! [`prepend_this`](FunctionEdit::prepend_this)). A surgery verb reads the existing prototype,
//! mutates one field, and re-applies; a failure is a typed
//! [`TypeWriteError`].

use std::ffi::c_int;
use std::ops::Range;

use idakit_sys as sys;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::VariantArray;

use crate::Database;
use crate::address::Address;
use crate::decompiler::DecompiledFunction;
use crate::decompiler::ctree::Ctree;
use crate::error::{Error, Result};
use crate::ffi::{read_string, reason_or, with_cstr};
use crate::flowchart::{FlowChart, flowchart_flags};
use crate::instruction::Instruction;
use crate::stack::StackFrame;
use crate::types::{Type, TypeExpr, TypeWriteError, walk_type};
use crate::xref::Xrefs;

impl Database {
    /// A typed cursor at `address`.
    ///
    /// Does not verify a function lives there; absence surfaces lazily. Use
    /// [`functions`](Self::functions) to enumerate real ones.
    #[inline]
    #[must_use]
    #[doc(alias("get_func"))]
    pub fn function(&self, address: Address) -> Function<'_> {
        Function::new(address, self)
    }

    /// Iterates every function in the database, in kernel order.
    #[inline]
    #[must_use]
    #[doc(alias("get_func_qty"))]
    pub fn functions(&self) -> Functions<'_> {
        Functions::new(self)
    }

    /// A write cursor for the function containing `address`, or `None` if none does.
    ///
    /// Normalizes to the function's entry, so `db.function_mut(f.address())` and a mid-body address
    /// target the same function. Acquired by the address key, not by promoting a [`Function`] view.
    ///
    /// ```
    /// # idakit::doctest::with_db(|db| {
    /// let entry = db.functions().next().unwrap().address();
    /// if let Some(mut function) = db.function_mut(entry) {
    ///     function.set_type("int handler(int code)")?;
    /// }
    /// # Ok(())
    /// # }).unwrap();
    /// ```
    #[inline]
    #[must_use]
    #[doc(alias("get_func"))]
    pub fn function_mut(&mut self, address: Address) -> Option<FunctionEdit<'_>> {
        let entry = Address::try_new(self.func_start(address))?;
        Some(FunctionEdit { db: self, entry })
    }

    /// Runs `f` against a write cursor for the function containing `address`, or returns `None`
    /// (without calling `f`) if no function does.
    ///
    /// The scoped-closure companion to [`function_mut`](Self::function_mut).
    pub fn with_function_mut<R>(
        &mut self,
        address: Address,
        f: impl FnOnce(&mut FunctionEdit<'_>) -> R,
    ) -> Option<R> {
        let mut cursor = self.function_mut(address)?;
        Some(f(&mut cursor))
    }
}

/// A borrowed view of one function, keyed by entry address.
#[derive(Clone, Copy)]
#[doc(alias("func_t"))]
pub struct Function<'db> {
    address: Address,
    db: &'db Database,
}

impl<'db> Function<'db> {
    #[inline]
    pub(crate) fn new(address: Address, db: &'db Database) -> Self {
        Self { address, db }
    }

    /// The function's entry address.
    #[inline]
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// The function's name and how IDA assigned it.
    ///
    /// [`FunctionName`] carries the provenance too. A function entry always has a name (an
    /// address-derived placeholder at worst), so this is not optional.
    #[must_use]
    #[doc(alias("get_func_name"))]
    pub fn name(&self) -> FunctionName {
        let text =
            read_string(|buf, cap| self.db.func_name(self.address, buf, cap)).unwrap_or_default();
        FunctionName::from_flags(self.db.get_flags(self.address), text)
    }

    /// The one-line C prototype, or `None` if the kernel has no type info.
    #[must_use]
    #[doc(alias("print_type"))]
    pub fn prototype(&self) -> Option<String> {
        read_string(|buf, cap| self.db.func_type(self.address, buf, cap))
    }

    /// Walks this function's stored prototype into an owned [`Type`].
    ///
    /// The structured counterpart to [`prototype`](Self::prototype), whose root is a
    /// [`TypeShape::Function`](crate::types::TypeShape::Function). `Ok(None)` if the kernel has
    /// no type info for the function.
    ///
    /// # Errors
    /// [`Error::Extract`] if the walked type is malformed.
    #[doc(alias("get_tinfo"))]
    pub fn prototype_type(&self) -> Result<Option<Type>> {
        // SAFETY: the kernel is claimed for `self.db`; the walk's out-params are valid locals.
        walk_type(|v, ctx, root| unsafe {
            sys::idakit_func_type_walk(self.address.get(), v, ctx, root)
        })
        .map_err(|source| Error::Extract {
            address: self.address.get(),
            source,
        })
    }

    /// Lazily iterates this function's chunks, starting with the entry chunk, then any tail
    /// chunks in address order.
    ///
    /// A contiguous function yields exactly one [`FunctionChunk`].
    #[must_use]
    pub fn chunks(&self) -> FunctionChunks<'db> {
        FunctionChunks::new(self.address, self.db)
    }

    /// Lazily iterates this function's instructions, in address order within each chunk,
    /// across every chunk.
    ///
    /// Data items and the alignment tail are skipped; see [`Instructions`].
    #[must_use]
    pub fn instructions(&self) -> Instructions<'db> {
        Instructions::new(self.db, self.address)
    }

    /// The function's exclusive end address: the entry chunk's `end_ea`.
    ///
    /// `None` only if the entry is no longer a function.
    #[must_use]
    #[doc(alias("end_ea"))]
    pub fn end(&self) -> Option<Address> {
        Address::try_new(self.db.func_end(self.address))
    }

    /// The entry chunk's size in bytes (`end - start`), or `0` if the end is unavailable.
    ///
    /// A chunked function's tail chunks lie outside this span; walk [`chunks`](Self::chunks)
    /// for the full extent.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.end().map_or(0, |end| self.address.distance_to(end))
    }

    /// Whether IDA flags this as a library function.
    #[must_use]
    #[doc(alias("FUNC_LIB"))]
    pub fn is_lib(&self) -> bool {
        self.db.func_flags(self.address) & sys::FUNC_LIB != 0
    }

    /// Whether this is a thunk, a trampoline that jumps straight to another function.
    #[must_use]
    #[doc(alias("FUNC_THUNK"))]
    pub fn is_thunk(&self) -> bool {
        self.db.func_flags(self.address) & sys::FUNC_THUNK != 0
    }

    /// Whether this function does not return, e.g. `exit`, `abort`.
    #[must_use]
    #[doc(alias("FUNC_NORET"))]
    pub fn is_noreturn(&self) -> bool {
        self.db.func_flags(self.address) & sys::FUNC_NORET != 0
    }

    /// Lazily iterates cross-references targeting this function's entry.
    #[must_use]
    pub fn xrefs_to(&self) -> Xrefs<'db> {
        self.db.xrefs_to(self.address)
    }

    /// Lazily iterates cross-references originating at this function's entry.
    #[must_use]
    pub fn xrefs_from(&self) -> Xrefs<'db> {
        self.db.xrefs_from(self.address)
    }

    /// Decompiles this function.
    ///
    /// # Errors
    /// [`Error::HexRaysInit`] if the decompiler could not be initialized, [`Error::Decompile`]
    /// if Hex-Rays rejected this function, or [`Error::KernelExit`] if decompilation trapped a
    /// fatal exit.
    #[doc(alias("decompile_func"))]
    pub fn decompile(&self) -> Result<DecompiledFunction<'db>> {
        self.db.decompile(self.address)
    }

    /// Decompiles and materializes the ctree in one step.
    ///
    /// [`decompile`](Self::decompile) then [`DecompiledFunction::ctree`]; use the two-step form
    /// when you also need the [`DecompiledFunction`] itself.
    ///
    /// # Errors
    /// Propagates [`decompile`](Self::decompile)'s errors, plus [`Error::Extract`] if the ctree
    /// fails to materialize.
    pub fn ctree(&self) -> Result<Ctree> {
        let cfunc = self.decompile()?;
        cfunc.ctree().map_err(|source| Error::Extract {
            address: self.address.get(),
            source,
        })
    }

    /// Snapshots this function's stack frame, or `Ok(None)` if it has none.
    ///
    /// The disassembly-level stack layout, no decompilation needed; see [`Database::frame`].
    ///
    /// # Errors
    /// [`Error::Extract`] if a stack variable's type could not be structured.
    #[doc(alias("get_func_frame"))]
    pub fn frame(&self) -> Result<Option<StackFrame>> {
        self.db.frame(self.address)
    }

    /// Snapshots this view's scalar facts into an owned [`FunctionSnapshot`] that can leave the
    /// kernel thread.
    #[must_use]
    pub fn snapshot(&self) -> FunctionSnapshot {
        FunctionSnapshot {
            address: self.address,
            name: self.name(),
            prototype: self.prototype(),
        }
    }
}

#[bon::bon]
impl<'db> Function<'db> {
    /// Builds this function's control-flow graph with default options.
    ///
    /// The whole function is covered, tail chunks included. See [`FlowChart`] and
    /// [`flowchart_with`](Self::flowchart_with) for the knobs.
    ///
    /// # Errors
    /// [`Error::NoFunction`] if the entry address no longer resolves to a function.
    #[doc(alias("qflow_chart_t"))]
    pub fn flowchart(&self) -> Result<FlowChart> {
        self.db.flowchart(self.address)
    }

    /// Builds this function's CFG with non-default options.
    ///
    /// `call_ends` splits a block after every call instruction, `externals(false)` drops the
    /// out-of-function [`ExternalExit`](crate::flowchart::ExternalExit) edges (jump/call targets
    /// outside the function), and `predecessors(false)` skips predecessor lists (a cheaper
    /// build when only forward edges are needed).
    ///
    /// # Errors
    /// [`Error::NoFunction`] if the entry address no longer resolves to a function.
    #[builder]
    #[doc(alias("qflow_chart_t"))]
    pub fn flowchart_with(
        &self,
        #[builder(default = false)] call_ends: bool,
        #[builder(default = true)] externals: bool,
        #[builder(default = true)] predecessors: bool,
    ) -> Result<FlowChart> {
        self.db.build_flowchart(
            self.address,
            flowchart_flags(call_ends, externals, predecessors),
        )
    }
}

/// A write cursor for one function, from [`Database::function_mut`].
///
/// Holds the database exclusively and is keyed by the function's entry address. Read-capable: the
/// common [`Function`] reads ([`name`](Self::name), [`prototype`](Self::prototype)) are inherent
/// here, delegating to the view, so a read-modify-write stays on one cursor. Not obtainable from a
/// borrowing [`Function`].
pub struct FunctionEdit<'db> {
    db: &'db mut Database,
    entry: Address,
}

impl FunctionEdit<'_> {
    /// The function's entry address.
    #[inline]
    #[must_use]
    pub const fn address(&self) -> Address {
        self.entry
    }

    /// The function's name and how IDA assigned it.
    #[must_use]
    #[doc(alias("get_func_name"))]
    pub fn name(&self) -> FunctionName {
        self.db.function(self.entry).name()
    }

    /// The one-line C prototype, or `None` if the kernel has no type info.
    #[must_use]
    #[doc(alias("print_type"))]
    pub fn prototype(&self) -> Option<String> {
        self.db.function(self.entry).prototype()
    }

    /// The function's exclusive end address, or `None` if the entry is no longer a function.
    #[must_use]
    #[doc(alias("end_ea"))]
    pub fn end(&self) -> Option<Address> {
        self.db.function(self.entry).end()
    }

    /// Rename the function.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel rejects the rename, or [`Error::InteriorNul`] if
    /// `name` contains a NUL byte.
    #[doc(alias("set_name"))]
    pub fn rename(&mut self, name: impl AsRef<str>) -> Result<()> {
        self.db.at_mut(self.entry).rename(name)
    }

    /// Apply a function prototype (or any type) to this function's entry.
    ///
    /// A function-typed declaration (`"int f(int)"`) sets the prototype. The database prototype is
    /// not always what the decompiler renders, since a user-pinned local-variable type can
    /// override it.
    ///
    /// # Errors
    /// [`TypeWriteError::ParseFailed`] for an unparseable declaration, [`TypeWriteError::NoType`]
    /// for an unknown named type, [`TypeWriteError::ApplyRejected`] if the kernel rejects the
    /// type, or [`Error::InteriorNul`] if the input contains a NUL byte.
    #[doc(alias("apply_tinfo"))]
    pub fn set_type(&mut self, ty: impl Into<TypeExpr>) -> Result<()> {
        self.db.apply_type_at(self.entry, &ty.into())
    }

    /// Remove this function's prototype, clearing the type at its entry.
    ///
    /// Idempotent: a function with no prototype stays that way and still succeeds.
    ///
    /// # Errors
    /// [`Error::WriteRejected`] if the kernel refuses to remove the existing prototype.
    #[doc(alias("del_tinfo"))]
    pub fn clear_type(&mut self) -> Result<()> {
        self.db.at_mut(self.entry).clear_type()
    }

    /// Replace this function's return type, keeping its parameters and calling convention.
    ///
    /// The surgery counterpart to respelling the whole prototype: it reads the current signature,
    /// swaps the return, and re-applies.
    ///
    /// # Errors
    /// [`TypeWriteError::NoPrototype`] if the entry has no editable prototype,
    /// [`TypeWriteError::BuildFailed`] if `ret` cannot be built, or
    /// [`TypeWriteError::ApplyRejected`] if the kernel rejects the rebuilt signature.
    #[doc(alias("get_func_details", "create_func"))]
    pub fn set_return_type(&mut self, ret: impl Into<TypeExpr>) -> Result<()> {
        let recipe = ret.into().serialize();
        let (code, reason) = self.db.func_set_rettype(self.entry, &recipe);
        sig_result(code, self.entry, None, reason)
    }

    /// Replace the type of parameter `index` (zero-based), keeping its name.
    ///
    /// # Errors
    /// [`TypeWriteError::NoPrototype`] if the entry has no editable prototype,
    /// [`TypeWriteError::ArgIndexOutOfRange`] if `index` is past the last parameter,
    /// [`TypeWriteError::BuildFailed`] if `ty` cannot be built, or
    /// [`TypeWriteError::ApplyRejected`] if the kernel rejects the rebuilt signature.
    #[doc(alias("get_func_details", "create_func"))]
    pub fn set_arg_type(&mut self, index: usize, ty: impl Into<TypeExpr>) -> Result<()> {
        let recipe = ty.into().serialize();
        let (code, arity, reason) = self.db.func_set_argtype(self.entry, index, &recipe);
        sig_result(code, self.entry, Some((index, arity)), reason)
    }

    /// Rename parameter `index` (zero-based), keeping its type.
    ///
    /// # Errors
    /// [`TypeWriteError::NoPrototype`] if the entry has no editable prototype,
    /// [`TypeWriteError::ArgIndexOutOfRange`] if `index` is past the last parameter, or
    /// [`TypeWriteError::ApplyRejected`] if the kernel rejects the rebuilt signature; or
    /// [`Error::InteriorNul`] if `name` contains a NUL byte.
    #[doc(alias("get_func_details", "create_func"))]
    pub fn rename_arg(&mut self, index: usize, name: impl AsRef<str>) -> Result<()> {
        let (code, arity, reason) = with_cstr(name.as_ref(), "name", |p| {
            self.db.func_rename_arg(self.entry, index, p)
        })?;
        sig_result(code, self.entry, Some((index, arity)), reason)
    }

    /// Set this function's calling convention.
    ///
    /// # Errors
    /// [`TypeWriteError::NoPrototype`] if the entry has no editable prototype, or
    /// [`TypeWriteError::ApplyRejected`] if the kernel rejects the convention (e.g. an x86
    /// convention on a non-x86 target).
    #[doc(alias("set_cc"))]
    pub fn set_calling_convention(&mut self, cc: CallingConvention) -> Result<()> {
        let (code, reason) = self.db.func_set_cc(self.entry, c_int::from(u8::from(cc)));
        sig_result(code, self.entry, None, reason)
    }

    /// Insert an implicit `this` pointer as the first parameter, shifting the rest.
    ///
    /// The idiom for turning a free function into a method: pass the owning type as a pointer
    /// (`expr::named("widget_t").pointer()`). Pair with
    /// [`set_calling_convention`](Self::set_calling_convention) for `__thiscall` where the target
    /// wants it.
    ///
    /// # Errors
    /// [`TypeWriteError::NoPrototype`] if the entry has no editable prototype,
    /// [`TypeWriteError::BuildFailed`] if `this` cannot be built, or
    /// [`TypeWriteError::ApplyRejected`] if the kernel rejects the rebuilt signature.
    #[doc(alias("get_func_details", "create_func"))]
    pub fn prepend_this(&mut self, this: impl Into<TypeExpr>) -> Result<()> {
        let recipe = this.into().serialize();
        let (code, reason) = self.db.func_prepend_this(self.entry, &recipe);
        sig_result(code, self.entry, None, reason)
    }
}

/// Maps a surgery return code, the current arity, and any captured reason to a crate [`Result`],
/// the shared tail of the [`FunctionEdit`] surgery verbs. `arg` is `Some((index, arity))` for the
/// index-taking verbs, so an out-of-range code names both. The `IDAKIT_SIG_*` set is closed; an
/// unexpected code names itself in the message rather than silently landing on a generic reason,
/// so a facade drift shows up immediately instead of only in the reason text.
fn sig_result(
    code: c_int,
    address: Address,
    arg: Option<(usize, usize)>,
    reason: String,
) -> Result<()> {
    match code {
        sys::IDAKIT_SIG_OK => Ok(()),
        sys::IDAKIT_SIG_NO_PROTOTYPE => Err(TypeWriteError::NoPrototype {
            address: address.get(),
        }
        .into()),
        sys::IDAKIT_SIG_ARG_RANGE => {
            let (index, arity) = arg.unwrap_or_default();
            Err(TypeWriteError::ArgIndexOutOfRange {
                address: address.get(),
                index,
                arity,
            }
            .into())
        }
        sys::IDAKIT_SIG_BUILD => Err(TypeWriteError::BuildFailed {
            reason: reason_or(
                reason,
                "an unknown named type or invalid declaration within it",
            ),
        }
        .into()),
        sys::IDAKIT_SIG_APPLY => Err(TypeWriteError::ApplyRejected {
            address: address.get(),
            reason: reason_or(reason, "the kernel rejected the edited signature"),
        }
        .into()),
        n => Err(TypeWriteError::ApplyRejected {
            address: address.get(),
            reason: reason_or(
                reason,
                &format!("the kernel rejected the edited signature (unexpected facade code {n})"),
            ),
        }
        .into()),
    }
}

/// A function's calling convention: the plain register/stack conventions surgery can set.
///
/// A curated closed set mirroring the settable `CM_CC_*` conventions from `typeinf.hpp`
/// (IDA 9.3), idakit's own semantic layer over IDA's open convention byte. It omits the
/// usercall/special and custom conventions (which carry explicit argument locations), the ellipsis
/// convention (varargs is a [`function`](crate::types::expr::function) builder flag), and the
/// spoiled-registers marker.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    TryFromPrimitive,
    IntoPrimitive,
    VariantArray,
)]
#[repr(u8)]
#[doc(alias("cm_t", "CM_CC_MASK"))]
pub enum CallingConvention {
    /// Unknown or unspecified (`CM_CC_UNKNOWN`).
    Unknown = 0x10,
    /// `__cdecl`: caller-cleaned stack (`CM_CC_CDECL`).
    Cdecl = 0x30,
    /// `__stdcall`: callee-cleaned stack (`CM_CC_STDCALL`).
    Stdcall = 0x50,
    /// `__pascal`: callee-cleaned, reversed argument order (`CM_CC_PASCAL`).
    Pascal = 0x60,
    /// `__fastcall`: leading arguments in registers (`CM_CC_FASTCALL`).
    Fastcall = 0x70,
    /// `__thiscall`: the `this` pointer in a register (`CM_CC_THISCALL`).
    Thiscall = 0x80,
    /// Swift: arguments and results in registers (`CM_CC_SWIFT`).
    Swift = 0x90,
    /// Go: arguments and results in registers or on the stack by version (`CM_CC_GOLANG`).
    Golang = 0xB0,
}

/// An owned, `Send` snapshot of a function's scalar facts, detached from the database.
/// `Function` borrows a `!Send` [`Database`]; collect snapshots inside an
/// [`Ida::call`](crate::kernel::Ida::call) job to carry results back out.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FunctionSnapshot {
    /// Entry address.
    pub address: Address,
    /// Name and how IDA assigned it.
    pub name: FunctionName,
    /// One-line C prototype, if the kernel had type info.
    pub prototype: Option<String>,
}

/// A function's name together with how IDA assigned it, from [`Function::name`].
///
/// Derefs to the name text, so it reads as the `str` it carries; match the variant to branch on
/// provenance. Every function entry has a name, since IDA names even an unnamed one with at
/// least an address-derived placeholder, so `name()` yields this directly, never an `Option`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[doc(alias("FF_NAME", "FF_LABL"))]
pub enum FunctionName {
    /// An explicit name: user-assigned, or an imported/mangled symbol.
    User(String),
    /// A name IDA generated from analysis (a recognized stub, library match, or thunk), e.g.
    /// `nullsub_0` or `j_malloc`.
    Auto(String),
    /// An address-derived placeholder for an otherwise-unnamed function, e.g. `sub_401000`.
    Dummy(String),
}

impl FunctionName {
    /// The name text, whatever its provenance.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::User(s) | Self::Auto(s) | Self::Dummy(s) => s,
        }
    }

    /// Whether this is an explicit name, user-assigned or an imported symbol.
    #[inline]
    #[must_use]
    pub fn is_user(&self) -> bool {
        matches!(self, Self::User(_))
    }

    /// Whether IDA generated this name from analysis.
    #[inline]
    #[must_use]
    pub fn is_auto(&self) -> bool {
        matches!(self, Self::Auto(_))
    }

    /// Whether this is an address-derived placeholder.
    #[inline]
    #[must_use]
    pub fn is_dummy(&self) -> bool {
        matches!(self, Self::Dummy(_))
    }

    /// Classifies from an address's flags and its resolved name text.
    ///
    /// The two name bits partition cleanly: `FF_NAME` alone is an explicit name, both bits an
    /// IDA-generated one, `FF_LABL` alone a placeholder. A function entry always carries one of
    /// the three, so the flag-less case folds to [`Dummy`](Self::Dummy); unreachable in
    /// practice, pinned by the name sweep test. The bit logic mirrors IDA's
    /// `has_user_name`/`has_auto_name`/`has_dummy_name`, held in step by the alignment test.
    fn from_flags(flags: u64, text: String) -> Self {
        let named = flags & sys::FF_NAME != 0;
        let labeled = flags & sys::FF_LABL != 0;
        match (named, labeled) {
            (true, false) => Self::User(text),
            (true, true) => Self::Auto(text),
            _ => Self::Dummy(text),
        }
    }
}

/// Consume the classification into the owned name string it carries.
impl From<FunctionName> for String {
    #[inline]
    fn from(name: FunctionName) -> Self {
        match name {
            FunctionName::User(s) | FunctionName::Auto(s) | FunctionName::Dummy(s) => s,
        }
    }
}

impl std::ops::Deref for FunctionName {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for FunctionName {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Debug for Function<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Function")
            .field("address", &self.address)
            .field("name", &self.name())
            .finish()
    }
}

// Identity is the entry address alone; the `db` borrow is incidental and must not
// participate, so these are hand-written rather than derived.
impl PartialEq for Function<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.address == o.address
    }
}
impl Eq for Function<'_> {}
impl std::hash::Hash for Function<'_> {
    fn hash<H: std::hash::Hasher>(&self, s: &mut H) {
        self.address.hash(s);
    }
}
impl Ord for Function<'_> {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.address.cmp(&o.address)
    }
}
impl PartialOrd for Function<'_> {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

/// A lazy iterator over every function in the database, in kernel order, from
/// [`Database::functions`].
#[doc(alias("getn_func"))]
pub struct Functions<'db> {
    db: &'db Database,
    next: usize,
    count: usize,
}

impl<'db> Functions<'db> {
    #[inline]
    pub(crate) fn new(db: &'db Database) -> Self {
        Self {
            db,
            next: 0,
            count: db.func_qty(),
        }
    }
}

impl<'db> Iterator for Functions<'db> {
    type Item = Function<'db>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while self.next < self.count {
            let raw = self.db.func_ea(self.next);
            self.next += 1;
            if let Some(address) = Address::try_new(raw) {
                return Some(Function::new(address, self.db));
            }
        }
        None
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.count - self.next))
    }
}

/// A contiguous address range belonging to a function: `[start, end)`.
///
/// A function is one chunk when contiguous, or several when the compiler scattered its body
/// into tail chunks placed elsewhere. Yielded by [`Function::chunks`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(alias("func_tail_iterator_t"))]
pub struct FunctionChunk {
    /// First address of the chunk.
    pub start: Address,
    /// One-past-the-last address of the chunk.
    pub end: Address,
}

/// A lazy iterator over a function's chunks, entry chunk first then tail chunks in address
/// order, from [`Function::chunks`].
#[doc(alias("func_tail_iterator_t"))]
pub struct FunctionChunks<'db> {
    db: &'db Database,
    address: Address,
    next: i32,
    count: i32,
}

impl<'db> FunctionChunks<'db> {
    #[inline]
    pub(crate) fn new(address: Address, db: &'db Database) -> Self {
        Self {
            db,
            address,
            next: 0,
            count: db.func_chunk_qty(address),
        }
    }
}

impl Iterator for FunctionChunks<'_> {
    type Item = FunctionChunk;

    fn next(&mut self) -> Option<FunctionChunk> {
        if self.next >= self.count {
            return None;
        }
        let idx = self.next;
        self.next += 1;
        let (mut start, mut end): (u64, u64) = (0, 0);
        if self.db.func_chunk(self.address, idx, &mut start, &mut end) == 0 {
            return None;
        }
        Some(FunctionChunk {
            start: Address::try_new(start)?,
            end: Address::try_new(end)?,
        })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some((self.count - self.next).max(0) as usize))
    }
}

/// A lazy iterator over a function's instructions, across all its chunks, from
/// [`Function::instructions`].
///
/// Code-gated, decoding only addresses the kernel classifies as code ([`Database::is_code`])
/// and stepping over data items (jump tables, embedded constants) and the alignment tail.
/// [`Database::decode`] turns any bytes into an [`Instruction`], so a plain linear decode past a
/// function's `ret` yields garbage; `is_code` keeps the stream to real instructions.
pub struct Instructions<'db> {
    db: &'db Database,
    chunks: FunctionChunks<'db>,
    /// `(next address to examine, current chunk end)`; `None` until the first chunk loads and
    /// again once the last chunk drains.
    cursor: Option<(Address, Address)>,
}

impl<'db> Instructions<'db> {
    #[inline]
    pub(crate) fn new(db: &'db Database, address: Address) -> Self {
        Self {
            db,
            chunks: FunctionChunks::new(address, db),
            cursor: None,
        }
    }
}

impl Iterator for Instructions<'_> {
    type Item = Instruction;

    fn next(&mut self) -> Option<Instruction> {
        loop {
            let (address, end) = match self.cursor {
                Some((address, end)) if address < end => (address, end),
                _ => {
                    let chunk = self.chunks.next()?;
                    self.cursor = Some((chunk.start, chunk.end));
                    continue;
                }
            };
            // Step past this item before deciding to yield, so every branch advances; the
            // kernel's item end is `address + len` for a decoded instruction, and skips a whole
            // data item in one go. The `> address` guard keeps a pathological zero-width item from
            // stalling the walk.
            let stepped = self.db.item_end(address);
            self.cursor = Some((if stepped > address { stepped } else { end }, end));
            if self.db.is_code(address)
                && let Ok(instruction) = self.db.decode(address)
            {
                return Some(instruction);
            }
        }
    }
}

impl Database {
    /// Lazily decodes the instructions in the half-open range `[range.start, range.end)`,
    /// code-gated like [`Function::instructions`].
    ///
    /// The ranged twin of that walk. Pass a
    /// [`BasicBlock`](crate::flowchart::BasicBlock)'s [`range`](crate::flowchart::BasicBlock::range)
    /// to iterate one basic block.
    #[must_use]
    pub fn instructions_in(&self, range: Range<Address>) -> InstructionsIn<'_> {
        InstructionsIn {
            db: self,
            cursor: range.start,
            end: range.end,
        }
    }
}

/// A lazy iterator over the instructions in a fixed `[start, end)` range, code-gated like
/// [`Instructions`], from [`Database::instructions_in`].
pub struct InstructionsIn<'db> {
    db: &'db Database,
    cursor: Address,
    end: Address,
}

impl Iterator for InstructionsIn<'_> {
    type Item = Instruction;

    fn next(&mut self) -> Option<Instruction> {
        while self.cursor < self.end {
            let address = self.cursor;
            // Step past this item before deciding to yield, so every branch advances; the
            // `> address` guard keeps a zero-width item from stalling the walk (cf. Instructions).
            let stepped = self.db.item_end(address);
            self.cursor = if stepped > address { stepped } else { self.end };
            if self.db.is_code(address)
                && let Ok(instruction) = self.db.decode(address)
            {
                return Some(instruction);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    const fn assert_send<T: Send>() {}

    // Both owned so they can cross the kernel-thread boundary, unlike the borrowed Function view.
    const _: () = assert_send::<FunctionSnapshot>();
    const _: () = assert_send::<FunctionName>();

    /// Every `CallingConvention` round-trips its byte, so a drifted value fails here rather than
    /// silently setting the wrong convention at the facade.
    #[test]
    fn calling_convention_round_trips() {
        for &cc in CallingConvention::VARIANTS {
            assert!(CallingConvention::try_from(u8::from(cc)).ok() == Some(cc));
        }
        // A byte outside the curated set is rejected, not absorbed.
        assert!(CallingConvention::try_from(0x20u8).is_err());
    }

    /// Each discriminant is pinned to the raw `CM_CC_*` code (typeinf.hpp, IDA 9.3).
    #[rstest]
    #[case(CallingConvention::Unknown, 0x10)]
    #[case(CallingConvention::Cdecl, 0x30)]
    #[case(CallingConvention::Stdcall, 0x50)]
    #[case(CallingConvention::Pascal, 0x60)]
    #[case(CallingConvention::Fastcall, 0x70)]
    #[case(CallingConvention::Thiscall, 0x80)]
    #[case(CallingConvention::Swift, 0x90)]
    #[case(CallingConvention::Golang, 0xB0)]
    fn calling_convention_pins_cm_cc(#[case] cc: CallingConvention, #[case] raw: u8) {
        assert!(u8::from(cc) == raw);
    }

    #[test]
    fn from_flags_classifies_by_the_two_name_bits() {
        assert!(
            FunctionName::from_flags(sys::FF_NAME, "s".into()) == FunctionName::User("s".into())
        );
        assert!(
            FunctionName::from_flags(sys::FF_NAME | sys::FF_LABL, "s".into())
                == FunctionName::Auto("s".into())
        );
        assert!(
            FunctionName::from_flags(sys::FF_LABL, "s".into()) == FunctionName::Dummy("s".into())
        );
        // No name flag at all folds to a placeholder (unreachable for a function entry).
        assert!(FunctionName::from_flags(0, "s".into()) == FunctionName::Dummy("s".into()));
    }

    #[test]
    fn from_flags_ignores_unrelated_bits() {
        // Bits outside the two name bits (code/data class, etc.) must not perturb it.
        let noise = 0xFFFF_FFFF_FFFF_3FFFu64; // every bit except FF_NAME (0x4000) and FF_LABL (0x8000)
        assert!(
            FunctionName::from_flags(noise | sys::FF_NAME, "x".into())
                == FunctionName::User("x".into())
        );
        assert!(
            FunctionName::from_flags(noise | sys::FF_LABL, "x".into())
                == FunctionName::Dummy("x".into())
        );
    }

    #[test]
    fn accessors_project_text_and_kind() {
        let u = FunctionName::User("main".into());
        assert!(u.as_str() == "main");
        assert!(&*u == "main");
        assert!(format!("{u}") == "main");
        assert!(String::from(u.clone()) == "main");
        assert!(u.is_user() && !u.is_auto() && !u.is_dummy());
        assert!(FunctionName::Dummy("sub_1000".into()).is_dummy());
        assert!(FunctionName::Auto("nullsub_0".into()).is_auto());
    }

    #[test]
    fn from_flags_matches_ida_predicates() {
        // Our FF_NAME/FF_LABL derivation must agree with IDA's own has_*_name predicates for
        // every combination of the two name bits, regardless of surrounding flag bits, so a
        // future SDK that redefines the bits, or a typo in our constants, fails here.
        for extra in [0u64, 0x1234_5678, u64::MAX] {
            let extra = extra & !(sys::FF_NAME | sys::FF_LABL);
            for &bits in &[0, sys::FF_NAME, sys::FF_LABL, sys::FF_NAME | sys::FF_LABL] {
                let flags = extra | bits;
                let ours = FunctionName::from_flags(flags, String::new());
                // SAFETY: has_*_name are pure bit tests over `flags`, requiring no kernel state
                // and no open database.
                let (user, auto, dummy) = unsafe {
                    (
                        sys::idakit_has_user_name(flags) != 0,
                        sys::idakit_has_auto_name(flags) != 0,
                        sys::idakit_has_dummy_name(flags) != 0,
                    )
                };
                assert!(ours.is_user() == user);
                assert!(ours.is_auto() == auto);
                // IDA's dummy always maps to ours; ours additionally absorbs the no-name case.
                assert!(ours.is_dummy() == (!user && !auto));
                if dummy {
                    assert!(ours.is_dummy());
                }
            }
        }
    }
}
