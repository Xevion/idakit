//! [`Frame`]: an owned, `Send` snapshot of a function's stack frame.
//!
//! IDA models a function frame as a UDT, so idakit reads it much like a struct -- but with stack
//! semantics the generic [`TypeInfo`](crate::TypeInfo) walk lacks: each [`FrameVar`] carries its
//! frame-pointer-relative [`offset`](FrameVar::offset) (the `var_18`/`arg_4` displacement IDA
//! displays), and its [`kind`](FrameVar::kind) distinguishes a real stack variable from IDA's
//! reserved return-address and saved-register slots. Materialized on the kernel thread and handed
//! back owned, so it analyzes anywhere. This is the disassembly-level counterpart to the
//! decompiler's lvars ([`Ctree::lvars`](crate::ctree::Ctree::lvars)), and needs no decompilation.
//!
//! The [`FrameVar`]/[`FrameVarKind`] split is a deliberate divergence from idalib's flat UDT
//! members: `offset`/`size` are universal, but a name and type only mean anything for a real
//! variable, so they live inside [`FrameVarKind::Variable`]. A reserved slot's IDA-synthesized
//! name (`__return_address`) carries no information the [`kind`](FrameVar::kind) doesn't, so it is
//! dropped rather than surfaced as a placeholder.

use std::ffi::{c_char, c_void};

use idakit_sys as sys;

use crate::Idb;
use crate::address::Address;
use crate::ctree::ExtractError;
use crate::error::{Error, Result};
use crate::ffi::lossy;
use crate::types::{TypeBuilder, TypeData, TypeId, TypeSink, TypeTable, reborrow, tid, type_vtbl};

/// What a [`FrameVar`] is: a real stack variable (carrying its name and type), or one of the two
/// slots IDA reserves in every frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameVarKind {
    /// A stack variable: a local (negative [`offset`](FrameVar::offset)) or a stack-passed
    /// argument (positive), with the name and type IDA gave it.
    Variable {
        /// The variable's name (e.g. `var_18`, `arg_4`); empty if IDA assigned none.
        name: String,
        /// The variable's structured type as a [`TypeId`] into the [`Frame`]'s
        /// [`types`](Frame::types) table, or `None` for an untyped stack slot. Resolve it with
        /// [`Frame::type_of`].
        ty: Option<TypeId>,
    },
    /// IDA's reserved return-address slot.
    ReturnAddress,
    /// IDA's reserved saved-registers slot (callee-saved registers spilled on entry).
    SavedRegisters,
}

impl FrameVarKind {
    /// Build from the facade's `(flags, name, ty)` parts. A reserved slot (either flag set) drops
    /// the synthetic name/type; return-address wins a (never-real) tie so the mapping stays total
    /// and deterministic.
    fn from_parts(flags: u32, name: String, ty: Option<TypeId>) -> Self {
        if flags & sys::FRAME_VAR_RETADDR != 0 {
            Self::ReturnAddress
        } else if flags & sys::FRAME_VAR_SAVREGS != 0 {
            Self::SavedRegisters
        } else {
            Self::Variable { name, ty }
        }
    }
}

/// One slot in a function's stack frame: its frame-pointer-relative offset and byte size, plus a
/// [`kind`](Self::kind) that is either a real variable (with name/type) or a reserved slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameVar {
    offset: i64,
    size: u64,
    kind: FrameVarKind,
}

impl FrameVar {
    /// The frame-pointer-relative offset IDA displays: negative below the frame pointer (locals),
    /// positive above it (the return address, then stack arguments).
    #[inline]
    #[must_use]
    pub const fn offset(&self) -> i64 {
        self.offset
    }

    /// The slot's size in bytes.
    #[inline]
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// What this slot is -- a real variable (with name/type) or a reserved slot.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> &FrameVarKind {
        &self.kind
    }

    /// The variable's name, or `None` for a reserved slot. Shortcut into
    /// [`kind`](Self::kind).
    #[inline]
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match &self.kind {
            FrameVarKind::Variable { name, .. } => Some(name),
            _ => None,
        }
    }

    /// The variable's structured type handle, or `None` for a reserved slot or an untyped stack
    /// slot. Resolve it against the owning [`Frame`] with [`Frame::type_of`]. Shortcut into
    /// [`kind`](Self::kind).
    #[inline]
    #[must_use]
    pub fn ty(&self) -> Option<TypeId> {
        match &self.kind {
            FrameVarKind::Variable { ty, .. } => *ty,
            _ => None,
        }
    }

    /// Whether this is one of IDA's reserved slots (return address or saved registers) rather than
    /// a real variable.
    #[inline]
    #[must_use]
    pub const fn is_special(&self) -> bool {
        !matches!(self.kind, FrameVarKind::Variable { .. })
    }
}

/// An owned, `Send` snapshot of a function's stack frame. Build with
/// [`Function::frame`](crate::Function::frame)/[`Idb::frame`], then read its [`size`](Self::size)
/// and [`vars`](Self::vars). Detached from the kernel, so it inspects on any thread.
#[derive(Debug)]
pub struct Frame {
    size: u64,
    types: TypeTable,
    vars: Vec<FrameVar>,
}

impl Frame {
    /// The frame's total size in bytes: locals + saved registers + return address + purged args.
    #[inline]
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The interned type table backing every [`FrameVar::ty`] handle. The frame's own arena,
    /// materialized on the kernel thread, so it resolves types on any thread.
    #[inline]
    #[must_use]
    pub const fn types(&self) -> &TypeTable {
        &self.types
    }

    /// Resolve a [`FrameVar::ty`] handle to its type. Handles come from this frame's own
    /// [`types`](Self::types) table, so this never panics on a handle taken from `self`.
    #[inline]
    #[must_use]
    pub fn type_of(&self, id: TypeId) -> &TypeData {
        self.types.get(id)
    }

    /// Every slot in the frame, in IDA's member order (low to high offset) -- real variables and
    /// reserved slots alike, told apart by [`FrameVar::kind`]. Filter on
    /// [`is_special`](FrameVar::is_special) for just the variables.
    #[inline]
    #[must_use]
    pub fn vars(&self) -> &[FrameVar] {
        &self.vars
    }

    /// The number of slots, including the reserved ones.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.vars.len()
    }

    /// Whether the frame has no slots.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }
}

/// Accumulates the frame walk: the shared [`TypeBuilder`] every variable's type is interned in,
/// plus the variable rows themselves (their `ty` handles into that builder's table).
struct FrameBuilder {
    types: TypeBuilder,
    vars: Vec<FrameVar>,
}

impl TypeSink for FrameBuilder {
    fn type_builder(&mut self) -> &mut TypeBuilder {
        &mut self.types
    }
}

/// Append one frame variable. `ty` is [`IDAKIT_NONE`](sys::IDAKIT_NONE) for a reserved or
/// untyped slot, otherwise a handle into the shared table.
unsafe extern "C" fn cb_f_var(
    ctx: *mut c_void,
    name: *const c_char,
    name_len: usize,
    offset: i64,
    size: u64,
    flags: u32,
    ty: u32,
) {
    let name = unsafe { lossy(name, name_len) }.unwrap_or_default();
    let ty = (ty != sys::IDAKIT_NONE).then(|| tid(ty));
    // SAFETY: `ctx` is the `*mut FrameBuilder` passed to the walk, unaliased for this call.
    unsafe { reborrow::<FrameBuilder>(&ctx) }
        .vars
        .push(FrameVar {
            offset,
            size,
            kind: FrameVarKind::from_parts(flags, name, ty),
        });
}

impl Idb {
    /// Snapshot the stack frame of the function containing `address`: `Ok(None)` if no function
    /// covers it or the function has no frame, `Err` only if a variable's type could not be
    /// structured. The disassembly-level view of the function's stack layout -- no decompilation
    /// needed. For the decompiler's richer locals, see [`ctree`](Self::ctree).
    pub fn frame(&self, address: Address) -> Result<Option<Frame>> {
        let mut fb = FrameBuilder {
            types: TypeBuilder::new(),
            vars: Vec::new(),
        };
        let vtbl = sys::FrameVtbl {
            types: type_vtbl::<FrameBuilder>(),
            f_var: cb_f_var,
        };
        let mut size = 0u64;
        // SAFETY: the kernel is claimed for `&self`; `vtbl`'s callbacks are static and `fb` is a
        // valid out-context borrowed only for this call; `size` is a valid out-param.
        let rc = unsafe {
            sys::idakit_frame_type_walk(
                address.get(),
                &vtbl,
                (&mut fb as *mut FrameBuilder).cast(),
                &mut size,
            )
        };
        if rc != 0 {
            return Ok(None);
        }
        // The builder is error-type-agnostic (see the ctree walk): surface an over-wide scalar or
        // an unfilled placeholder as an extraction failure rather than shipping a malformed table.
        if let Some(bytes) = fb.types.too_wide() {
            return Err(Error::Extract {
                address: address.get(),
                source: ExtractError::ScalarTooWide { bytes },
            });
        }
        let unfilled = fb.types.unfilled();
        if unfilled != 0 {
            return Err(Error::Extract {
                address: address.get(),
                source: ExtractError::UnfilledType { count: unfilled },
            });
        }
        Ok(Some(Frame {
            size,
            types: fb.types.into_table(),
            vars: fb.vars,
        }))
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    const fn assert_send<T: Send>() {}

    // A frame must cross the kernel thread; a later non-Send field would fail this.
    const _: () = assert_send::<Frame>();

    /// A clear flag word yields a `Variable` carrying the name/type; either reserved flag yields
    /// the matching special kind and drops the name/type, with return-address winning a tie.
    #[test]
    fn kind_from_parts() {
        let ty = Some(tid(0));
        assert!(
            FrameVarKind::from_parts(0, "var_18".to_owned(), ty)
                == FrameVarKind::Variable {
                    name: "var_18".to_owned(),
                    ty,
                }
        );
        assert!(
            FrameVarKind::from_parts(sys::FRAME_VAR_RETADDR, "r".to_owned(), ty)
                == FrameVarKind::ReturnAddress
        );
        assert!(
            FrameVarKind::from_parts(sys::FRAME_VAR_SAVREGS, "s".to_owned(), None)
                == FrameVarKind::SavedRegisters
        );
        assert!(
            FrameVarKind::from_parts(
                sys::FRAME_VAR_RETADDR | sys::FRAME_VAR_SAVREGS,
                String::new(),
                None
            ) == FrameVarKind::ReturnAddress
        );
    }

    /// A real variable exposes its name/type and is not special; a reserved slot is the reverse.
    #[test]
    fn accessors_follow_the_kind() {
        let ty = Some(tid(3));
        let var = FrameVar {
            offset: -0x18,
            size: 4,
            kind: FrameVarKind::Variable {
                name: "var_18".to_owned(),
                ty,
            },
        };
        assert!(!var.is_special());
        assert!(var.name() == Some("var_18"));
        assert!(var.ty() == ty);

        let retaddr = FrameVar {
            offset: 0,
            size: 8,
            kind: FrameVarKind::ReturnAddress,
        };
        assert!(retaddr.is_special());
        assert!(retaddr.name().is_none());
        assert!(retaddr.ty().is_none());
    }
}
