//! An owned, `Send` snapshot of a function's stack frame ([`StackFrame`]).
//!
//! IDA models a function frame as a UDT, so idakit reads it much like a struct, but with stack
//! semantics the generic [`Type`](crate::types::Type) walk lacks: each [`StackSlot`] carries its
//! frame-pointer-relative [`offset`](StackSlot::offset) (the `var_18`/`arg_4` displacement IDA
//! displays), and its [`kind`](StackSlot::kind) distinguishes a real stack variable from IDA's
//! reserved return-address and saved-register slots. Materialized on the kernel thread and handed
//! back owned, so it analyzes anywhere. This is the disassembly-level counterpart to the
//! decompiler's lvars ([`Ctree::lvars`](crate::decompiler::ctree::Ctree::lvars)), and needs no decompilation.
//!
//! The [`StackSlot`]/[`StackSlotKind`] split is a deliberate divergence from idalib's flat UDT
//! members: `offset`/`size` are universal, but a name and type only mean anything for a real
//! variable, so they live inside [`StackSlotKind::Variable`]. A reserved slot's IDA-synthesized
//! name (`__return_address`) carries no information the [`kind`](StackSlot::kind) doesn't, so it
//! is dropped rather than surfaced as a placeholder.

use idakit_sys as sys;

use crate::Database;
use crate::address::Address;
use crate::decompiler::ctree::ExtractError;
use crate::error::{Error, Result};
use crate::types::{SinkAdapter, TypeBuilder, TypeId, TypeSink, TypeTable, TypeValue, tid};

/// A [`StackSlot`] is either a real stack variable, carrying its name and type, or one of the
/// two slots IDA reserves in every frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StackSlotKind {
    /// A stack variable: a local (negative [`offset`](StackSlot::offset)) or a stack-passed
    /// argument (positive), with the name and type IDA gave it.
    Variable {
        /// The variable's name (e.g. `var_18`, `arg_4`); empty if IDA assigned none.
        name: String,
        /// The variable's structured type as a [`TypeId`] into the [`StackFrame`]'s
        /// [`types`](StackFrame::types) table, or `None` for an untyped stack slot. Resolve it
        /// with [`StackFrame::type_of`].
        ty: Option<TypeId>,
    },
    /// IDA's reserved return-address slot.
    #[doc(alias("is_retaddr"))]
    ReturnAddress,
    /// IDA's reserved saved-registers slot (callee-saved registers spilled on entry).
    #[doc(alias("is_savregs"))]
    SavedRegisters,
}

impl StackSlotKind {
    /// Builds from the facade's `(flags, name, ty)` parts.
    ///
    /// A reserved slot (either flag set) drops the synthetic name/type; return-address wins a
    /// (never-real) tie so the mapping stays total and deterministic.
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

/// One slot in a function's stack frame, its frame-pointer-relative offset and byte size, plus a
/// [`kind`](Self::kind) that is either a real variable (with name/type) or a reserved slot.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(alias("udm_t"))]
pub struct StackSlot {
    offset: i64,
    size: u64,
    kind: StackSlotKind,
}

impl StackSlot {
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

    /// What this slot is: a real variable (with name/type) or a reserved slot.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> &StackSlotKind {
        &self.kind
    }

    /// The variable's name, or `None` for a reserved slot.
    ///
    /// Shortcut into [`kind`](Self::kind).
    #[inline]
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match &self.kind {
            StackSlotKind::Variable { name, .. } => Some(name),
            _ => None,
        }
    }

    /// The variable's structured type handle, or `None` for a reserved slot or an untyped stack
    /// slot.
    ///
    /// Resolve it against the owning [`StackFrame`] with [`StackFrame::type_of`]. Shortcut into
    /// [`kind`](Self::kind).
    #[inline]
    #[must_use]
    pub fn ty(&self) -> Option<TypeId> {
        match &self.kind {
            StackSlotKind::Variable { ty, .. } => *ty,
            _ => None,
        }
    }

    /// Whether this is one of IDA's reserved slots (return address or saved registers) rather than
    /// a real variable.
    #[inline]
    #[must_use]
    pub const fn is_special(&self) -> bool {
        !matches!(self.kind, StackSlotKind::Variable { .. })
    }
}

/// An owned, `Send` snapshot of a function's stack frame.
///
/// Build with [`Function::frame`](crate::function::Function::frame)/[`Database::frame`], then
/// read its [`size`](Self::size) and [`slots`](Self::slots). Detached from the kernel, so it
/// inspects on any thread.
#[derive(Debug)]
#[doc(alias("get_func_frame"))]
pub struct StackFrame {
    size: u64,
    types: TypeTable,
    slots: Vec<StackSlot>,
}

impl StackFrame {
    /// The frame's total size in bytes: locals + saved registers + return address + purged args.
    #[inline]
    #[must_use]
    #[doc(alias("get_frame_size"))]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The interned type table backing every [`StackSlot::ty`] handle.
    ///
    /// The frame's own arena, materialized on the kernel thread, so it resolves types on any
    /// thread.
    #[inline]
    #[must_use]
    pub const fn types(&self) -> &TypeTable {
        &self.types
    }

    /// Resolves a [`StackSlot::ty`] handle to its type.
    ///
    /// Handles come from this frame's own [`types`](Self::types) table, so this never panics on
    /// a handle taken from `self`.
    #[inline]
    #[must_use]
    pub fn type_of(&self, id: TypeId) -> &TypeValue {
        self.types.get(id)
    }

    /// Every slot in the frame, in IDA's member order (low to high offset), real variables and
    /// reserved slots alike, told apart by [`StackSlot::kind`].
    ///
    /// Use [`variables`](Self::variables) for just the real ones.
    #[inline]
    #[must_use]
    pub fn slots(&self) -> &[StackSlot] {
        &self.slots
    }

    /// The real stack variables, skipping IDA's reserved slots (return address, saved registers).
    pub fn variables(&self) -> impl Iterator<Item = &StackSlot> {
        self.slots().iter().filter(|s| !s.is_special())
    }

    /// The number of slots, including the reserved ones.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether the frame has no slots.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

/// Accumulates the frame walk's type table: every variable's type is interned here, and the
/// [`FrameVar`](sys::FrameVar) handles the walk returns index it.
struct FrameTypes {
    types: TypeBuilder,
}

impl TypeSink for FrameTypes {
    fn type_builder(&mut self) -> &mut TypeBuilder {
        &mut self.types
    }
}

impl Database {
    /// Snapshots the stack frame of the function containing `address`.
    ///
    /// Returns `Ok(None)` if no function covers `address` or the function has no frame. This is
    /// the disassembly-level view of the function's stack layout, needing no decompilation; for
    /// the decompiler's richer locals, see [`ctree`](Self::ctree).
    ///
    /// # Errors
    /// [`Error::Extract`] if a variable's type could not be structured.
    pub fn frame(&self, address: Address) -> Result<Option<StackFrame>> {
        let mut ft = FrameTypes {
            types: TypeBuilder::new(),
        };
        // The kernel is claimed for `&self`; the driver interns each variable's type into `ft` and
        // returns the frame size and its variables (their `ty` handles into `ft`'s table).
        let Some(walk) = sys::walk_frame_type(address.get(), &mut SinkAdapter(&mut ft)) else {
            return Ok(None);
        };
        // The builder is error-type-agnostic (see the ctree walk): surface an over-wide scalar or
        // an unfilled placeholder as an extraction failure rather than shipping a malformed table.
        if let Some(bytes) = ft.types.too_wide() {
            return Err(Error::Extract {
                address: address.get(),
                source: ExtractError::ScalarTooWide { bytes },
            });
        }
        let unfilled = ft.types.unfilled();
        if unfilled != 0 {
            return Err(Error::Extract {
                address: address.get(),
                source: ExtractError::UnfilledType { count: unfilled },
            });
        }
        let slots = walk
            .vars
            .into_iter()
            .map(|v| StackSlot {
                offset: v.offset,
                size: v.size,
                // A reserved/untyped slot reports IDAKIT_NONE; only a real variable carries a type.
                kind: StackSlotKind::from_parts(
                    v.flags,
                    v.name,
                    (v.ty != sys::IDAKIT_NONE).then(|| tid(v.ty)),
                ),
            })
            .collect();
        Ok(Some(StackFrame {
            size: walk.size,
            types: ft.types.into_table(),
            slots,
        }))
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    const fn assert_send<T: Send>() {}

    // A frame must cross the kernel thread; a later non-Send field would fail this.
    const _: () = assert_send::<StackFrame>();

    /// A clear flag word yields a `Variable` carrying the name/type; either reserved flag yields
    /// the matching special kind and drops the name/type, with return-address winning a tie.
    #[test]
    fn kind_from_parts() {
        let ty = Some(tid(0));
        assert!(
            StackSlotKind::from_parts(0, "var_18".to_owned(), ty)
                == StackSlotKind::Variable {
                    name: "var_18".to_owned(),
                    ty,
                }
        );
        assert!(
            StackSlotKind::from_parts(sys::FRAME_VAR_RETADDR, "r".to_owned(), ty)
                == StackSlotKind::ReturnAddress
        );
        assert!(
            StackSlotKind::from_parts(sys::FRAME_VAR_SAVREGS, "s".to_owned(), None)
                == StackSlotKind::SavedRegisters
        );
        assert!(
            StackSlotKind::from_parts(
                sys::FRAME_VAR_RETADDR | sys::FRAME_VAR_SAVREGS,
                String::new(),
                None
            ) == StackSlotKind::ReturnAddress
        );
    }

    /// A real variable exposes its name/type and is not special; a reserved slot is the reverse.
    #[test]
    fn accessors_follow_the_kind() {
        let ty = Some(tid(3));
        let var = StackSlot {
            offset: -0x18,
            size: 4,
            kind: StackSlotKind::Variable {
                name: "var_18".to_owned(),
                ty,
            },
        };
        assert!(!var.is_special());
        assert!(var.name() == Some("var_18"));
        assert!(var.ty() == ty);

        let retaddr = StackSlot {
            offset: 0,
            size: 8,
            kind: StackSlotKind::ReturnAddress,
        };
        assert!(retaddr.is_special());
        assert!(retaddr.name().is_none());
        assert!(retaddr.ty().is_none());
    }
}
