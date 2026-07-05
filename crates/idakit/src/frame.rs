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

use std::ffi::c_void;

use idakit_sys as sys;

use crate::Idb;
use crate::address::Address;
use crate::ffi::read_string;

/// What a [`FrameVar`] is: a real stack variable (carrying its name and type), or one of the two
/// slots IDA reserves in every frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameVarKind {
    /// A stack variable: a local (negative [`offset`](FrameVar::offset)) or a stack-passed
    /// argument (positive), with the name and type IDA gave it.
    Variable {
        /// The variable's name (e.g. `var_18`, `arg_4`); empty if IDA assigned none.
        name: String,
        /// The variable's type, rendered as IDA prints it (e.g. `int`, `char[16]`); empty if
        /// untyped. A rendered string, not a structured type -- the same representation
        /// [`Member::type_repr`](crate::Member) uses at the disassembly level (the structured form
        /// lives only in the decompiler's [`TypeTable`](crate::ctree::TypeTable)).
        type_repr: String,
    },
    /// IDA's reserved return-address slot.
    ReturnAddress,
    /// IDA's reserved saved-registers slot (callee-saved registers spilled on entry).
    SavedRegisters,
}

impl FrameVarKind {
    /// Build from the facade's `(flags, name, type)` triple. A reserved slot (either flag set)
    /// drops the synthetic name/type; return-address wins a (never-real) tie so the mapping stays
    /// total and deterministic.
    fn from_parts(flags: u32, name: String, type_repr: String) -> Self {
        if flags & sys::FRAME_VAR_RETADDR != 0 {
            Self::ReturnAddress
        } else if flags & sys::FRAME_VAR_SAVREGS != 0 {
            Self::SavedRegisters
        } else {
            Self::Variable { name, type_repr }
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

    /// The variable's rendered type, or `None` for a reserved slot (the `Option` marks
    /// variable-vs-reserved, not a missing type -- a real variable's type is empty at worst).
    /// Shortcut into [`kind`](Self::kind).
    #[inline]
    #[must_use]
    pub fn type_repr(&self) -> Option<&str> {
        match &self.kind {
            FrameVarKind::Variable { type_repr, .. } => Some(type_repr),
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
#[derive(Clone, Debug)]
pub struct Frame {
    size: u64,
    vars: Vec<FrameVar>,
}

impl Frame {
    /// The frame's total size in bytes: locals + saved registers + return address + purged args.
    #[inline]
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
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

    /// Drain a built frame snapshot handle into an owned [`Frame`]. The caller owns `handle` and
    /// frees it afterward; this only reads through it.
    fn from_handle(handle: *const c_void) -> Self {
        // SAFETY (every call below): `handle` is a live frame snapshot; `i` stays in `[0, nvars)`;
        // out-params are valid locals.
        let size = unsafe { sys::idakit_frame_size(handle) };
        let n = unsafe { sys::idakit_frame_nvars(handle) };
        let mut vars = Vec::with_capacity(n);
        for i in 0..n {
            let (mut offset, mut var_size, mut flags) = (0i64, 0u64, 0u32);
            if unsafe { sys::idakit_frame_var(handle, i, &mut offset, &mut var_size, &mut flags) }
                == 0
            {
                continue;
            }
            let name =
                read_string(|buf, cap| unsafe { sys::idakit_frame_var_name(handle, i, buf, cap) })
                    .unwrap_or_default();
            let type_repr =
                read_string(|buf, cap| unsafe { sys::idakit_frame_var_type(handle, i, buf, cap) })
                    .unwrap_or_default();
            vars.push(FrameVar {
                offset,
                size: var_size,
                kind: FrameVarKind::from_parts(flags, name, type_repr),
            });
        }
        Self { size, vars }
    }
}

impl Idb {
    /// Snapshot the stack frame of the function containing `address`, or `None` if no function
    /// covers it or the function has no frame. The disassembly-level view of the function's stack
    /// layout -- no decompilation needed. For the decompiler's richer locals, see
    /// [`ctree`](Self::ctree).
    #[must_use]
    pub fn frame(&self, address: Address) -> Option<Frame> {
        // SAFETY: the kernel is claimed for `&self`; the handle is owned by this call and freed
        // once, below.
        let handle = unsafe { sys::idakit_frame_build(address.get()) };
        if handle.is_null() {
            return None;
        }
        let frame = Frame::from_handle(handle);
        // SAFETY: `handle` came from `idakit_frame_build`, is non-null, and is freed exactly once
        // here; nothing borrows it afterwards.
        unsafe { sys::idakit_frame_free(handle) };
        Some(frame)
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
        assert!(
            FrameVarKind::from_parts(0, "var_18".to_owned(), "int".to_owned())
                == FrameVarKind::Variable {
                    name: "var_18".to_owned(),
                    type_repr: "int".to_owned(),
                }
        );
        assert!(
            FrameVarKind::from_parts(sys::FRAME_VAR_RETADDR, "r".to_owned(), String::new())
                == FrameVarKind::ReturnAddress
        );
        assert!(
            FrameVarKind::from_parts(sys::FRAME_VAR_SAVREGS, "s".to_owned(), String::new())
                == FrameVarKind::SavedRegisters
        );
        assert!(
            FrameVarKind::from_parts(
                sys::FRAME_VAR_RETADDR | sys::FRAME_VAR_SAVREGS,
                String::new(),
                String::new()
            ) == FrameVarKind::ReturnAddress
        );
    }

    /// A real variable exposes its name/type and is not special; a reserved slot is the reverse.
    #[test]
    fn accessors_follow_the_kind() {
        let var = FrameVar {
            offset: -0x18,
            size: 4,
            kind: FrameVarKind::Variable {
                name: "var_18".to_owned(),
                type_repr: "int".to_owned(),
            },
        };
        assert!(!var.is_special());
        assert!(var.name() == Some("var_18"));
        assert!(var.type_repr() == Some("int"));

        let retaddr = FrameVar {
            offset: 0,
            size: 8,
            kind: FrameVarKind::ReturnAddress,
        };
        assert!(retaddr.is_special());
        assert!(retaddr.name().is_none());
        assert!(retaddr.type_repr().is_none());
    }
}
