//! The typed [`FrameVarFlags`] layer over `FrameVar`'s reserved-slot flag bits.
//!
//! The frame walk itself is the `cxx` `idakit_cxx::frame_type_walk_visit` entry (see
//! `bridge_visitors`); these flags classify the slots it returns.

use bitflags::bitflags;

bitflags! {
    /// `FrameVar::flags` bits (`FRAME_VAR_RETADDR`/`FRAME_VAR_SAVREGS`).
    ///
    /// Accepts any bit pattern (`from_bits_retain`), since `FrameVar::flags` is a raw `u32` field
    /// the C++ walk writes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias("FRAME_VAR_RETADDR", "FRAME_VAR_SAVREGS"))]
    pub struct FrameVarFlags: u32 {
        /// The return-address slot in the frame (`FRAME_VAR_RETADDR`).
        #[doc(alias("FRAME_VAR_RETADDR"))]
        const RETADDR = 1;
        /// The saved-registers slot in the frame (`FRAME_VAR_SAVREGS`).
        #[doc(alias("FRAME_VAR_SAVREGS"))]
        const SAVREGS = 2;
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn flags_pin_the_raw_values() {
        assert!(FrameVarFlags::RETADDR.bits() == 1);
        assert!(FrameVarFlags::SAVREGS.bits() == 2);
    }

    #[test]
    fn from_bits_retain_preserves_unknown_bits() {
        let raw = FrameVarFlags::RETADDR.bits() | 0x10;
        let flags = FrameVarFlags::from_bits_retain(raw);
        assert!(flags.contains(FrameVarFlags::RETADDR));
        assert!(flags.bits() == raw);
    }
}
