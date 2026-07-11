//! Function stack-frame flags.
//!
//! The frame walk itself is the `cxx` `idakit_cxx::frame_type_walk_visit` entry (see
//! `bridge_typewalk`); these flags classify the slots it returns.

/// `FrameVar` flag: the return-address slot in the frame.
pub const FRAME_VAR_RETADDR: u32 = 1;
/// `FrameVar` flag: the saved-registers slot in the frame.
pub const FRAME_VAR_SAVREGS: u32 = 2;
