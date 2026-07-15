//! Instruction-decode sentinels shared with the generated decode bridge: semantic operand
//! kinds, control-flow flags, operand access bits, the absent-register sentinel, and the
//! ABI-alignment counts.

use bitflags::bitflags;

/// Maximum operands the instruction bridge fills, matching `UA_MAXOP`.
pub const IDAKIT_MAX_OPS: usize = 8;

/// Sentinel for an absent base/index register in a decoded operand.
pub const IDAKIT_REG_NONE: u16 = 0xFFFF;

/// Semantic operand kinds; the raw `optype` is folded into these.
pub const IDAKIT_OP_REG: u8 = 0;
/// See [`IDAKIT_OP_REG`].
pub const IDAKIT_OP_MEM: u8 = 1;
/// See [`IDAKIT_OP_REG`].
pub const IDAKIT_OP_IMM: u8 = 2;
/// See [`IDAKIT_OP_REG`].
pub const IDAKIT_OP_NEAR: u8 = 3;
/// See [`IDAKIT_OP_REG`].
pub const IDAKIT_OP_FAR: u8 = 4;

bitflags! {
    /// `InstructionData::flow` control-flow bits for a decoded instruction: `IDAKIT_FLOW_CALL`/
    /// `_RET`/`_JUMP`/`_INDIRECT`/`_STOPS`.
    ///
    /// `IDAKIT_FLOW_*` is idakit's own facade sentinel, not a raw SDK value; accepts any bit
    /// pattern (`from_bits_retain`), since `InstructionData::flow` is a raw `u8` field the C++
    /// decoder writes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    #[doc(alias("IDAKIT_FLOW_CALL", "IDAKIT_FLOW_RET", "IDAKIT_FLOW_JUMP", "IDAKIT_FLOW_INDIRECT", "IDAKIT_FLOW_STOPS"))]
    pub struct FlowFlags: u8 {
        /// The instruction is a call (`IDAKIT_FLOW_CALL`).
        #[doc(alias("IDAKIT_FLOW_CALL"))]
        const CALL = 0x01;
        /// The instruction returns (`IDAKIT_FLOW_RET`).
        #[doc(alias("IDAKIT_FLOW_RET"))]
        const RET = 0x02;
        /// The instruction jumps (`IDAKIT_FLOW_JUMP`).
        #[doc(alias("IDAKIT_FLOW_JUMP"))]
        const JUMP = 0x04;
        /// The transfer target is indirect, not statically known (`IDAKIT_FLOW_INDIRECT`).
        #[doc(alias("IDAKIT_FLOW_INDIRECT"))]
        const INDIRECT = 0x08;
        /// Sequential flow stops after this instruction (`IDAKIT_FLOW_STOPS`).
        #[doc(alias("IDAKIT_FLOW_STOPS"))]
        const STOPS = 0x10;
    }
}

bitflags! {
    /// `OperandData::access` bits for a decoded operand: `bit0` read, `bit1` written.
    ///
    /// Accepts any bit pattern (`from_bits_retain`), since `OperandData::access` is a raw `u8`
    /// field the C++ decoder writes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub struct OperandAccess: u8 {
        /// The operand is read.
        const READ = 1;
        /// The operand is written.
        const WRITTEN = 2;
    }
}

/// Number of idakit RegisterClass codes (the `reg_class_ids` alignment-source length).
pub const IDAKIT_REG_CLASS_COUNT: usize = 13;
/// Number of `op_dtype_t` values idakit mirrors (the `op_dtype_ids` alignment-source length).
pub const IDAKIT_OP_DTYPE_COUNT: usize = 19;

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn flags_pin_the_raw_facade_values() {
        assert!(FlowFlags::CALL.bits() == 0x01);
        assert!(FlowFlags::RET.bits() == 0x02);
        assert!(FlowFlags::JUMP.bits() == 0x04);
        assert!(FlowFlags::INDIRECT.bits() == 0x08);
        assert!(FlowFlags::STOPS.bits() == 0x10);
    }

    #[test]
    fn from_bits_retain_preserves_unknown_bits() {
        let raw = (FlowFlags::CALL | FlowFlags::STOPS).bits() | 0x40;
        let flow = FlowFlags::from_bits_retain(raw);
        assert!(flow.contains(FlowFlags::CALL | FlowFlags::STOPS));
        assert!(flow.bits() == raw);
    }

    #[test]
    fn operand_access_flags_pin_the_raw_values() {
        assert!(OperandAccess::READ.bits() == 1);
        assert!(OperandAccess::WRITTEN.bits() == 2);
    }

    #[test]
    fn operand_access_from_bits_retain_preserves_unknown_bits() {
        let raw = OperandAccess::READ.bits() | 0x04;
        let access = OperandAccess::from_bits_retain(raw);
        assert!(access.contains(OperandAccess::READ));
        assert!(access.bits() == raw);
    }
}
