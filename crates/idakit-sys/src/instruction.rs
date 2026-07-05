//! Instruction-decode facade: the flat [`InstructionRaw`] POD and `idakit_decode_insn` (`decode.cpp`).

use std::ffi::{c_char, c_int};

use crate::Address;

/// Maximum operands the facade fills in an [`InstructionRaw`], matching `UA_MAXOP`.
pub const IDAKIT_MAX_OPS: usize = 8;

/// [`InstructionRegister::num`] sentinel for an absent base/index register.
pub const IDAKIT_REG_NONE: u16 = 0xFFFF;

/// Semantic operand kinds ([`InstructionOperand::kind`]); the raw `optype` is folded into these.
pub const IDAKIT_OP_REG: u8 = 0;
/// See [`IDAKIT_OP_REG`].
pub const IDAKIT_OP_MEM: u8 = 1;
/// See [`IDAKIT_OP_REG`].
pub const IDAKIT_OP_IMM: u8 = 2;
/// See [`IDAKIT_OP_REG`].
pub const IDAKIT_OP_NEAR: u8 = 3;
/// See [`IDAKIT_OP_REG`].
pub const IDAKIT_OP_FAR: u8 = 4;

/// [`InstructionRaw::flow`] bit flags.
pub const IDAKIT_FLOW_CALL: u8 = 0x01;
/// See [`IDAKIT_FLOW_CALL`].
pub const IDAKIT_FLOW_RET: u8 = 0x02;
/// See [`IDAKIT_FLOW_CALL`].
pub const IDAKIT_FLOW_JUMP: u8 = 0x04;
/// See [`IDAKIT_FLOW_CALL`].
pub const IDAKIT_FLOW_INDIRECT: u8 = 0x08;
/// See [`IDAKIT_FLOW_CALL`].
pub const IDAKIT_FLOW_STOPS: u8 = 0x10;

/// A register reference in a decoded operand, mirroring the facade's `idakit_reg_t`.
/// `num == `[`IDAKIT_REG_NONE`] marks an absent base/index slot; `name` is NUL-terminated.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InstructionRegister {
    /// Register number, or [`IDAKIT_REG_NONE`].
    pub num: u16,
    /// idakit RegisterClass code.
    pub cls: u8,
    /// Byte width selecting the name alias.
    pub width: u8,
    /// IDA's resolved register name (NUL-terminated, empty if unresolved).
    pub name: [c_char; 16],
}

/// One decoded operand, mirroring the facade's `idakit_op_t`. Which fields are meaningful
/// depends on `kind` (see the `IDAKIT_OP_*` constants).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InstructionOperand {
    /// Semantic kind (`IDAKIT_OP_*`).
    pub kind: u8,
    /// Original operand slot index (feature bits are keyed by it).
    pub idx: u8,
    /// Raw `op_dtype_t`.
    pub data_type: u8,
    /// Access bits: bit0 read, bit1 written.
    pub access: u8,
    /// Memory index scale multiplier (1/2/4/8).
    pub scale: u8,
    /// Register (kind = REG).
    pub register: InstructionRegister,
    /// Memory base register (kind = MEM).
    pub base: InstructionRegister,
    /// Memory index register (kind = MEM).
    pub index: InstructionRegister,
    /// Memory displacement (kind = MEM).
    pub disp: i64,
    /// Immediate value (kind = IMM) or far offset (kind = FAR).
    pub value: u64,
    /// Near target, or memory static target / `BADADDR` (kind = NEAR / MEM).
    pub addr: u64,
    /// Far selector (kind = FAR).
    pub sel: u16,
}

/// A decoded instruction, mirroring the facade's `idakit_insn_t`. Filled by
/// [`idakit_decode_insn`]; only the first `nops` entries of `ops` are populated.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InstructionRaw {
    /// Instruction address.
    pub address: u64,
    /// Direct branch/call target, or `BADADDR`.
    pub target: u64,
    /// Processor-local canonical instruction id.
    pub itype: u16,
    /// Encoded length in bytes.
    pub len: u8,
    /// 0 = x86, 1 = x64.
    pub isa: u8,
    /// Number of populated operands.
    pub nops: u8,
    /// `IDAKIT_FLOW_*` bit flags.
    pub flow: u8,
    /// On the `-3` return, the offending raw operand type.
    pub err_optype: u8,
    /// On the `-3` return, the offending operand index.
    pub err_op: u8,
    /// Canonical mnemonic (NUL-terminated).
    pub mnemonic: [c_char; 24],
    /// Operands; only `nops` are valid.
    pub ops: [InstructionOperand; IDAKIT_MAX_OPS],
}

// instruction decode
unsafe extern "C" {
    /// Decode the instruction at `address` into `*out`. Returns 0 on success, or negative:
    /// `-1` no instruction, `-2` unsupported processor, `-3` unmodeled operand.
    pub fn idakit_decode_insn(address: Address, out: *mut InstructionRaw) -> c_int;
}
