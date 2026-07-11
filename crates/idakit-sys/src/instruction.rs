//! Instruction-decode sentinels shared with the generated decode bridge: semantic operand
//! kinds, control-flow flags, the absent-register sentinel, and the ABI-alignment counts.

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

/// Control-flow bit flags for a decoded instruction.
pub const IDAKIT_FLOW_CALL: u8 = 0x01;
/// See [`IDAKIT_FLOW_CALL`].
pub const IDAKIT_FLOW_RET: u8 = 0x02;
/// See [`IDAKIT_FLOW_CALL`].
pub const IDAKIT_FLOW_JUMP: u8 = 0x04;
/// See [`IDAKIT_FLOW_CALL`].
pub const IDAKIT_FLOW_INDIRECT: u8 = 0x08;
/// See [`IDAKIT_FLOW_CALL`].
pub const IDAKIT_FLOW_STOPS: u8 = 0x10;

/// Number of idakit RegisterClass codes (the `reg_class_ids` alignment-source length).
pub const IDAKIT_REG_CLASS_COUNT: usize = 13;
/// Number of `op_dtype_t` values idakit mirrors (the `op_dtype_ids` alignment-source length).
pub const IDAKIT_OP_DTYPE_COUNT: usize = 19;
