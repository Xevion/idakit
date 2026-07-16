use super::super::model::*;

/// The instruction-decode domain: x86/x64 `decode_insn` folded into an owned, by-value
/// [`InstructionData`] shared struct instead of a flat out-param POD. The struct nests
/// [`OperandData`] (a `Vec`, right-sized to the populated operands) and [`RegisterData`] by value,
/// and carries a `status` field standing in for the raw facade's return code, so the whole decode
/// crosses as one value with no `Result` (the five outcomes, ok plus `-1..-4`, are structured
/// payloads a string-only `cxx` exception could not carry). `reg_class_ids`/`op_dtype_ids` expose
/// the facade's own discriminants as `Vec<u8>` alignment sources for idakit's mirror tests. The
/// whole body is hand-written in `facade/instruction.cpp`.
pub const INSTRUCTION: Domain = Domain {
    name: "instruction",
    sdk_includes: &[],
    externs: &[],
    structs: &[
        SharedStruct {
            name: "RegisterData",
            doc: "One register reference in a decoded operand, nested by value in an \
                  [`OperandData`].",
            fields: fields! {
                num: U16 = "Register number, or `0xFFFF` for an absent base/index slot.";
                cls: U8 = "idakit `RegisterClass` code.";
                width: U8 = "Byte width selecting the name alias.";
                name: Str = "IDA's resolved register name, empty if unresolved.";
            },
        },
        SharedStruct {
            name: "OperandData",
            doc: "One decoded operand; which fields are meaningful depends on `kind`.",
            fields: fields! {
                kind: U8 = "Semantic kind (0 reg, 1 mem, 2 imm, 3 near, 4 far).";
                idx: U8 = "Original operand slot index (feature bits are keyed by it).";
                offb: U8 = "Raw `op_t::offb`: the operand's byte offset within the encoded \
                            instruction.";
                data_type: U8 = "Raw `op_dtype_t`.";
                access: U8 = "Access bits: bit0 read, bit1 written.";
                scale: U8 = "Memory index scale multiplier (1/2/4/8).";
                reg: Struct("RegisterData") = "Register (kind = reg). Named `reg`, not `register` (a C++ keyword).";
                base: Struct("RegisterData") = "Memory base register (kind = mem).";
                index: Struct("RegisterData") = "Memory index register (kind = mem).";
                disp: I64 = "Memory displacement (kind = mem).";
                value: U64 = "Immediate value (kind = imm) or far offset (kind = far).";
                addr: U64 = "Near target, or memory static target / `BADADDR` (kind = near/mem).";
                sel: U16 = "Far selector (kind = far).";
            },
        },
        SharedStruct {
            name: "InstructionData",
            doc: "A decoded instruction, returned by value from [`decode_insn`]; `status` carries \
                  the raw result code and `ops` is right-sized to the populated operands.",
            fields: fields! {
                status: I32 = "Result code: 0 ok, -1 no instruction, -2 unsupported processor, \
                          -3 unmodeled operand, -4 unmodeled register.";
                err_op: U8 = "On the -3/-4 status, the offending operand index.";
                err_optype: U8 = "On -3 the offending raw operand type; on -4 the register number.";
                address: U64 = "Instruction address.";
                target: U64 = "Direct branch/call target, or `BADADDR`.";
                itype: U16 = "Processor-local canonical instruction id.";
                len: U8 = "Encoded length in bytes.";
                isa: U8 = "0 = x86, 1 = x64.";
                nops: U8 = "Number of populated operands (matches `ops.len()`).";
                flow: U8 = "`FLOW_*` bit flags.";
                mnemonic: Str = "Canonical mnemonic.";
                ops: VecStruct("OperandData") = "Decoded operands; only meaningful when `status == 0`.";
            },
        },
    ],
    consts: &[
        ConstDef {
            name: "MAX_OPS",
            ty: ConstTy::Usize,
            value: 8,
            doc: "Maximum operands the instruction bridge fills, matching `UA_MAXOP`.",
        },
        ConstDef {
            name: "OP_REG",
            ty: ConstTy::U8,
            value: 0,
            doc: "Semantic operand kind: register.",
        },
        ConstDef {
            name: "OP_MEM",
            ty: ConstTy::U8,
            value: 1,
            doc: "Semantic operand kind: memory.",
        },
        ConstDef {
            name: "OP_IMM",
            ty: ConstTy::U8,
            value: 2,
            doc: "Semantic operand kind: immediate.",
        },
        ConstDef {
            name: "OP_NEAR",
            ty: ConstTy::U8,
            value: 3,
            doc: "Semantic operand kind: near branch/call target.",
        },
        ConstDef {
            name: "OP_FAR",
            ty: ConstTy::U8,
            value: 4,
            doc: "Semantic operand kind: far branch/call target.",
        },
        ConstDef {
            name: "REG_NONE",
            ty: ConstTy::U16,
            value: 0xFFFF,
            doc: "Sentinel for an absent base/index register in a decoded operand.",
        },
        ConstDef {
            name: "FLOW_CALL",
            ty: ConstTy::U8,
            value: 0x01,
            doc: "`InstructionData::flow` bit: the instruction is a call.",
        },
        ConstDef {
            name: "FLOW_RET",
            ty: ConstTy::U8,
            value: 0x02,
            doc: "`InstructionData::flow` bit: the instruction returns.",
        },
        ConstDef {
            name: "FLOW_JUMP",
            ty: ConstTy::U8,
            value: 0x04,
            doc: "`InstructionData::flow` bit: the instruction jumps.",
        },
        ConstDef {
            name: "FLOW_INDIRECT",
            ty: ConstTy::U8,
            value: 0x08,
            doc: "`InstructionData::flow` bit: the transfer target is indirect, not statically known.",
        },
        ConstDef {
            name: "FLOW_STOPS",
            ty: ConstTy::U8,
            value: 0x10,
            doc: "`InstructionData::flow` bit: sequential flow stops after this instruction.",
        },
    ],
    custom_tus: &["facade/instruction.cpp"],
    fns: fns! {
        "Decode the instruction at `ea`, folding raw operands into semantic kinds with resolved \
         register names and control-flow facts. Infallible at the boundary: the result code lands \
         in [`InstructionData::status`] rather than throwing, since the -3/-4 failures carry \
         structured payloads."
            decode_insn(ea: U64) -> Shared("InstructionData");
        "The facade's `RegisterClass` codes in idakit's discriminant order, an alignment source \
         pinning the Rust mirror to this SDK build in a test."
            reg_class_ids() -> VecU8;
        "This SDK's `op_dtype_t` (`dt_*`) values in idakit `DataType`'s discriminant order, an \
         alignment source for a mirror test."
            op_dtype_ids() -> VecU8;
    },
};
