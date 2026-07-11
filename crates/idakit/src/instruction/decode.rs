//! Mapping from the facade's owned `InstructionData` shared struct into the [`Instruction`] ADT.
//!
//! The facade has already done the processor-specific work on the kernel thread (folding raw
//! operand types into semantic kinds, resolving register names and control flow) and returned it
//! by value. This is the pure, kernel-free rebuild into idakit types, so it is exercised directly
//! by unit tests over hand-built structs.

use idakit_sys as sys;

use super::{
    Access, DecodeError, Flow, Instruction, Isa, Memory, Operand, OperandDataType, OperandKind,
    Register, RegisterClass,
};
use crate::address::Address;

/// Rebuilds a register slot, or `None` for the absent-register sentinel (a memory operand with no
/// base/index).
///
/// The facade only emits a modelled `RegClass` code. An unmodelled register is rejected at the
/// facade with `-4` and never reaches here, so a code outside the enum is pure ABI drift, not
/// runtime data.
fn register(r: &sys::RegisterData) -> Option<Register> {
    if r.num == sys::IDAKIT_REG_NONE {
        return None;
    }
    let class = RegisterClass::try_from(r.cls)
        .unwrap_or_else(|_| unreachable!("facade emitted an out-of-range reg class {}", r.cls));
    Some(Register {
        num: r.num,
        class,
        width: r.width,
        name: r.name.as_str().into(),
    })
}

fn operand(o: &sys::OperandData, address: Address) -> Result<Operand, DecodeError> {
    let kind = match o.kind {
        sys::IDAKIT_OP_REG => {
            OperandKind::Register(register(&o.reg).ok_or(DecodeError::MalformedOperand {
                address: address.get(),
                op: o.idx,
                reason: "register operand carries no register",
            })?)
        }
        sys::IDAKIT_OP_MEM => OperandKind::Memory(Memory {
            base: register(&o.base),
            index: register(&o.index),
            scale: o.scale,
            disp: o.disp,
            segment: None,
            target: Address::try_new(o.addr),
        }),
        sys::IDAKIT_OP_IMM => OperandKind::Immediate { value: o.value },
        sys::IDAKIT_OP_NEAR => OperandKind::Near(Address::try_new(o.addr).ok_or(
            DecodeError::MalformedOperand {
                address: address.get(),
                op: o.idx,
                reason: "near operand has no resolved target",
            },
        )?),
        sys::IDAKIT_OP_FAR => OperandKind::Far {
            selector: o.sel,
            offset: o.value,
        },
        // The facade only ever emits the kinds above; a mismatch means the two sides of the
        // ABI drifted, which is a build-time bug, not runtime data.
        other => unreachable!("facade emitted unknown operand kind {other}"),
    };
    let data_type =
        OperandDataType::try_from(o.data_type).map_err(|_| DecodeError::UnsupportedDataType {
            address: address.get(),
            op: o.idx,
            dtype: o.data_type,
        })?;
    Ok(Operand {
        idx: o.idx,
        kind,
        data_type,
        access: Access {
            read: o.access & 1 != 0,
            written: o.access & 2 != 0,
        },
    })
}

/// Rebuilds an owned [`Instruction`] from a successfully-decoded (`status == 0`) [`InstructionData`].
///
/// `address` is the decode site, filled into `data.address` by the facade and passed through so
/// operand errors carry it without re-parsing the sentinel-carrying raw field. `data.ops` is
/// already right-sized to the populated operands, so it maps one-to-one with no trailing slots.
pub(crate) fn insn_from_data(
    data: &sys::InstructionData,
    address: Address,
) -> Result<Instruction, DecodeError> {
    let ops = data
        .ops
        .iter()
        .map(|o| operand(o, address))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Instruction {
        address,
        len: data.len,
        isa: if data.isa == 1 { Isa::X64 } else { Isa::X86 },
        itype: data.itype,
        mnemonic: data.mnemonic.as_str().into(),
        ops,
        flow: Flow {
            is_call: data.flow & sys::IDAKIT_FLOW_CALL != 0,
            is_ret: data.flow & sys::IDAKIT_FLOW_RET != 0,
            is_jump: data.flow & sys::IDAKIT_FLOW_JUMP != 0,
            is_indirect: data.flow & sys::IDAKIT_FLOW_INDIRECT != 0,
            stops: data.flow & sys::IDAKIT_FLOW_STOPS != 0,
            target: Address::try_new(data.target),
        },
    })
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    // A fixed decode site for the operand-level tests; the facade would fill `data.address` with
    // this, and `insn_from_data` takes it directly.
    fn at() -> Address {
        Address::try_new(0x1000).expect("0x1000 is a valid address")
    }

    fn none_reg() -> sys::RegisterData {
        sys::RegisterData {
            num: sys::IDAKIT_REG_NONE,
            cls: 0,
            width: 0,
            name: String::new(),
        }
    }

    fn gpr(num: u16, width: u8, nm: &str) -> sys::RegisterData {
        sys::RegisterData {
            num,
            cls: u8::from(RegisterClass::GeneralPurpose),
            width,
            name: nm.to_owned(),
        }
    }

    fn blank_op() -> sys::OperandData {
        sys::OperandData {
            kind: 0,
            idx: 0,
            data_type: 0,
            access: 0,
            scale: 0,
            reg: none_reg(),
            base: none_reg(),
            index: none_reg(),
            disp: 0,
            value: 0,
            addr: sys::BADADDR,
            sel: 0,
        }
    }

    fn blank_insn() -> sys::InstructionData {
        sys::InstructionData {
            status: 0,
            err_op: 0,
            err_optype: 0,
            address: 0x1000,
            target: sys::BADADDR,
            itype: 0,
            len: 0,
            isa: 1,
            nops: 0,
            flow: 0,
            mnemonic: String::new(),
            ops: Vec::new(),
        }
    }

    #[test]
    fn register_operand_carries_name_and_class() {
        let mut op = blank_op();
        op.kind = sys::IDAKIT_OP_REG;
        op.data_type = u8::from(OperandDataType::Qword);
        op.access = 0b11; // read + written
        op.reg = gpr(0, 8, "rax");

        let mapped = operand(&op, at()).expect("valid reg operand");
        assert!(let OperandKind::Register(r) = &mapped.kind);
        assert!(r.name.as_ref() == "rax");
        assert!(r.class == RegisterClass::GeneralPurpose);
        assert!(r.width == 8);
        assert!(mapped.data_type == OperandDataType::Qword);
        assert!(
            mapped.access
                == Access {
                    read: true,
                    written: true
                }
        );
    }

    #[test]
    fn memory_operand_decodes_base_index_scale_disp() {
        let mut op = blank_op();
        op.kind = sys::IDAKIT_OP_MEM;
        op.data_type = u8::from(OperandDataType::Dword);
        op.base = gpr(5, 8, "rbp");
        op.index = gpr(0, 8, "rax");
        op.scale = 4;
        op.disp = 8;
        op.addr = sys::BADADDR; // no static target for [rbp+rax*4+8]

        let mapped = operand(&op, at()).expect("valid mem operand");
        assert!(let OperandKind::Memory(m) = &mapped.kind);
        assert!(let Some(base) = &m.base);
        assert!(base.name.as_ref() == "rbp");
        assert!(let Some(index) = &m.index);
        assert!(index.name.as_ref() == "rax");
        assert!(m.scale == 4);
        assert!(m.disp == 8);
        assert!(m.target.is_none());
        assert!(m.segment.is_none());
    }

    #[test]
    fn absent_base_index_map_to_none() {
        let mut op = blank_op();
        op.kind = sys::IDAKIT_OP_MEM;
        op.addr = 0x40_0000; // a direct [addr] reference resolves to a target
        let mapped = operand(&op, at()).expect("valid mem operand");
        assert!(let OperandKind::Memory(m) = &mapped.kind);
        assert!(m.base.is_none());
        assert!(m.index.is_none());
        assert!(let Some(t) = m.target);
        assert!(t.get() == 0x40_0000);
    }

    #[test]
    fn immediate_and_near_operands() {
        let mut imm = blank_op();
        imm.kind = sys::IDAKIT_OP_IMM;
        imm.value = 0x1234;
        assert!(let OperandKind::Immediate { value } = operand(&imm, at()).expect("imm").kind);
        assert!(value == 0x1234);

        let mut near = blank_op();
        near.kind = sys::IDAKIT_OP_NEAR;
        near.addr = 0x1400;
        assert!(let OperandKind::Near(t) = operand(&near, at()).expect("near").kind);
        assert!(t.get() == 0x1400);
    }

    #[test]
    fn far_operand_carries_selector_and_offset() {
        // A far pointer splits across two facade fields: `sel` the selector, `value` the offset,
        // distinct from NEAR, which lands in `addr`.
        let mut far = blank_op();
        far.kind = sys::IDAKIT_OP_FAR;
        far.sel = 0x07;
        far.value = 0xdead_beef;
        assert!(let OperandKind::Far { selector, offset } = operand(&far, at()).expect("far").kind);
        assert!(selector == 0x07);
        assert!(offset == 0xdead_beef);
    }

    #[test]
    fn insn_maps_every_present_operand() {
        // `ops` arrives right-sized from the facade, so each entry maps one-to-one with no
        // trailing blank slots to drop.
        let mut raw = blank_insn();
        raw.len = 3;
        raw.itype = 42;
        raw.mnemonic = "lea".to_owned();
        raw.nops = 2;
        let mut op0 = blank_op();
        op0.kind = sys::IDAKIT_OP_REG;
        op0.reg = gpr(0, 8, "rax");
        let mut op1 = blank_op();
        op1.kind = sys::IDAKIT_OP_MEM;
        op1.base = gpr(5, 8, "rbp");
        raw.ops = vec![op0, op1];

        let instruction = insn_from_data(&raw, at()).expect("valid instruction");
        assert!(instruction.address.get() == 0x1000);
        assert!(instruction.len == 3);
        assert!(instruction.isa == Isa::X64);
        assert!(instruction.mnemonic.as_ref() == "lea");
        assert!(instruction.ops.len() == 2);
    }

    #[test]
    fn flow_flags_and_target_unpack() {
        let mut raw = blank_insn();
        raw.flow = sys::IDAKIT_FLOW_CALL | sys::IDAKIT_FLOW_STOPS;
        raw.target = 0x2000;
        let instruction = insn_from_data(&raw, at()).expect("valid instruction");
        assert!(instruction.flow.is_call);
        assert!(instruction.flow.stops);
        assert!(!instruction.flow.is_ret);
        assert!(!instruction.flow.is_jump);
        assert!(let Some(t) = instruction.flow.target);
        assert!(t.get() == 0x2000);

        // A branch with no static target reports None.
        let mut ind = blank_insn();
        ind.flow = sys::IDAKIT_FLOW_JUMP | sys::IDAKIT_FLOW_INDIRECT | sys::IDAKIT_FLOW_STOPS;
        let instruction = insn_from_data(&ind, at()).expect("valid instruction");
        assert!(instruction.flow.is_jump);
        assert!(instruction.flow.is_indirect);
        assert!(instruction.flow.target.is_none());
    }

    // The escape hatches are gone: each malformed field the facade could theoretically emit now
    // yields a typed error instead of a panic or a silent fallback. Empirically these never occur
    // across millions of real operands, but the decoder rejects them loudly rather than
    // fabricating a value.

    #[test]
    fn reg_operand_without_register_is_rejected() {
        let mut op = blank_op();
        op.kind = sys::IDAKIT_OP_REG; // REG kind, but the register slot is the absent sentinel
        assert!(let Err(DecodeError::MalformedOperand { .. }) = operand(&op, at()));
    }

    #[test]
    fn near_operand_without_target_is_rejected() {
        let mut op = blank_op();
        op.kind = sys::IDAKIT_OP_NEAR;
        op.addr = sys::BADADDR; // an unresolved near target
        assert!(let Err(DecodeError::MalformedOperand { .. }) = operand(&op, at()));
    }

    #[test]
    fn out_of_domain_data_type_is_rejected() {
        let mut op = blank_op();
        op.kind = sys::IDAKIT_OP_IMM;
        op.data_type = 200; // outside the modeled domain, no longer folded to Void
        assert!(let Err(DecodeError::UnsupportedDataType { dtype: 200, .. }) = operand(&op, at()));
    }
}
