//! Mapping from the facade's owned `InstructionData` shared struct into the [`Instruction`] ADT.
//!
//! The facade has already done the processor-specific work on the kernel thread (folding raw
//! operand types into semantic kinds, resolving register names and control flow) and returned it
//! by value. This is the pure, kernel-free rebuild into idakit types, so it is exercised directly
//! by unit tests over hand-built structs.

use idakit_sys as sys;

use super::{
    Access, DecodeError, Flow, FpControl, Instruction, Isa, Masking, Memory, Operand,
    OperandDataType, OperandKind, Register, RegisterClass, RoundMode,
};
use crate::address::Address;

/// Rebuilds a register slot, or `None` for the absent-register sentinel (a memory operand with no
/// base/index).
///
/// The facade only emits a modelled `RegClass` code. An unmodelled register is rejected at the
/// facade with `-4` and never reaches here, so a code outside the enum is pure ABI drift, not
/// runtime data.
fn register(r: &sys::RegisterData) -> Option<Register> {
    if r.num == sys::REG_NONE {
        return None;
    }
    let class = RegisterClass::try_from(r.cls)
        .unwrap_or_else(|_| unreachable!("facade emitted an out-of-range reg class {}", r.cls));
    Some(Register {
        number: r.num,
        class,
        width: r.width,
        name: r.name.as_str().into(),
    })
}

fn operand(o: &sys::OperandData, address: Address) -> Result<Operand, DecodeError> {
    let kind = match o.kind {
        sys::OP_REG => OperandKind::Register(register(&o.reg).ok_or_else(|| {
            DecodeError::MalformedOperand {
                address: address.get(),
                slot: o.idx,
                reason: "register operand carries no register",
            }
        })?),
        sys::OP_MEM => OperandKind::Memory(Memory {
            base: register(&o.base),
            index: register(&o.index),
            scale: o.scale,
            displacement: o.disp,
            segment: None,
            target: Address::try_new(o.addr),
            broadcast: (o.broadcast != 0).then_some(o.broadcast),
        }),
        sys::OP_IMM => OperandKind::Immediate { value: o.value },
        sys::OP_NEAR => OperandKind::Near(Address::try_new(o.addr).ok_or_else(|| {
            DecodeError::MalformedOperand {
                address: address.get(),
                slot: o.idx,
                reason: "near operand has no resolved target",
            }
        })?),
        sys::OP_FAR => OperandKind::Far {
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
            slot: o.idx,
            data_type: o.data_type,
        })?;
    Ok(Operand {
        slot: o.idx,
        byte_offset: o.offb,
        kind,
        data_type,
        access: {
            let access = sys::OperandAccess::from_bits_retain(o.access);
            Access {
                read: access.contains(sys::OperandAccess::READ),
                written: access.contains(sys::OperandAccess::WRITTEN),
            }
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
    // The opmask register (or the REG_NONE sentinel) rides alongside the operands; `register`
    // returns None for the sentinel, so an unmasked instruction lifts to `None` here.
    let masking = register(&data.mask).map(|register| Masking {
        register,
        zeroing: data.zeroing != 0,
    });
    let fp_control = match data.fp_control {
        sys::FPC_NONE => None,
        sys::FPC_ROUNDING => Some(FpControl::Rounding {
            mode: RoundMode::try_from(data.round_mode).unwrap_or_else(|_| {
                unreachable!(
                    "facade emitted an out-of-range round mode {}",
                    data.round_mode
                )
            }),
        }),
        sys::FPC_SAE => Some(FpControl::SuppressExceptions),
        other => unreachable!("facade emitted unknown fp_control {other}"),
    };
    let flow = sys::FlowFlags::from_bits_retain(data.flow);
    Ok(Instruction {
        address,
        len: data.len,
        isa: if data.isa == 1 { Isa::X64 } else { Isa::X86 },
        canonical_code: data.itype,
        mnemonic: data.mnemonic.as_str().into(),
        ops,
        masking,
        fp_control,
        flow: Flow {
            is_call: flow.contains(sys::FlowFlags::CALL),
            is_ret: flow.contains(sys::FlowFlags::RET),
            is_jump: flow.contains(sys::FlowFlags::JUMP),
            is_indirect: flow.contains(sys::FlowFlags::INDIRECT),
            stops: flow.contains(sys::FlowFlags::STOPS),
            target: Address::try_new(data.target),
        },
    })
}

/// Classifies a raw decode result into the rebuilt instruction or the matching [`DecodeError`],
/// from [`Database::decode`](crate::Database::decode)'s `status` code.
///
/// Pure and kernel-free like [`insn_from_data`], so unit tests exercise every status code
/// (including the empirically-unreachable-on-x86 `-2`/`-3`/`-4`) with hand-built data.
pub(crate) fn classify(
    data: &sys::InstructionData,
    address: Address,
) -> Result<Instruction, DecodeError> {
    match data.status {
        0 => insn_from_data(data, address),
        -2 => Err(DecodeError::UnsupportedProcessor),
        -3 => Err(DecodeError::UnsupportedOperand {
            address: address.get(),
            slot: data.err_op,
            operand_type: data.err_optype,
        }),
        -4 => Err(DecodeError::UnsupportedRegister {
            address: address.get(),
            slot: data.err_op,
            // for -4 the facade repurposes err_optype to carry the register number.
            register_number: data.err_optype,
        }),
        // -1 (no instruction) and any other negative status.
        _ => Err(DecodeError::NotCode {
            address: address.get(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    // A fixed decode site for the operand-level tests; the facade would fill `data.address` with
    // this, and `insn_from_data` takes it directly.
    fn at() -> Address {
        Address::try_new(0x1000).expect("0x1000 is a valid address")
    }

    fn none_reg() -> sys::RegisterData {
        sys::RegisterData {
            num: sys::REG_NONE,
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
            offb: 0,
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
            broadcast: 0,
        }
    }

    fn kreg(num: u16, nm: &str) -> sys::RegisterData {
        sys::RegisterData {
            num,
            cls: u8::from(RegisterClass::Mask),
            width: 8,
            name: nm.to_owned(),
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
            mask: none_reg(),
            zeroing: 0,
            fp_control: sys::FPC_NONE,
            round_mode: sys::ROUND_NEAREST,
        }
    }

    #[test]
    fn register_operand_carries_name_and_class() {
        let mut op = blank_op();
        op.kind = sys::OP_REG;
        op.offb = 2;
        op.data_type = u8::from(OperandDataType::Qword);
        op.access = 0b11; // read + written
        op.reg = gpr(0, 8, "rax");

        let mapped = operand(&op, at()).expect("valid reg operand");
        assert!(let OperandKind::Register(r) = &mapped.kind);
        assert!(r.name.as_ref() == "rax");
        assert!(r.class == RegisterClass::GeneralPurpose);
        assert!(r.width == 8);
        assert!(mapped.byte_offset == 2);
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
        op.kind = sys::OP_MEM;
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
        assert!(m.displacement == 8);
        assert!(m.target.is_none());
        assert!(m.segment.is_none());
    }

    #[test]
    fn absent_base_index_map_to_none() {
        let mut op = blank_op();
        op.kind = sys::OP_MEM;
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
        imm.kind = sys::OP_IMM;
        imm.value = 0x1234;
        assert!(let OperandKind::Immediate { value } = operand(&imm, at()).expect("imm").kind);
        assert!(value == 0x1234);

        let mut near = blank_op();
        near.kind = sys::OP_NEAR;
        near.addr = 0x1400;
        assert!(let OperandKind::Near(t) = operand(&near, at()).expect("near").kind);
        assert!(t.get() == 0x1400);
    }

    #[test]
    fn far_operand_carries_selector_and_offset() {
        // A far pointer splits across two facade fields: `sel` the selector, `value` the offset,
        // distinct from NEAR, which lands in `addr`.
        let mut far = blank_op();
        far.kind = sys::OP_FAR;
        far.sel = 0x07;
        far.value = 0xdead_beef;
        assert!(let OperandKind::Far { selector, offset } = operand(&far, at()).expect("far").kind);
        assert!(selector == 0x07);
        assert!(offset == 0xdead_beef);
    }

    #[test]
    fn evex_masking_maps_register_and_zeroing() {
        let mut raw = blank_insn();
        raw.mask = kreg(166, "k1");
        raw.zeroing = 1;
        let insn = insn_from_data(&raw, at()).expect("valid instruction");
        assert!(let Some(m) = &insn.masking);
        assert!(m.register.name.as_ref() == "k1");
        assert!(m.register.class == RegisterClass::Mask);
        assert!(m.zeroing);
    }

    #[test]
    fn merge_masking_has_zeroing_false() {
        let mut raw = blank_insn();
        raw.mask = kreg(167, "k2");
        raw.zeroing = 0;
        let insn = insn_from_data(&raw, at()).expect("valid instruction");
        assert!(let Some(m) = &insn.masking);
        assert!(!m.zeroing);
    }

    #[test]
    fn absent_mask_is_none() {
        let raw = blank_insn(); // mask defaults to the REG_NONE sentinel
        let insn = insn_from_data(&raw, at()).expect("valid instruction");
        assert!(insn.masking.is_none());
    }

    #[test]
    fn broadcast_maps_to_memory_operand() {
        let mut op = blank_op();
        op.kind = sys::OP_MEM;
        op.base = gpr(7, 8, "rdi");
        op.broadcast = 16;
        let mapped = operand(&op, at()).expect("valid mem operand");
        assert!(let OperandKind::Memory(m) = &mapped.kind);
        assert!(m.broadcast == Some(16));
    }

    #[test]
    fn no_broadcast_is_none() {
        let mut op = blank_op();
        op.kind = sys::OP_MEM;
        op.base = gpr(7, 8, "rdi");
        let mapped = operand(&op, at()).expect("valid mem operand");
        assert!(let OperandKind::Memory(m) = &mapped.kind);
        assert!(m.broadcast.is_none());
    }

    #[rstest]
    #[case::nearest(sys::ROUND_NEAREST, RoundMode::Nearest)]
    #[case::down(sys::ROUND_DOWN, RoundMode::Down)]
    #[case::up(sys::ROUND_UP, RoundMode::Up)]
    #[case::zero(sys::ROUND_ZERO, RoundMode::Zero)]
    fn fp_control_rounding_carries_mode(#[case] raw_mode: u8, #[case] mode: RoundMode) {
        let mut raw = blank_insn();
        raw.fp_control = sys::FPC_ROUNDING;
        raw.round_mode = raw_mode;
        let insn = insn_from_data(&raw, at()).expect("valid instruction");
        assert!(insn.fp_control == Some(FpControl::Rounding { mode }));
    }

    #[test]
    fn fp_control_sae_only() {
        let mut raw = blank_insn();
        raw.fp_control = sys::FPC_SAE;
        let insn = insn_from_data(&raw, at()).expect("valid instruction");
        assert!(insn.fp_control == Some(FpControl::SuppressExceptions));
    }

    #[test]
    fn no_fp_control_is_none() {
        let raw = blank_insn(); // fp_control defaults to FPC_NONE
        let insn = insn_from_data(&raw, at()).expect("valid instruction");
        assert!(insn.fp_control.is_none());
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
        op0.kind = sys::OP_REG;
        op0.reg = gpr(0, 8, "rax");
        let mut op1 = blank_op();
        op1.kind = sys::OP_MEM;
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
        raw.flow = (sys::FlowFlags::CALL | sys::FlowFlags::STOPS).bits();
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
        ind.flow = (sys::FlowFlags::JUMP | sys::FlowFlags::INDIRECT | sys::FlowFlags::STOPS).bits();
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
        op.kind = sys::OP_REG; // REG kind, but the register slot is the absent sentinel
        assert!(let Err(DecodeError::MalformedOperand { .. }) = operand(&op, at()));
    }

    #[test]
    fn near_operand_without_target_is_rejected() {
        let mut op = blank_op();
        op.kind = sys::OP_NEAR;
        op.addr = sys::BADADDR; // an unresolved near target
        assert!(let Err(DecodeError::MalformedOperand { .. }) = operand(&op, at()));
    }

    #[test]
    fn out_of_domain_data_type_is_rejected() {
        let mut op = blank_op();
        op.kind = sys::OP_IMM;
        op.data_type = 200; // outside the modeled scalar/float domain
        assert!(let Err(DecodeError::UnsupportedDataType { data_type: 200, .. }) = operand(&op, at()));
    }

    /// A successful status rebuilds the instruction via `insn_from_data`.
    #[test]
    fn classify_success_status_rebuilds_the_instruction() {
        let raw = blank_insn();
        assert!(classify(&raw, at()) == insn_from_data(&raw, at()));
    }

    /// Every failure status maps to its own [`DecodeError`] variant; `-1` and any other negative
    /// status fall back to `NotCode`. Tabled over every arm so dropping one silently regresses to
    /// `NotCode` instead.
    #[rstest]
    #[case::unsupported_processor(-2)]
    #[case::unsupported_operand(-3)]
    #[case::unsupported_register(-4)]
    #[case::no_instruction(-1)]
    #[case::other_negative_status(-99)]
    fn classify_maps_every_failure_status(#[case] status: i32) {
        let mut raw = blank_insn();
        raw.status = status;
        raw.err_op = 3;
        raw.err_optype = 7;
        let err = classify(&raw, at()).expect_err("a negative status is always an error");
        match status {
            -2 => assert!(err == DecodeError::UnsupportedProcessor),
            -3 => assert!(
                err == DecodeError::UnsupportedOperand {
                    address: at().get(),
                    slot: 3,
                    operand_type: 7,
                }
            ),
            -4 => assert!(
                err == DecodeError::UnsupportedRegister {
                    address: at().get(),
                    slot: 3,
                    register_number: 7,
                }
            ),
            _ => assert!(
                err == DecodeError::NotCode {
                    address: at().get(),
                }
            ),
        }
    }
}
