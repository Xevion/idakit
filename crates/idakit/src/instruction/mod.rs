//! Decoded machine instructions: an owned, `Send` disassembly ADT.
//!
//! [`Idb::decode`](crate::Idb::decode) turns the bytes at an [`Address`] into an owned [`Instruction`]
//! -- mnemonic, operands, and control-flow facts all resolved on the kernel thread and
//! baked in, so the value carries no borrow and can be analyzed on any worker thread. This
//! is the raw-disassembly counterpart to the decompiler ctree: it stays ISA-shaped (it
//! does not lift to an IR), and, like the ctree, it materializes owned data rather than
//! handing back a `!Send` view over kernel structures.
//!
//! Operands are modelled *semantically* -- [`OperandKind`] is a small closed set
//! (register / memory / immediate / branch target). IDA's raw operand-type byte is an
//! open space (x86 alone uses values above the documented range for YMM/ZMM/mask
//! registers), so mirroring it would be a trap; instead the per-processor decoder folds
//! every raw type into one of these kinds. An [`Instruction`] that exists is therefore fully and
//! faithfully decoded: an unsupported processor or an operand the decoder cannot model is
//! a [`DecodeError`], never a partial or fallback value.

mod data_type;
mod decode;
mod register;

pub use data_type::DataType;
pub use register::{Register, RegisterClass};

pub(crate) use decode::insn_from_raw;

use snafu::Snafu;

use idakit_sys as sys;

use crate::Idb;
use crate::address::Address;

impl Idb {
    /// Decode the instruction at `address` into an owned, `Send` [`Instruction`] -- mnemonic, semantic
    /// operands, and control-flow facts, all resolved here on the kernel thread.
    ///
    /// `Err` if no instruction decodes there ([`DecodeError::NotCode`]) or the database's
    /// processor has no decoder ([`DecodeError::UnsupportedProcessor`]); only x86/x64 are
    /// modelled. An [`Instruction`] that is returned is *fully faithfully* decoded -- there is
    /// no partial or fallback result: an operand the model cannot represent exactly (an
    /// unmodelled register or value type, a malformed payload) is a loud error, never a guess.
    pub fn decode(&self, address: Address) -> Result<Instruction, DecodeError> {
        // SAFETY: `InstructionRaw` is an all-integer POD, so an all-zero bit pattern is a valid
        // value; the facade overwrites it before it reports success.
        let mut raw: sys::InstructionRaw = unsafe { std::mem::zeroed() };
        match self.decode_insn(address, &mut raw) {
            0 => insn_from_raw(&raw, address),
            -2 => Err(DecodeError::UnsupportedProcessor),
            -3 => Err(DecodeError::UnsupportedOperand {
                address: address.get(),
                op: raw.err_op,
                optype: raw.err_optype,
            }),
            -4 => Err(DecodeError::UnsupportedRegister {
                address: address.get(),
                op: raw.err_op,
                // for -4 the facade repurposes err_optype to carry the register number.
                regnum: raw.err_optype,
            }),
            // -1 (no instruction) and any other negative rc.
            _ => Err(DecodeError::NotCode {
                address: address.get(),
            }),
        }
    }
}

/// Why decoding an instruction failed.
///
/// [`NotCode`](Self::NotCode) is an ordinary outcome -- probing an address that isn't an
/// instruction -- so it is a distinct, cheaply matched error rather than a variant of the
/// crate-wide [`Error`](crate::Error); a [`From`] conversion still lets `?` flatten it into
/// an [`Error`](crate::Error) where that's wanted.
#[derive(Debug, Snafu, PartialEq, Eq)]
#[snafu(visibility(pub(crate)))]
pub enum DecodeError {
    /// No instruction decodes at `address`: the bytes there are data or undefined.
    #[snafu(display("no instruction at {address:#x}"))]
    NotCode {
        /// The address probed.
        address: u64,
    },
    /// The database's processor has no wired decoder (only x86/x64 are modelled).
    #[snafu(display("no instruction decoder for this processor (x86/x64 only)"))]
    UnsupportedProcessor,
    /// A supported processor produced an operand this decoder cannot model. Unreachable
    /// for x86, which enumerates all of its operand types; a loud safety net, not a normal
    /// path.
    #[snafu(display("unmodeled operand {op} (raw optype {optype}) at {address:#x}"))]
    UnsupportedOperand {
        /// Address of the instruction.
        address: u64,
        /// The operand slot that could not be modelled.
        op: u8,
        /// The raw `optype` byte the decoder did not recognize.
        optype: u8,
    },

    /// A register operand referred to a register in no modelled [`RegisterClass`] -- flags,
    /// fpu/sse control-status, or a number outside the register file. Rejected loudly rather
    /// than mislabeled `Gpr`; empirically never emitted for a real x86 operand.
    #[snafu(display("unmodeled register {regnum} at operand {op}, {address:#x}"))]
    UnsupportedRegister {
        /// Address of the instruction.
        address: u64,
        /// The operand slot carrying the register.
        op: u8,
        /// The processor-local register number that has no modelled class.
        regnum: u8,
    },

    /// An operand's value type was outside this IDA minor's `op_dtype_t` domain -- only 9.3's
    /// `dt_*` set is modelled, so a newer SDK's value is a deliberate break, not a silent
    /// `Void`. See [`DataType`].
    #[snafu(display("unmodeled data type {dtype} at operand {op}, {address:#x}"))]
    UnsupportedDataType {
        /// Address of the instruction.
        address: u64,
        /// The operand slot carrying the value type.
        op: u8,
        /// The raw `op_dtype_t` byte outside the modelled domain.
        dtype: u8,
    },

    /// A modelled operand kind arrived with a payload that contradicts it -- a near branch
    /// whose target did not resolve, or a register operand with no register. A facade
    /// contract violation; empirically impossible, kept as a loud guard rather than a panic.
    #[snafu(display("malformed operand {op} at {address:#x}: {reason}"))]
    MalformedOperand {
        /// Address of the instruction.
        address: u64,
        /// The offending operand slot.
        op: u8,
        /// What made the operand malformed.
        reason: &'static str,
    },
}

/// The instruction-set architecture a decoded instruction was read under.
///
/// A closed set that grows only when a decoder is *implemented*: decoding under a
/// processor with no wired decoder is a [`DecodeError::UnsupportedProcessor`], not a
/// variant here. `#[non_exhaustive]` reserves room for future decoders without a breaking
/// change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Isa {
    /// 32-bit x86.
    X86,
    /// 64-bit x86-64.
    X64,
}

/// One decoded instruction: owned, `Send`, and self-describing.
///
/// Keyed by its [`Address`]; fall-through is `address + len` and branch destinations are plain
/// [`Address`]s, so an instruction stream needs no interning -- it is just an address-ordered
/// sequence of these. Everything the kernel had to resolve (the mnemonic, register names,
/// control-flow classification) is already here; nothing on an [`Instruction`] calls back into
/// the kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    /// Address of the instruction.
    pub address: Address,
    /// Encoded length in bytes.
    pub len: u8,
    /// The architecture this was decoded under; makes `itype`, register numbers, and the
    /// mnemonic self-describing off-thread.
    pub isa: Isa,
    /// Processor-local canonical instruction id (x86 `NN_*`). Numeric and cheap to match;
    /// meaningful only together with [`isa`](Self::isa). This is the trustable machine
    /// identity, of which `mnemonic` is the human projection.
    pub itype: u16,
    /// IDA's canonical mnemonic, resolved at decode.
    pub mnemonic: Box<str>,
    /// Explicit operands in encoding order. Trailing empty operand slots are dropped, so
    /// `ops.len()` is the real operand count.
    pub ops: Vec<Operand>,
    /// Control-flow classification, resolved on the kernel thread.
    pub flow: Flow,
}

impl Instruction {
    /// Every register this instruction references, in operand order: each register operand,
    /// then the base, index, and segment registers of each memory operand. Immediates and
    /// branch targets contribute none.
    pub fn registers(&self) -> impl Iterator<Item = &Register> {
        self.ops.iter().flat_map(|op| {
            let regs: [Option<&Register>; 3] = match &op.kind {
                OperandKind::Register(r) => [Some(r), None, None],
                OperandKind::Mem(m) => [m.base.as_ref(), m.index.as_ref(), m.segment.as_ref()],
                _ => [None, None, None],
            };
            regs.into_iter().flatten()
        })
    }
}

/// One operand of an [`Instruction`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operand {
    /// The operand's original slot index (0-based). Void slots are dropped from
    /// [`ops`](Instruction::ops), so a slot's position in that vector need not equal this; anything
    /// keyed by IDA's per-operand slots correlates through `idx`.
    pub idx: u8,
    /// What the operand refers to.
    pub kind: OperandKind,
    /// The operand's value type.
    pub data_type: DataType,
    /// Whether the instruction reads and/or writes this operand.
    pub access: Access,
}

/// The semantic classification of an operand.
///
/// Closed on purpose: the per-processor decoder maps *every* raw operand type -- including
/// the SIMD/mask register types x86 encodes above the documented range -- into one of
/// these. `#[non_exhaustive]` guards against a future operand *category*, not against
/// unknown raw bytes (those are a [`DecodeError`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperandKind {
    /// A register, of any class (folds every register operand type).
    Register(Register),
    /// A memory reference: `seg:[base + index*scale + disp]`.
    Mem(Mem),
    /// An immediate constant. Signedness is carried by the operand's
    /// [`data_type`](Operand::data_type).
    Imm {
        /// The immediate value.
        value: u64,
    },
    /// A near (intra-segment) code target, resolved to an address.
    Near(Address),
    /// A far (inter-segment) code target.
    Far {
        /// Segment selector.
        selector: u16,
        /// Offset within the target segment.
        offset: u64,
    },
}

/// A structured memory operand: `segment:[base + index*scale + disp]`.
///
/// Decoded from IDA's own REX-aware addressing accessors, so the register components are
/// real, not parsed out of rendered text. Which fields are populated encodes the
/// addressing form (a bare `[disp]` has no `base`/`index`; a RIP-relative reference IDA
/// folded to an absolute address populates `target`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mem {
    /// Base register, if any.
    pub base: Option<Register>,
    /// Index register, if any.
    pub index: Option<Register>,
    /// Index scale multiplier (1, 2, 4, or 8).
    pub scale: u8,
    /// Signed displacement.
    pub disp: i64,
    /// Segment-override register. Currently always `None`: reliably distinguishing an
    /// explicit override from the default segment is deferred, so this is left unpopulated
    /// rather than guessed.
    pub segment: Option<Register>,
    /// The static target address, when IDA resolved the reference to one (direct memory
    /// operands, including RIP-relative that the kernel folded to an absolute).
    pub target: Option<Address>,
}

/// Whether an instruction reads and/or writes a given operand.
///
/// Both bits come from the instruction's *canonical* per-operand feature flags -- a static
/// approximation keyed on the instruction type, not value-accurate dataflow. It does not
/// account for conditional or implicit access; precise use/def analysis is a separate,
/// deferred concern. The two bits are independent (an operand may be neither, either, or
/// both), so they are not collapsed into a single read/write/read-write enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Access {
    /// The instruction reads this operand's value.
    pub read: bool,
    /// The instruction writes this operand.
    pub written: bool,
}

/// Control-flow facts about an instruction, resolved on the kernel thread.
///
/// `is_call`/`is_ret`/`is_indirect` come from the processor's own predicates (richer than
/// the raw feature bits); `stops` reports whether execution falls through to `address + len`.
/// `target` is the static destination of a *direct* branch or call, when one exists --
/// the single fact CFG assembly needs, hoisted here so each [`Instruction`] is a self-contained
/// CFG input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    /// A call instruction.
    pub is_call: bool,
    /// A return instruction.
    pub is_ret: bool,
    /// A branch (conditional or unconditional).
    pub is_jump: bool,
    /// The branch/call target is computed (register or memory), not a static address.
    pub is_indirect: bool,
    /// Execution does not fall through to `address + len`.
    pub stops: bool,
    /// Static destination of a direct branch/call, when known.
    pub target: Option<Address>,
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;
    use crate::address::Address;

    const fn assert_send<T: Send>() {}

    // `Instruction` is owned precisely so it can leave the kernel thread; a later non-`Send` field
    // would defeat that, so pin the guarantee at compile time.
    const _: () = assert_send::<Instruction>();

    fn reg(name: &str) -> Register {
        Register {
            num: 0,
            class: RegisterClass::Gpr,
            width: 8,
            name: name.into(),
        }
    }

    fn op(kind: OperandKind) -> Operand {
        Operand {
            idx: 0,
            kind,
            data_type: DataType::Qword,
            access: Access::default(),
        }
    }

    // `registers()` yields register operands first, then each memory operand's base, index, and
    // segment in that order; immediates and branch targets contribute nothing.
    #[test]
    fn registers_walks_operand_and_memory_components_in_order() {
        let insn = Instruction {
            address: Address::try_new(0x1000).expect("valid"),
            len: 4,
            isa: Isa::X64,
            itype: 0,
            mnemonic: "lea".into(),
            ops: vec![
                op(OperandKind::Register(reg("rax"))),
                op(OperandKind::Mem(Mem {
                    base: Some(reg("rbx")),
                    index: Some(reg("rcx")),
                    scale: 1,
                    disp: 0,
                    segment: None,
                    target: None,
                })),
                op(OperandKind::Imm { value: 5 }),
            ],
            flow: Flow {
                is_call: false,
                is_ret: false,
                is_jump: false,
                is_indirect: false,
                stops: false,
                target: None,
            },
        };
        let names: Vec<&str> = insn.registers().map(|r| r.name.as_ref()).collect();
        assert!(names == ["rax", "rbx", "rcx"]);
    }
}
