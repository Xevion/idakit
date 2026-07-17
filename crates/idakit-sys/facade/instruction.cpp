// Hand-written Custom bodies for the generated instruction-decode domain (namespace gen).
// decode_insn folds one x86/x64 insn_t into an owned InstructionData shared struct. Unlike the rest
// of the generated bridges, failure rides InstructionData::status rather than a thrown exception,
// since the -3/-4 cases need to carry a structured operand index and raw code that a string-only
// cxx exception cannot. reg_class_ids/op_dtype_ids expose the facade's own discriminants so idakit
// can pin its RegisterClass/DataType mirrors to this SDK build in a test.

#include <pro.h>

#include <ida.hpp>

#include <idp.hpp>
#include <intel.hpp> // x86 operand types + REX-aware SIB accessors (x86_base_reg, ...)
#include <lines.hpp> // generate_disasm_line (read IDA's rendered broadcast decoration)
#include <ua.hpp>    // decode_insn, insn_t, op_t

#include "gen_instruction.h"
// The generated bridge header defines the shared structs (full definitions needed to construct them
// below); gen_instruction.h only forward-declares them.
#include "gen_bridge.h"

namespace gen {

namespace {

// idakit RegClass discriminants, must match the Rust `RegisterClass` enum, pinned by the
// alignment test that reg_class_ids feeds.
constexpr uint8_t RC_GPR = 0;
constexpr uint8_t RC_SEGMENT = 1;
constexpr uint8_t RC_XMM = 2;
constexpr uint8_t RC_YMM = 3;
constexpr uint8_t RC_ZMM = 4;
constexpr uint8_t RC_MASK = 5;
constexpr uint8_t RC_ST = 6;
constexpr uint8_t RC_MMX = 7;
constexpr uint8_t RC_CONTROL = 8;
constexpr uint8_t RC_DEBUG = 9;
constexpr uint8_t RC_TEST = 10;
constexpr uint8_t RC_IP = 11;
constexpr uint8_t RC_BND = 12;
// Sentinel: a register idakit does not model as an operand class. Never emitted to Rust;
// classify_op turns it into the -4 status so the decoder rejects it loudly.
constexpr uint8_t RC_BAD = 0xFF;

// An absent (base/index) register slot.
RegisterData none_reg() {
  RegisterData r{};
  r.num = REG_NONE;
  r.cls = RC_GPR;
  return r;
}

// Classify an x86 RegNo into idakit's RegisterClass by its authoritative range (intel.hpp `RegNo`).
// Used for plain o_reg operands and a memory operand's base/index, including a VSIB vector index.
uint8_t reg_class_of(int r) {
  // Tight R_ax..R_dil block, not a catch-all residual.
  if (r >= R_ax && r <= R_dil)
    return RC_GPR;
  if (r == R_ip)
    return RC_IP;
  if (is_segreg(r))
    return RC_SEGMENT;
  if (r >= R_st0 && r <= R_st7)
    return RC_ST;
  if (r >= R_mm0 && r <= R_mm7)
    return RC_MMX;
  if ((r >= R_xmm0 && r <= R_xmm15) || (r >= R_xmm16 && r <= R_xmm31))
    return RC_XMM;
  if ((r >= R_ymm0 && r <= R_ymm15) || (r >= R_ymm16 && r <= R_ymm31))
    return RC_YMM;
  if (r >= R_zmm0 && r <= R_zmm31)
    return RC_ZMM;
  if (r >= R_k0 && r <= R_k7)
    return RC_MASK;
  if (r >= R_bnd0 && r <= R_bnd3)
    return RC_BND;
  // No modelled class: flags cf..efl, fpctrl/fpstat/fptags, mxcsr, or out of range. Reject rather
  // than mislabel it GPR.
  return RC_BAD;
}

// Spell a register from its global RegNo and width into RegisterData.
void fill_reg(RegisterData &r, int num, uint8_t cls, int width) {
  r.num = static_cast<uint16_t>(num);
  r.cls = cls;
  r.width = static_cast<uint8_t>(width);
  if ((num >= R_ax && num <= R_r15) || num == R_ip) {
    // The wide integer GPRs and the instruction pointer alias by width (rax/eax/ax/al, rip/eip/ip),
    // so only these need get_reg_name(reg, width) rather than a fixed spelling.
    qstring nm;
    if (get_reg_name(&nm, num, width > 0 ? static_cast<size_t>(width) : 8) > 0)
      r.name = to_rust_string(nm);
  } else if (num >= 0 && num < PH.regs_num && PH.reg_names[num] != nullptr) {
    // Every other register has one spelling in the processor's own name table, width-independent
    // and robust where get_reg_name's width match is finicky (st is catalogued at 8 bytes, not its
    // 10-byte extent; byte regs resolve only at width 1).
    r.name = to_rust_string(PH.reg_names[num]);
  }
}

// Synthesize a control/debug/test register's name from its class-relative index. These have no
// global RegNo or name-table entry; their text exists only in IDA's out routine.
void fill_special_reg(RegisterData &r, char prefix, int index, uint8_t cls, bool d_suffix) {
  r.num = static_cast<uint16_t>(index);
  r.cls = cls;
  r.width = 0;
  char buf[16];
  // prefix is the class letter ('c'/'d'/'t'); cr8 alone takes a "d" suffix ("cr8d").
  qsnprintf(buf, sizeof(buf), "%cr%d%s", prefix, index, d_suffix ? "d" : "");
  r.name = to_rust_string(buf);
}

// A memory operand's effective address width (for naming its base/index registers).
int addr_width(const insn_t &insn) { return ad64(insn) ? 8 : (ad32(insn) ? 4 : 2); }

// Fill a memory operand's base/index registers, scale, displacement, and resolved address.
void fill_mem(const insn_t &insn, const op_t &op, OperandData &dst) {
  int aw = addr_width(insn);
  int base = x86_base_reg(insn, op);
  int index = x86_index_reg(insn, op);
  if (base != R_none)
    fill_reg(dst.base, base, reg_class_of(base), aw);
  if (index != R_none)
    fill_reg(dst.index, index, reg_class_of(index), aw);
  dst.scale = static_cast<uint8_t>(1 << x86_scale(op));
  // o_phrase is [reg(+reg)] with no displacement; o_mem/o_displ keep it in op.addr.
  dst.disp = op.type == o_phrase ? 0 : static_cast<int64_t>(op.addr);
  // o_mem resolves to a static address (incl. RIP-relative IDA already folded).
  dst.addr = op.type == o_mem ? static_cast<uint64_t>(op.addr) : static_cast<uint64_t>(BADADDR);
  // EVEX embedded broadcast: with EVEX.b and a memory operand, one element is read and fanned out
  // to N lanes. The factor N is vector width / element width, but neither is cleanly available:
  // op.dtype is the whole vector, and element width depends on the instruction (2 bytes for fp16,
  // and mixed for int/float converts), so no bit-level formula gets every form right. IDA already
  // computes N and renders it as `{1toN}`, so read it back from the rendered line (an EVEX.b
  // memory form has exactly one broadcast operand, so the line's single `{1to` is this one).
  // print_operand does not surface the decoration headless; generate_disasm_line does.
  if (evexpr(insn) && (insn.evex_flags & EVEX_b) != 0) {
    qstring line;
    if (generate_disasm_line(&line, insn.ea, GENDSM_REMOVE_TAGS)) {
      size_t at = line.find("{1to");
      if (at != qstring::npos) {
        uint32_t factor = 0;
        for (size_t i = at + 4; i < line.length() && qisdigit(line[i]); i++)
          factor = factor * 10 + static_cast<uint32_t>(line[i] - '0');
        dst.broadcast = static_cast<uint8_t>(factor);
      }
    }
  }
}

// Whether an x86 EVEX instruction supports embedded static rounding-control (`{r?-sae}`), as
// opposed to only suppress-all-exceptions (`{sae}`). The SDK exposes no such predicate, so this
// mirrors the Intel SDM's rounding-capable set: FP arithmetic, the FMA family, and the rounding
// conversions. A miss degrades to SAE-only, which is still true (EVEX.b always suppresses
// exceptions); it loses only the rounding mode.
bool is_rounding_capable(uint16_t itype) {
  switch (itype) {
  // Arithmetic (ps/pd/ss/sd).
  case NN_vaddps:
  case NN_vaddpd:
  case NN_vaddss:
  case NN_vaddsd:
  case NN_vsubps:
  case NN_vsubpd:
  case NN_vsubss:
  case NN_vsubsd:
  case NN_vmulps:
  case NN_vmulpd:
  case NN_vmulss:
  case NN_vmulsd:
  case NN_vdivps:
  case NN_vdivpd:
  case NN_vdivss:
  case NN_vdivsd:
  case NN_vsqrtps:
  case NN_vsqrtpd:
  case NN_vsqrtss:
  case NN_vsqrtsd:
  case NN_vscalefps:
  case NN_vscalefpd:
  case NN_vscalefss:
  case NN_vscalefsd:
  // Fused multiply-add family (132/213/231 forms, ps/pd/ss/sd).
  case NN_vfmadd132ps:
  case NN_vfmadd132pd:
  case NN_vfmadd132ss:
  case NN_vfmadd132sd:
  case NN_vfmadd213ps:
  case NN_vfmadd213pd:
  case NN_vfmadd213ss:
  case NN_vfmadd213sd:
  case NN_vfmadd231ps:
  case NN_vfmadd231pd:
  case NN_vfmadd231ss:
  case NN_vfmadd231sd:
  case NN_vfmsub132ps:
  case NN_vfmsub132pd:
  case NN_vfmsub132ss:
  case NN_vfmsub132sd:
  case NN_vfmsub213ps:
  case NN_vfmsub213pd:
  case NN_vfmsub213ss:
  case NN_vfmsub213sd:
  case NN_vfmsub231ps:
  case NN_vfmsub231pd:
  case NN_vfmsub231ss:
  case NN_vfmsub231sd:
  case NN_vfnmadd132ps:
  case NN_vfnmadd132pd:
  case NN_vfnmadd132ss:
  case NN_vfnmadd132sd:
  case NN_vfnmadd213ps:
  case NN_vfnmadd213pd:
  case NN_vfnmadd213ss:
  case NN_vfnmadd213sd:
  case NN_vfnmadd231ps:
  case NN_vfnmadd231pd:
  case NN_vfnmadd231ss:
  case NN_vfnmadd231sd:
  case NN_vfnmsub132ps:
  case NN_vfnmsub132pd:
  case NN_vfnmsub132ss:
  case NN_vfnmsub132sd:
  case NN_vfnmsub213ps:
  case NN_vfnmsub213pd:
  case NN_vfnmsub213ss:
  case NN_vfnmsub213sd:
  case NN_vfnmsub231ps:
  case NN_vfnmsub231pd:
  case NN_vfnmsub231ss:
  case NN_vfnmsub231sd:
  // Fused multiply-add/subtract interleaved (ps/pd only).
  case NN_vfmaddsub132ps:
  case NN_vfmaddsub132pd:
  case NN_vfmaddsub213ps:
  case NN_vfmaddsub213pd:
  case NN_vfmaddsub231ps:
  case NN_vfmaddsub231pd:
  case NN_vfmsubadd132ps:
  case NN_vfmsubadd132pd:
  case NN_vfmsubadd213ps:
  case NN_vfmsubadd213pd:
  case NN_vfmsubadd231ps:
  case NN_vfmsubadd231pd:
  // Rounding conversions (int<->float and float-narrowing that round; truncating `vcvtt*` and
  // exact widenings are excluded, since they carry no rounding mode).
  case NN_vcvtdq2ps:
  case NN_vcvtudq2ps:
  case NN_vcvtqq2ps:
  case NN_vcvtqq2pd:
  case NN_vcvtuqq2ps:
  case NN_vcvtuqq2pd:
  case NN_vcvtps2dq:
  case NN_vcvtps2udq:
  case NN_vcvtps2qq:
  case NN_vcvtps2uqq:
  case NN_vcvtpd2dq:
  case NN_vcvtpd2udq:
  case NN_vcvtpd2qq:
  case NN_vcvtpd2uqq:
  case NN_vcvtpd2ps:
  case NN_vcvtsd2ss:
  case NN_vcvtsd2si:
  case NN_vcvtsd2usi:
  case NN_vcvtss2si:
  case NN_vcvtss2usi:
  case NN_vcvtsi2ss:
  case NN_vcvtsi2sd:
  case NN_vcvtusi2ss:
  case NN_vcvtusi2sd:
    return true;
  default:
    return false;
  }
}

// Fold one raw op_t into a semantic OperandData. Returns 0, -3 for a raw operand type this decoder
// does not model (unreachable for x86, which enumerates all of its operand types), or -4 for an
// o_reg whose register lands in no modelled class (reg_class_of -> RC_BAD).
int classify_op(const insn_t &insn, const op_t &op, int idx, OperandData &dst) {
  dst.idx = static_cast<uint8_t>(idx);
  dst.offb = static_cast<uint8_t>(op.offb);
  dst.data_type = op.dtype;
  // dst arrives value-initialized, so every field that stays zero for this operand already is;
  // only the register slots need the REG_NONE sentinel a zeroed RegisterData wouldn't carry.
  dst.reg = none_reg();
  dst.base = none_reg();
  dst.index = none_reg();
  switch (op.type) {
  case o_reg: {
    uint8_t rc = reg_class_of(op.reg);
    if (rc == RC_BAD)
      return -4;
    dst.kind = OP_REG;
    fill_reg(dst.reg, op.reg, rc, static_cast<int>(get_dtype_size(op.dtype)));
    return 0;
  }
  // Register operands whose op.reg is a class-relative index into a global RegNo block: map it to
  // the RegNo so fill_reg names it from the processor table. On x86-64 only o_fpreg actually occurs
  // here (SIMD registers arrive as plain o_reg); the others are kept so a future/32-bit encoding
  // does not fall through to the -3 reject.
  case o_fpreg:
    dst.kind = OP_REG;
    fill_reg(dst.reg, R_st0 + op.reg, RC_ST, static_cast<int>(get_dtype_size(op.dtype)));
    return 0;
  case o_mmxreg:
    dst.kind = OP_REG;
    fill_reg(dst.reg, R_mm0 + op.reg, RC_MMX, static_cast<int>(get_dtype_size(op.dtype)));
    return 0;
  case o_xmmreg:
    dst.kind = OP_REG;
    fill_reg(dst.reg, R_xmm0 + op.reg, RC_XMM, static_cast<int>(get_dtype_size(op.dtype)));
    return 0;
  case o_ymmreg:
    dst.kind = OP_REG;
    fill_reg(dst.reg, R_ymm0 + op.reg, RC_YMM, static_cast<int>(get_dtype_size(op.dtype)));
    return 0;
  case o_zmmreg:
    dst.kind = OP_REG;
    fill_reg(dst.reg, R_zmm0 + op.reg, RC_ZMM, static_cast<int>(get_dtype_size(op.dtype)));
    return 0;
  case o_kreg:
    dst.kind = OP_REG;
    fill_reg(dst.reg, R_k0 + op.reg, RC_MASK, static_cast<int>(get_dtype_size(op.dtype)));
    return 0;
  // Control/debug/test registers have no global RegNo, so synthesize their canonical spelling.
  case o_crreg:
    dst.kind = OP_REG;
    fill_special_reg(dst.reg, 'c', op.reg, RC_CONTROL, op.specflag1 != 0);
    return 0;
  case o_dbreg:
    dst.kind = OP_REG;
    fill_special_reg(dst.reg, 'd', op.reg, RC_DEBUG, false);
    return 0;
  case o_trreg:
    dst.kind = OP_REG;
    fill_special_reg(dst.reg, 't', op.reg, RC_TEST, false);
    return 0;
  case o_mem:
  case o_phrase:
  case o_displ:
    dst.kind = OP_MEM;
    fill_mem(insn, op, dst);
    return 0;
  case o_imm:
    dst.kind = OP_IMM;
    dst.value = static_cast<uint64_t>(op.value);
    return 0;
  case o_near:
    dst.kind = OP_NEAR;
    dst.addr = static_cast<uint64_t>(op.addr);
    return 0;
  case o_far:
    dst.kind = OP_FAR;
    dst.value = static_cast<uint64_t>(op.addr);
    dst.sel = static_cast<uint16_t>(op.segsel);
    return 0;
  default:
    return -3;
  }
}

} // namespace

// Decode the instruction at addr into an owned InstructionData; status carries decode or
// classification failure instead of a thrown exception.
InstructionData decode_insn(uint64_t addr) {
  // Value-initialized: status/err_op/err_optype and every scalar start at 0 (so the success path
  // reports status 0 without an explicit set), mnemonic empty, ops empty.
  InstructionData out{};
  out.address = addr;
  out.target = static_cast<uint64_t>(BADADDR);

  // Only the x86 module's operand encoding is modelled; refuse other processors loudly rather than
  // fabricate operands from a foreign op_t layout.
  if (PH.id != PLFM_386) {
    out.status = -2;
    return out;
  }

  insn_t insn;
  if (::decode_insn(&insn, static_cast<ea_t>(addr)) <= 0) {
    out.status = -1;
    return out;
  }

  out.len = static_cast<uint8_t>(insn.size);
  out.isa = inf_is_64bit() ? 1 : 0;
  out.itype = insn.itype;
  const char *mnem = insn.get_canon_mnem(PH);
  if (mnem != nullptr)
    out.mnemonic = to_rust_string(mnem);

  uint32 feature = insn.get_canon_feature(PH);
  ea_t tgt = BADADDR;
  rust::Vec<OperandData> ops;
  // Stop at PROC_MAXOP (x86's real operand count), not UA_MAXOP: slot 5 (Op6) is not an operand
  // but the EVEX opmask/extension storage, lifted to InstructionData::mask below.
  for (int i = 0; i < PROC_MAXOP && static_cast<int>(ops.size()) < static_cast<int>(MAX_OPS); i++) {
    const op_t &op = insn.ops[i];
    if (op.type == o_void)
      continue;
    OperandData dst{};
    int rc = classify_op(insn, op, i, dst);
    if (rc != 0) {
      out.status = rc;
      out.err_op = static_cast<uint8_t>(i);
      // -3 reports the raw operand type; -4 reports the unmodelled register number.
      out.err_optype = rc == -4 ? static_cast<uint8_t>(op.reg) : static_cast<uint8_t>(op.type);
      return out;
    }
    dst.access = (has_cf_use(feature, i) ? 1 : 0) | (has_cf_chg(feature, i) ? 2 : 0);
    if ((op.type == o_near || op.type == o_far) && tgt == BADADDR)
      tgt = op.addr;
    ops.push_back(std::move(dst));
  }
  out.nops = static_cast<uint8_t>(ops.size());

  // EVEX modifiers (x86 EVEX; Op6 = ops[5] carries the opmask, evex_flags extends insn_t). The
  // opmask is deliberately not an entry in `ops`; embedded broadcast rode along per-operand in
  // fill_mem above. mask defaults to the absent sentinel since InstructionData value-inits its
  // RegisterData to register 0, a real register, not REG_NONE.
  out.mask = none_reg();
  if (evexpr(insn)) {
    const op_t &op6 = insn.ops[5];
    // k1..k7 select a mask; k0 encodes "no mask" and IDA leaves the slot void, never reaching here.
    if (op6.type == o_reg && op6.reg > R_k0 && op6.reg <= R_k7)
      fill_reg(out.mask, op6.reg, RC_MASK, static_cast<int>(get_dtype_size(op6.dtype)));
    if ((insn.evex_flags & EVEX_z) != 0)
      out.zeroing = 1;
    if ((insn.evex_flags & EVEX_b) != 0) {
      bool has_mem = false;
      for (int i = 0; i < PROC_MAXOP; i++) {
        optype_t ot = insn.ops[i].type;
        if (ot == o_mem || ot == o_phrase || ot == o_displ) {
          has_mem = true;
          break;
        }
      }
      // A memory operand makes EVEX.b broadcast (already recorded in fill_mem); register-only makes
      // it FP control. EVEX.b always suppresses exceptions, so a non-rounding op is SAE-only; the
      // rounding mode, when the op rounds, is EVEX.L'L = (EVEX_L << 1) | VEX_L.
      if (!has_mem) {
        if (is_rounding_capable(insn.itype)) {
          out.fp_control = FPC_ROUNDING;
          out.round_mode = static_cast<uint8_t>(((insn.evex_flags & EVEX_L) != 0 ? 2 : 0) |
                                                ((insn.rex & VEX_L) != 0 ? 1 : 0));
        } else {
          out.fp_control = FPC_SAE;
        }
      }
    }
  }

  bool call = is_call_insn(insn);
  bool ret = is_ret_insn(insn);
  bool ijmp = is_indirect_jump_insn(insn);
  bool jcc = insn_jcc(insn);
  bool stops = (feature & CF_STOP) != 0;
  bool has_tgt = tgt != BADADDR;
  // A direct unconditional jump has a static code target, stops sequential flow, and is neither a
  // call nor a ret; this catches `jmp` (incl. tail calls) without hardcoding its itype.
  bool is_jump = jcc || ijmp || (has_tgt && stops && !call && !ret);
  bool indirect = (call || is_jump) && !has_tgt;

  uint8_t flow = 0;
  if (call)
    flow |= FLOW_CALL;
  if (ret)
    flow |= FLOW_RET;
  if (is_jump)
    flow |= FLOW_JUMP;
  if (indirect)
    flow |= FLOW_INDIRECT;
  if (stops)
    flow |= FLOW_STOPS;
  out.flow = flow;
  out.target = has_tgt ? static_cast<uint64_t>(tgt) : static_cast<uint64_t>(BADADDR);
  out.ops = std::move(ops);
  return out;
}

// Alignment sources. These expose the facade's own discriminants so idakit can pin its
// hand-maintained mirrors to this SDK build in a test, catching drift between the two sides.

// idakit RegisterClass codes, written by position in the Rust enum's discriminant order so a drift
// between a C++ constant and its Rust variant shows up as out[i] != i in the test.
rust::Vec<uint8_t> reg_class_ids() {
  rust::Vec<uint8_t> out;
  for (uint8_t c : {RC_GPR, RC_SEGMENT, RC_XMM, RC_YMM, RC_ZMM, RC_MASK, RC_ST, RC_MMX, RC_CONTROL,
                    RC_DEBUG, RC_TEST, RC_IP, RC_BND})
    out.push_back(c);
  return out;
}

// This SDK's op_dtype_t values (ua.hpp dt_*), in idakit DataType's discriminant order.
rust::Vec<uint8_t> op_dtype_ids() {
  rust::Vec<uint8_t> out;
  for (uint8_t d : {dt_byte, dt_word, dt_dword, dt_float, dt_double, dt_tbyte, dt_packreal,
                    dt_qword, dt_byte16, dt_code, dt_void, dt_fword, dt_bitfild, dt_string,
                    dt_unicode, dt_ldbl, dt_byte32, dt_byte64, dt_half})
    out.push_back(d);
  return out;
}

} // namespace gen
