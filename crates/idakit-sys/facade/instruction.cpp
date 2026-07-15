// Hand-written Custom bodies for the generated instruction-decode domain (namespace gen).
// decode_insn folds one x86/x64 insn_t into an owned InstructionData shared struct: operands land
// in a right-sized rust::Vec<OperandData>, register slots nest RegisterData by value, and the raw
// result code rides InstructionData::status instead of a return code (the -3/-4 failures carry
// structured payloads a string-only cxx exception could not). reg_class_ids/op_dtype_ids expose the
// facade's discriminants as rust::Vec<uint8_t> for idakit's mirror tests.

#include <pro.h>

#include <ida.hpp>

#include <idp.hpp>
#include <intel.hpp> // x86 operand types + REX-aware SIB accessors (x86_base_reg, ...)
#include <ua.hpp>    // decode_insn, insn_t, op_t

#include "gen_instruction.h"
// The generated bridge header defines the shared structs (full definitions needed to construct them
// below); gen_instruction.h only forward-declares them.
#include "gen_bridge.h"

namespace gen {

namespace {

// idakit RegClass discriminants -- must match the Rust `RegisterClass` enum, pinned by the
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
// Sentinel: a register idakit does not model as an operand class. Never emitted to Rust --
// classify_op turns it into the -4 status so the decoder rejects it loudly.
constexpr uint8_t RC_BAD = 0xFF;

// An absent (base/index) register slot.
RegisterData none_reg() {
  RegisterData r{};
  r.num = REG_NONE;
  r.cls = RC_GPR;
  return r;
}

// Classify an x86 RegNo by its authoritative range (intel.hpp `RegNo`). Used for plain o_reg
// operands and a memory operand's base/index (incl. a VSIB vector index). The GPR case is the tight
// R_ax..R_dil block, not a catch-all residual: a number that lands in no modelled class (flags
// cf..efl, fpctrl/fpstat/fptags, mxcsr, or out of range) returns RC_BAD so classify_op can reject
// it loudly rather than mislabel it GPR.
uint8_t reg_class_of(int r) {
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
  return RC_BAD;
}

// Spell a register from its global RegNo. The wide integer GPRs and the instruction pointer alias
// by width (rax/eax/ax/al, rip/eip/ip), so those go through get_reg_name(reg, width); every other
// register has a single spelling in the processor's own name table, which is width-independent and
// robust where get_reg_name's width match is finicky (st is catalogued at 8 bytes, not its 10-byte
// extent; byte regs resolve only at width 1).
void fill_reg(RegisterData &r, int num, uint8_t cls, int width) {
  r.num = static_cast<uint16_t>(num);
  r.cls = cls;
  r.width = static_cast<uint8_t>(width);
  if ((num >= R_ax && num <= R_r15) || num == R_ip) {
    qstring nm;
    if (get_reg_name(&nm, num, width > 0 ? static_cast<size_t>(width) : 8) > 0)
      r.name = to_rust_string(nm);
  } else if (num >= 0 && num < PH.regs_num && PH.reg_names[num] != nullptr) {
    r.name = to_rust_string(PH.reg_names[num]);
  }
}

// Name a control/debug/test register. These carry a class-relative index in op.reg and have no
// global RegNo or name-table entry: their text exists only in IDA's out routine, so reconstruct the
// canonical "cr2"/"dr4"/"tr7" spelling from the index. `prefix` is the class letter ('c'/'d'/'t');
// cr8 (only) takes a "d" suffix via the cr_suff flag ("cr8d").
void fill_special_reg(RegisterData &r, char prefix, int index, uint8_t cls, bool d_suffix) {
  r.num = static_cast<uint16_t>(index);
  r.cls = cls;
  r.width = 0;
  char buf[16];
  qsnprintf(buf, sizeof(buf), "%cr%d%s", prefix, index, d_suffix ? "d" : "");
  r.name = to_rust_string(buf);
}

// A memory operand's effective address width (for naming its base/index registers).
int addr_width(const insn_t &insn) { return ad64(insn) ? 8 : (ad32(insn) ? 4 : 2); }

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
}

// Fold one raw op_t into a semantic OperandData. Returns 0, -3 for a raw operand type this decoder
// does not model (unreachable for x86, which enumerates all of its operand types), or -4 for an
// o_reg whose register lands in no modelled class (reg_class_of -> RC_BAD).
// `dst` arrives value-initialized ({}), so the fields that stay zero for a given operand (value,
// sel, scale, disp, and addr for a non-mem/non-near operand) are already zero here; only the
// register slots need the REG_NONE sentinel that a zeroed RegisterData would not carry.
int classify_op(const insn_t &insn, const op_t &op, int idx, OperandData &dst) {
  dst.idx = static_cast<uint8_t>(idx);
  dst.data_type = op.dtype;
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
  // Control/debug/test registers have no global RegNo -- synthesize their canonical spelling.
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
  for (int i = 0; i < UA_MAXOP && static_cast<int>(ops.size()) < static_cast<int>(MAX_OPS); i++) {
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
