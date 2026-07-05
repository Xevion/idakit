// idakit facade: x86/x64 instruction decode -- fold raw op_t operands into semantic kinds
// with resolved registers and control-flow facts.

#include <pro.h>

#include <ida.hpp>

#include <idp.hpp>
#include <intel.hpp> // x86 operand types + REX-aware SIB accessors (x86_base_reg, ...)
#include <ua.hpp>    // decode_insn, insn_t, op_t

#include <cstring>

#include "idakit_facade.h"

// idakit RegClass discriminants -- must match the Rust `RegisterClass` enum, pinned by an
// alignment test (idakit_reg_class_ids below feeds it).
#define RC_GPR 0
#define RC_SEGMENT 1
#define RC_XMM 2
#define RC_YMM 3
#define RC_ZMM 4
#define RC_MASK 5
#define RC_ST 6
#define RC_MMX 7
#define RC_CONTROL 8
#define RC_DEBUG 9
#define RC_TEST 10
#define RC_IP 11
#define RC_BND 12
// Sentinel: a register idakit does not model as an operand class. Never emitted to Rust --
// classify_op turns it into the -4 return so the decoder rejects it loudly.
#define RC_BAD 0xFF

namespace {

// Classify an x86 RegNo by its authoritative range (intel.hpp `RegNo`). Used for plain
// o_reg operands and a memory operand's base/index (incl. a VSIB vector index). The GPR
// case is the tight R_ax..R_dil block, not a catch-all residual: a number that lands in no
// modelled class (flags cf..efl, fpctrl/fpstat/fptags, mxcsr, or out of range) returns
// RC_BAD so classify_op can reject it loudly rather than mislabel it GPR.
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

// Spell a register from its global RegNo. The wide integer GPRs and the instruction pointer
// alias by width (rax/eax/ax/al, rip/eip/ip), so those go through get_reg_name(reg, width);
// every other register has a single spelling in the processor's own name table, which is
// width-independent and robust where get_reg_name's width match is finicky (st is catalogued
// at 8 bytes, not its 10-byte extent; byte regs resolve only at width 1).
void fill_reg(idakit_reg_t *r, int num, uint8_t cls, int width) {
  r->num = (uint16_t)num;
  r->cls = cls;
  r->width = (uint8_t)width;
  r->name[0] = 0;
  if ((num >= R_ax && num <= R_r15) || num == R_ip) {
    qstring nm;
    if (get_reg_name(&nm, num, width > 0 ? (size_t)width : 8) > 0)
      qstrncpy(r->name, nm.c_str(), sizeof(r->name));
  } else if (num >= 0 && num < PH.regs_num && PH.reg_names[num] != nullptr) {
    qstrncpy(r->name, PH.reg_names[num], sizeof(r->name));
  }
}

// Name a control/debug/test register. These carry a class-relative index in op.reg and have
// no global RegNo or name-table entry: their text exists only in IDA's out routine, so
// reconstruct the canonical "cr2"/"dr4"/"tr7" spelling from the index. `prefix` is the class
// letter ('c'/'d'/'t'); cr8 (only) takes a "d" suffix via the cr_suff flag ("cr8d").
void fill_special_reg(idakit_reg_t *r, char prefix, int index, uint8_t cls, bool d_suffix) {
  r->num = (uint16_t)index;
  r->cls = cls;
  r->width = 0;
  qsnprintf(r->name, sizeof(r->name), "%cr%d%s", prefix, index, d_suffix ? "d" : "");
}

void clear_reg(idakit_reg_t *r) {
  r->num = IDAKIT_REG_NONE;
  r->cls = RC_GPR;
  r->width = 0;
  r->name[0] = 0;
}

// A memory operand's effective address width (for naming its base/index registers).
int addr_width(const insn_t &insn) { return ad64(insn) ? 8 : (ad32(insn) ? 4 : 2); }

void fill_mem(const insn_t &insn, const op_t &op, idakit_op_t *dst) {
  int aw = addr_width(insn);
  int base = x86_base_reg(insn, op);
  int index = x86_index_reg(insn, op);
  if (base != R_none)
    fill_reg(&dst->base, base, reg_class_of(base), aw);
  else
    clear_reg(&dst->base);
  if (index != R_none)
    fill_reg(&dst->index, index, reg_class_of(index), aw);
  else
    clear_reg(&dst->index);
  dst->scale = (uint8_t)(1 << x86_scale(op));
  // o_phrase is [reg(+reg)] with no displacement; o_mem/o_displ keep it in op.addr.
  dst->disp = op.type == o_phrase ? 0 : (int64_t)op.addr;
  // o_mem resolves to a static address (incl. RIP-relative IDA already folded).
  dst->addr = op.type == o_mem ? (uint64_t)op.addr : (uint64_t)BADADDR;
}

// Fold one raw op_t into a semantic idakit_op_t. Returns 0, -3 for a raw operand type this
// decoder does not model (unreachable for x86, which enumerates all of its operand types),
// or -4 for an o_reg whose register lands in no modelled class (reg_class_of -> RC_BAD).
int classify_op(const insn_t &insn, const op_t &op, int idx, idakit_op_t *dst) {
  memset(dst, 0, sizeof(*dst));
  clear_reg(&dst->reg);
  clear_reg(&dst->base);
  clear_reg(&dst->index);
  dst->idx = (uint8_t)idx;
  dst->dtype = op.dtype;
  switch (op.type) {
  case o_reg: {
    uint8_t rc = reg_class_of(op.reg);
    if (rc == RC_BAD)
      return -4;
    dst->kind = IDAKIT_OP_REG;
    fill_reg(&dst->reg, op.reg, rc, (int)get_dtype_size(op.dtype));
    return 0;
  }
  // Register operands whose op.reg is a class-relative index into a global RegNo block: map
  // it to the RegNo so fill_reg names it from the processor table. On x86-64 only o_fpreg
  // actually occurs here (SIMD registers arrive as plain o_reg); the others are kept so a
  // future/32-bit encoding does not fall through to the -3 reject.
  case o_fpreg:
    dst->kind = IDAKIT_OP_REG;
    fill_reg(&dst->reg, R_st0 + op.reg, RC_ST, (int)get_dtype_size(op.dtype));
    return 0;
  case o_mmxreg:
    dst->kind = IDAKIT_OP_REG;
    fill_reg(&dst->reg, R_mm0 + op.reg, RC_MMX, (int)get_dtype_size(op.dtype));
    return 0;
  case o_xmmreg:
    dst->kind = IDAKIT_OP_REG;
    fill_reg(&dst->reg, R_xmm0 + op.reg, RC_XMM, (int)get_dtype_size(op.dtype));
    return 0;
  case o_ymmreg:
    dst->kind = IDAKIT_OP_REG;
    fill_reg(&dst->reg, R_ymm0 + op.reg, RC_YMM, (int)get_dtype_size(op.dtype));
    return 0;
  case o_zmmreg:
    dst->kind = IDAKIT_OP_REG;
    fill_reg(&dst->reg, R_zmm0 + op.reg, RC_ZMM, (int)get_dtype_size(op.dtype));
    return 0;
  case o_kreg:
    dst->kind = IDAKIT_OP_REG;
    fill_reg(&dst->reg, R_k0 + op.reg, RC_MASK, (int)get_dtype_size(op.dtype));
    return 0;
  // Control/debug/test registers have no global RegNo -- synthesize their canonical spelling.
  case o_crreg:
    dst->kind = IDAKIT_OP_REG;
    fill_special_reg(&dst->reg, 'c', op.reg, RC_CONTROL, op.specflag1 != 0);
    return 0;
  case o_dbreg:
    dst->kind = IDAKIT_OP_REG;
    fill_special_reg(&dst->reg, 'd', op.reg, RC_DEBUG, false);
    return 0;
  case o_trreg:
    dst->kind = IDAKIT_OP_REG;
    fill_special_reg(&dst->reg, 't', op.reg, RC_TEST, false);
    return 0;
  case o_mem:
  case o_phrase:
  case o_displ:
    dst->kind = IDAKIT_OP_MEM;
    fill_mem(insn, op, dst);
    return 0;
  case o_imm:
    dst->kind = IDAKIT_OP_IMM;
    dst->value = (uint64_t)op.value;
    return 0;
  case o_near:
    dst->kind = IDAKIT_OP_NEAR;
    dst->addr = (uint64_t)op.addr;
    return 0;
  case o_far:
    dst->kind = IDAKIT_OP_FAR;
    dst->value = (uint64_t)op.addr;
    dst->sel = (uint16_t)op.segsel;
    return 0;
  default:
    return -3;
  }
}

} // namespace

extern "C" int idakit_decode_insn(idakit_ea_t ea, idakit_insn_t *out) {
  try {
    memset(out, 0, sizeof(*out));
    out->ea = ea;
    out->target = (uint64_t)BADADDR;

    // Only the x86 module's operand encoding is modelled; refuse other processors loudly
    // rather than fabricate operands from a foreign op_t layout.
    if (PH.id != PLFM_386)
      return -2;

    insn_t insn;
    if (decode_insn(&insn, (ea_t)ea) <= 0)
      return -1;

    out->len = (uint8_t)insn.size;
    out->isa = inf_is_64bit() ? 1 : 0;
    out->itype = insn.itype;
    const char *mnem = insn.get_canon_mnem(PH);
    if (mnem != nullptr)
      qstrncpy(out->mnemonic, mnem, sizeof(out->mnemonic));

    uint32 feature = insn.get_canon_feature(PH);
    ea_t tgt = BADADDR;
    int nops = 0;
    for (int i = 0; i < UA_MAXOP && nops < IDAKIT_MAX_OPS; i++) {
      const op_t &op = insn.ops[i];
      if (op.type == o_void)
        continue;
      idakit_op_t *dst = &out->ops[nops];
      int rc = classify_op(insn, op, i, dst);
      if (rc != 0) {
        out->err_op = (uint8_t)i;
        // -3 reports the raw operand type; -4 reports the unmodelled register number.
        out->err_optype = rc == -4 ? (uint8_t)op.reg : (uint8_t)op.type;
        return rc;
      }
      dst->access = (has_cf_use(feature, i) ? 1 : 0) | (has_cf_chg(feature, i) ? 2 : 0);
      if ((op.type == o_near || op.type == o_far) && tgt == BADADDR)
        tgt = op.addr;
      nops++;
    }
    out->nops = (uint8_t)nops;

    bool call = is_call_insn(insn);
    bool ret = is_ret_insn(insn);
    bool ijmp = is_indirect_jump_insn(insn);
    bool jcc = insn_jcc(insn);
    bool stops = (feature & CF_STOP) != 0;
    bool has_tgt = tgt != BADADDR;
    // A direct unconditional jump has a static code target, stops sequential flow, and is
    // neither a call nor a ret -- this catches `jmp` (incl. tail calls) without hardcoding
    // its itype.
    bool is_jump = jcc || ijmp || (has_tgt && stops && !call && !ret);
    bool indirect = (call || is_jump) && !has_tgt;

    uint8_t flow = 0;
    if (call)
      flow |= IDAKIT_FLOW_CALL;
    if (ret)
      flow |= IDAKIT_FLOW_RET;
    if (is_jump)
      flow |= IDAKIT_FLOW_JUMP;
    if (indirect)
      flow |= IDAKIT_FLOW_INDIRECT;
    if (stops)
      flow |= IDAKIT_FLOW_STOPS;
    out->flow = flow;
    out->target = has_tgt ? (uint64_t)tgt : (uint64_t)BADADDR;
    return 0;
  } catch (...) {
    std::abort();
  }
}

// Alignment sources. These expose the facade's own discriminants so idakit can pin its
// hand-maintained mirrors to this SDK build in a test, catching drift between the two sides.

// idakit RegisterClass codes, written by position in the Rust enum's discriminant order so a
// drift between a C++ #define and its Rust variant shows up as out[i] != i in the test.
extern "C" void idakit_reg_class_ids(uint8_t *out) {
  out[0] = RC_GPR;
  out[1] = RC_SEGMENT;
  out[2] = RC_XMM;
  out[3] = RC_YMM;
  out[4] = RC_ZMM;
  out[5] = RC_MASK;
  out[6] = RC_ST;
  out[7] = RC_MMX;
  out[8] = RC_CONTROL;
  out[9] = RC_DEBUG;
  out[10] = RC_TEST;
  out[11] = RC_IP;
  out[12] = RC_BND;
}

// This SDK's op_dtype_t values (ua.hpp dt_*), in idakit DataType's discriminant order.
extern "C" void idakit_op_dtype_ids(uint8_t *out) {
  out[0] = dt_byte;
  out[1] = dt_word;
  out[2] = dt_dword;
  out[3] = dt_float;
  out[4] = dt_double;
  out[5] = dt_tbyte;
  out[6] = dt_packreal;
  out[7] = dt_qword;
  out[8] = dt_byte16;
  out[9] = dt_code;
  out[10] = dt_void;
  out[11] = dt_fword;
  out[12] = dt_bitfild;
  out[13] = dt_string;
  out[14] = dt_unicode;
  out[15] = dt_ldbl;
  out[16] = dt_byte32;
  out[17] = dt_byte64;
  out[18] = dt_half;
}
