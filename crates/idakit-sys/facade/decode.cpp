// idakit facade: x86/x64 instruction decode -- fold raw op_t operands into semantic kinds
// with resolved registers and control-flow facts.

#include <pro.h>

#include <ida.hpp>

#include <idp.hpp>
#include <intel.hpp> // x86 operand types + REX-aware SIB accessors (x86_base_reg, ...)
#include <ua.hpp>    // decode_insn, insn_t, op_t

#include <cstring>

#include "idakit_facade.h"

// idakit RegClass discriminants -- must match the Rust `RegClass` enum.
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

namespace {

// Classify an x86 RegNo by range. Used for plain o_reg operands and for a memory
// operand's base/index registers, whose numbers are always RegNo values.
uint8_t reg_class_of(int r) {
  if (r < 0)
    return RC_GPR;
  if (is_segreg(r))
    return RC_SEGMENT;
  if (r == R_ip)
    return RC_IP;
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
  return RC_GPR;
}

// Class for a register carried by a processor-specific operand type, where op.reg is a
// class-relative index (control/debug/test) rather than a RegNo.
uint8_t reg_class_for_optype(uint8_t t) {
  switch (t) {
  case o_trreg:
    return RC_TEST;
  case o_dbreg:
    return RC_DEBUG;
  case o_crreg:
    return RC_CONTROL;
  case o_fpreg:
    return RC_ST;
  case o_mmxreg:
    return RC_MMX;
  case o_xmmreg:
    return RC_XMM;
  case o_ymmreg:
    return RC_YMM;
  case o_zmmreg:
    return RC_ZMM;
  case o_kreg:
    return RC_MASK;
  default:
    return RC_GPR;
  }
}

void fill_reg(idakit_reg_t *r, int num, uint8_t cls, int width) {
  r->num = (uint16_t)num;
  r->cls = cls;
  r->width = (uint8_t)width;
  r->name[0] = 0;
  qstring nm;
  if (num >= 0 && get_reg_name(&nm, num, width > 0 ? (size_t)width : 8) > 0)
    qstrncpy(r->name, nm.c_str(), sizeof(r->name));
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

// Fold one raw op_t into a semantic idakit_op_t. Returns 0, or -3 for a type this decoder
// does not model (unreachable for x86, which enumerates all of its operand types).
int classify_op(const insn_t &insn, const op_t &op, int idx, idakit_op_t *dst) {
  memset(dst, 0, sizeof(*dst));
  clear_reg(&dst->reg);
  clear_reg(&dst->base);
  clear_reg(&dst->index);
  dst->idx = (uint8_t)idx;
  dst->dtype = op.dtype;
  switch (op.type) {
  case o_reg:
    dst->kind = IDAKIT_OP_REG;
    fill_reg(&dst->reg, op.reg, reg_class_of(op.reg), (int)get_dtype_size(op.dtype));
    return 0;
  case o_trreg:
  case o_dbreg:
  case o_crreg:
  case o_fpreg:
  case o_mmxreg:
  case o_xmmreg:
  case o_ymmreg:
  case o_zmmreg:
  case o_kreg:
    dst->kind = IDAKIT_OP_REG;
    fill_reg(&dst->reg, op.reg, reg_class_for_optype(op.type), (int)get_dtype_size(op.dtype));
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
        out->err_optype = op.type;
        out->err_op = (uint8_t)i;
        return -3;
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
