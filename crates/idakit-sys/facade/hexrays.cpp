// idakit facade: Hex-Rays decompiler init and streaming ctree extraction.

#include <pro.h>

#include <ida.hpp>

#include <funcs.hpp>
#include <hexrays.hpp>
#include <idp.hpp>    // HEXDSP / get_hexdsp
#include <lines.hpp>  // tag_remove
#include <loader.hpp> // load_plugin
#include <name.hpp>
#include <typeinf.hpp>

#include <vector>

#include "idakit_facade_internal.hpp"
#include "typewalk_walker.hpp"

using namespace idakit_facade;

// The decompiler is a plugin; init_hexrays_plugin() wires HEXDSP via callui
// broadcast once the plugin is loaded. Headless, load hexx64 explicitly if needed.
extern "C" int idakit_hexrays_init(void) {
  if (init_hexrays_plugin())
    return 1;
  load_plugin("hexx64");
  return init_hexrays_plugin() ? 1 : 0;
}

namespace {

struct walker_t {
  const idakit_emit_vtbl_t *v;
  void *ctx;
  // Walks node types into the shared type table via the cxx opaque visitor (see
  // typewalk_walker.hpp); created/freed around the walk in the entry below.
  idakit_cxx::visit_walker_t *vw;

  uint32_t expr(const cexpr_t *e) {
    ea_t ea = e->ea;
    uint32_t t = idakit_cxx::visit_walker_ty(vw, e->type);
    switch (e->op) {
    case cot_num:
      return v->e_num(ctx, ea, e->n->value(e->type), t);
    case cot_fnum: {
      double d = 0.0;
      e->fpc->fnum.to_double(&d);
      return v->e_fnum(ctx, ea, d, t);
    }
    case cot_obj: {
      qstring nm;
      get_name(&nm, e->obj_ea);
      return v->e_obj(ctx, ea, (uint64_t)e->obj_ea, nm.c_str(), nm.length(), t);
    }
    case cot_var:
      return v->e_var(ctx, ea, (uint32_t)e->v.idx, t);
    case cot_str:
      return v->e_str(ctx, ea, e->string != nullptr ? e->string : "",
                      e->string != nullptr ? strlen(e->string) : 0, t);
    case cot_helper:
      return v->e_helper(ctx, ea, e->helper != nullptr ? e->helper : "",
                         e->helper != nullptr ? strlen(e->helper) : 0, t);
    case cot_ptr:
      return v->e_deref(ctx, ea, expr(e->x), (uint32_t)e->ptrsize, t);
    case cot_memref:
      return v->e_memref(ctx, ea, expr(e->x), e->m, t);
    case cot_memptr:
      return v->e_memptr(ctx, ea, expr(e->x), e->m, t);
    case cot_call: {
      uint32_t callee = expr(e->x);
      std::vector<uint32_t> args;
      if (e->a != nullptr) {
        args.reserve(e->a->size());
        for (const carg_t &arg : *e->a)
          args.push_back(expr(&arg));
      }
      return v->e_call(ctx, ea, callee, args.data(), args.size(), t);
    }
    default: {
      // Binary/assign/unary/ternary/cast/index/sizeof/empty/type/insn: operands by the
      // SDK's own predicates, ctype passed raw for the Rust side to classify.
      uint32_t x = op_uses_x(e->op) ? expr(e->x) : IDAKIT_NONE;
      uint32_t y = op_uses_y(e->op) ? expr(e->y) : IDAKIT_NONE;
      uint32_t z = op_uses_z(e->op) ? expr(e->z) : IDAKIT_NONE;
      return v->e_op(ctx, ea, (uint32_t)e->op, x, y, z, t);
    }
    }
  }

  uint32_t opt_expr(const cexpr_t *e) {
    return (e == nullptr || e->op == cot_empty) ? IDAKIT_NONE : expr(e);
  }

  uint32_t block(const cinsn_list_t &list, ea_t ea) {
    std::vector<uint32_t> kids;
    kids.reserve(list.size());
    for (const cinsn_t &child : list)
      kids.push_back(stmt(&child));
    return v->s_block(ctx, ea, kids.data(), kids.size());
  }

  uint32_t stmt(const cinsn_t *i) {
    ea_t ea = i->ea;
    switch (i->op) {
    case cit_block:
      return block(*i->cblock, ea);
    case cit_expr:
      return v->s_expr(ctx, ea, expr(i->cexpr));
    case cit_if: {
      uint32_t c = expr(&i->cif->expr);
      uint32_t th = stmt(i->cif->ithen);
      uint32_t el = i->cif->ielse != nullptr ? stmt(i->cif->ielse) : IDAKIT_NONE;
      return v->s_if(ctx, ea, c, th, el);
    }
    case cit_for: {
      uint32_t in = opt_expr(&i->cfor->init);
      uint32_t co = opt_expr(&i->cfor->expr);
      uint32_t st = opt_expr(&i->cfor->step);
      return v->s_for(ctx, ea, in, co, st, stmt(i->cfor->body));
    }
    case cit_while: {
      uint32_t c = expr(&i->cwhile->expr);
      return v->s_while(ctx, ea, c, stmt(i->cwhile->body));
    }
    case cit_do: {
      uint32_t b = stmt(i->cdo->body);
      return v->s_do(ctx, ea, b, expr(&i->cdo->expr));
    }
    case cit_switch: {
      uint32_t ex = expr(&i->cswitch->expr);
      // Reserve so element addresses stay stable while `cs` references into `vals`.
      std::vector<std::vector<uint64_t>> vals;
      std::vector<idakit_case_t> cs;
      vals.reserve(i->cswitch->cases.size());
      cs.reserve(i->cswitch->cases.size());
      for (const ccase_t &c : i->cswitch->cases) {
        std::vector<uint64_t> vv;
        vv.reserve(c.values.size());
        for (uint64 val : c.values)
          vv.push_back(val);
        uint32_t body = stmt(&c); // ccase_t is-a cinsn_t
        vals.push_back(std::move(vv));
        idakit_case_t cd;
        cd.values = vals.back().data();
        cd.nvalues = vals.back().size();
        cd.body = body;
        cs.push_back(cd);
      }
      return v->s_switch(ctx, ea, ex, cs.data(), cs.size());
    }
    case cit_return:
      return v->s_return(ctx, ea, opt_expr(&i->creturn->expr));
    case cit_goto:
      return v->s_goto(ctx, ea, (int32_t)i->cgoto->label_num);
    case cit_asm: {
      std::vector<uint64_t> addrs;
      addrs.reserve(i->casm->size());
      for (ea_t a : *i->casm)
        addrs.push_back((uint64_t)a);
      return v->s_asm(ctx, ea, addrs.data(), addrs.size());
    }
    case cit_throw:
      return v->s_throw(ctx, ea, opt_expr(&i->cthrow->expr));
    case cit_try: {
      // ctry is-a cblock (the guarded body); each catch is a cblock too.
      uint32_t body = block(*i->ctry, ea);
      std::vector<uint32_t> catches;
      catches.reserve(i->ctry->catchs.size());
      for (const ccatch_t &cat : i->ctry->catchs)
        catches.push_back(block(cat, ea));
      return v->s_try(ctx, ea, body, catches.data(), catches.size());
    }
    case cit_break:
      return v->s_break(ctx, ea);
    case cit_continue:
      return v->s_continue(ctx, ea);
    // cit_empty and any statement kind this facade doesn't model both emit an empty stmt.
    case cit_empty:
    default:
      return v->s_empty(ctx, ea);
    }
  }

  // Emit the lvar table in index order, so `e_var.idx` resolves against it.
  void lvars(cfunc_t *cf) {
    lvars_t *lv = cf->get_lvars();
    if (lv == nullptr)
      return;
    for (const lvar_t &l : *lv) {
      uint32_t flags = (l.is_arg_var() ? 1u : 0u) | (l.is_result_var() ? 2u : 0u) |
                       (l.is_used_byref() ? 4u : 0u);
      const vdloc_t &loc = l.location;
      idakit_lvar_loc_t out = {};
      out.atype = (uint32_t)loc.atype();
      std::vector<idakit_loc_piece_t> pieces;
      switch (loc.atype()) {
      case ALOC_STACK:
        out.sval = (int64_t)l.get_stkoff();
        break;
      case ALOC_REG1:
        out.reg1 = (uint32_t)loc.reg1();
        break;
      case ALOC_REG2:
        out.reg1 = (uint32_t)loc.reg1();
        out.reg2 = (uint32_t)loc.reg2();
        break;
      case ALOC_RREL: {
        const rrel_t &rr = loc.get_rrel();
        out.reg1 = (uint32_t)rr.reg;
        out.sval = (int64_t)rr.off;
        break;
      }
      case ALOC_STATIC:
        out.sval = (int64_t)loc.get_ea();
        break;
      case ALOC_DIST: {
        const scattered_aloc_t &sc = loc.scattered();
        pieces.reserve(sc.size());
        for (const argpart_t &p : sc) {
          idakit_loc_piece_t pc = {};
          pc.atype = (uint32_t)p.atype();
          if (p.is_reg1())
            pc.reg = (uint32_t)p.reg1();
          else if (p.is_stkoff())
            pc.sval = (int64_t)p.stkoff();
          else if (p.is_ea())
            pc.sval = (int64_t)p.get_ea();
          pc.off = p.off;
          pc.size = p.size;
          pieces.push_back(pc);
        }
        out.pieces = pieces.data();
        out.npieces = (uint32_t)pieces.size();
        break;
      }
      default:
        break; // ALOC_NONE / ALOC_CUSTOM: atype alone carries it
      }
      v->l_lvar(ctx, l.name.c_str(), l.name.length(), idakit_cxx::visit_walker_ty(vw, l.tif), flags,
                (uint32_t)l.width, l.cmt.c_str(), l.cmt.length(), &out);
    }
  }
};

} // namespace

extern "C" int idakit_cfunc_walk_ctree(void *h, const idakit_emit_vtbl_t *v, void *ctx,
                                       void *visitor, uint32_t *root) {
  if (h == nullptr || v == nullptr || visitor == nullptr || root == nullptr)
    return 1;
  try {
    cfunc_t *cf = *reinterpret_cast<cfuncptr_t *>(h);

    walker_t w;
    w.v = v;
    w.ctx = ctx;
    // `visitor` is the Rust TypeWalkVisitor as an opaque pointer; the walker drives it for node
    // types. The guard frees it on the normal return and on the exception path below.
    w.vw = idakit_cxx::visit_walker_new(visitor);
    struct walker_guard {
      idakit_cxx::visit_walker_t *w;
      ~walker_guard() { idakit_cxx::visit_walker_free(w); }
    } guard{w.vw};
    w.lvars(cf);
    *root = w.stmt(&cf->body);
    return 0;
  } catch (...) {
    std::abort();
  }
}
