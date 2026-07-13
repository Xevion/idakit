// cxx extern "Rust" opaque-visitor ctree walk (namespace idakit_cxx). walker_t does the same
// depth-first cfunc_t recursion the deleted C-vtbl facade did, but emits through the extern "Rust"
// opaque visitor's member functions (nodes->e_num(...), nodes->s_if(...), nodes->l_lvar(...)) that
// cxx generates, not a function-pointer table and void* context. Node types are resolved through
// the shared tinfo walker (typewalk_walker.hpp), one walker created per ctree walk and driven
// alongside the recursion exactly as the deleted facade did. Byte strings cross as
// rust::Slice<const uint8_t>, arrays as rust::Slice<T>, borrowed for the one call.

#include <pro.h>

#include <ida.hpp>

#include <cstring>
#include <vector>

#include <funcs.hpp> // get_func
#include <hexrays.hpp>
#include <name.hpp> // get_name

#include "ctree_cxx.h"
#include "typewalk_walker.hpp"
// The generated visitor-bridge header defines the CtreeVisitor class (its member functions) and
// the LocPiece shared struct. OUT_DIR is on this TU's include path.
#include "gen_visitors.h"

namespace idakit_cxx {

namespace {

constexpr uint32_t IDAKIT_NONE = 0xFFFFFFFFu;

rust::Slice<const uint8_t> bytes_of(const char *p, size_t n) {
  return rust::Slice<const uint8_t>(reinterpret_cast<const uint8_t *>(p), n);
}

rust::Slice<const uint32_t> slice_of(const std::vector<uint32_t> &v) {
  return v.empty() ? rust::Slice<const uint32_t>()
                   : rust::Slice<const uint32_t>(v.data(), v.size());
}

rust::Slice<const uint64_t> slice_of(const std::vector<uint64_t> &v) {
  return v.empty() ? rust::Slice<const uint64_t>()
                   : rust::Slice<const uint64_t>(v.data(), v.size());
}

rust::Slice<const LocPiece> slice_of(const std::vector<LocPiece> &v) {
  return v.empty() ? rust::Slice<const LocPiece>()
                   : rust::Slice<const LocPiece>(v.data(), v.size());
}

} // namespace

// Full recursion driving the extern "Rust" CtreeVisitor, mirroring the deleted C-vtbl walker_t
// one-to-one; only the emission target changed.
struct walker_t {
  CtreeVisitor *nodes;
  // Walks node types into the shared type table via the cxx opaque visitor (see
  // typewalk_walker.hpp); created/freed around the walk in cfunc_walk_ctree below.
  idakit_cxx::visit_walker_t *vw;

  uint32_t expr(const cexpr_t *e) {
    ea_t ea = e->ea;
    uint32_t t = idakit_cxx::visit_walker_ty(vw, e->type);
    switch (e->op) {
    case cot_num:
      return nodes->e_num(ea, e->n->value(e->type), t);
    case cot_fnum: {
      double d = 0.0;
      e->fpc->fnum.to_double(&d);
      return nodes->e_fnum(ea, d, t);
    }
    case cot_obj: {
      qstring nm;
      get_name(&nm, e->obj_ea);
      return nodes->e_obj(ea, (uint64_t)e->obj_ea, bytes_of(nm.c_str(), nm.length()), t);
    }
    case cot_var:
      return nodes->e_var(ea, (uint32_t)e->v.idx, t);
    case cot_str:
      return nodes->e_str(ea,
                          bytes_of(e->string != nullptr ? e->string : "",
                                   e->string != nullptr ? strlen(e->string) : 0),
                          t);
    case cot_helper:
      return nodes->e_helper(ea,
                             bytes_of(e->helper != nullptr ? e->helper : "",
                                      e->helper != nullptr ? strlen(e->helper) : 0),
                             t);
    case cot_ptr:
      return nodes->e_deref(ea, expr(e->x), (uint32_t)e->ptrsize, t);
    case cot_memref:
      return nodes->e_memref(ea, expr(e->x), e->m, t);
    case cot_memptr:
      return nodes->e_memptr(ea, expr(e->x), e->m, t);
    case cot_call: {
      uint32_t callee = expr(e->x);
      std::vector<uint32_t> args;
      if (e->a != nullptr) {
        args.reserve(e->a->size());
        for (const carg_t &arg : *e->a)
          args.push_back(expr(&arg));
      }
      return nodes->e_call(ea, callee, slice_of(args), t);
    }
    default: {
      // Binary/assign/unary/ternary/cast/index/sizeof/empty/type/insn: operands by the
      // SDK's own predicates, ctype passed raw for the Rust side to classify.
      uint32_t x = op_uses_x(e->op) ? expr(e->x) : IDAKIT_NONE;
      uint32_t y = op_uses_y(e->op) ? expr(e->y) : IDAKIT_NONE;
      uint32_t z = op_uses_z(e->op) ? expr(e->z) : IDAKIT_NONE;
      return nodes->e_op(ea, (uint32_t)e->op, x, y, z, t);
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
    return nodes->s_block(ea, slice_of(kids));
  }

  uint32_t stmt(const cinsn_t *i) {
    ea_t ea = i->ea;
    switch (i->op) {
    case cit_block:
      return block(*i->cblock, ea);
    case cit_expr:
      return nodes->s_expr(ea, expr(i->cexpr));
    case cit_if: {
      uint32_t c = expr(&i->cif->expr);
      uint32_t th = stmt(i->cif->ithen);
      uint32_t el = i->cif->ielse != nullptr ? stmt(i->cif->ielse) : IDAKIT_NONE;
      return nodes->s_if(ea, c, th, el);
    }
    case cit_for: {
      uint32_t in = opt_expr(&i->cfor->init);
      uint32_t co = opt_expr(&i->cfor->expr);
      uint32_t st = opt_expr(&i->cfor->step);
      return nodes->s_for(ea, in, co, st, stmt(i->cfor->body));
    }
    case cit_while: {
      uint32_t c = expr(&i->cwhile->expr);
      return nodes->s_while(ea, c, stmt(i->cwhile->body));
    }
    case cit_do: {
      uint32_t b = stmt(i->cdo->body);
      return nodes->s_do(ea, b, expr(&i->cdo->expr));
    }
    case cit_switch: {
      uint32_t ex = expr(&i->cswitch->expr);
      std::vector<uint32_t> bodies;
      std::vector<uint32_t> value_counts;
      std::vector<uint64_t> values;
      bodies.reserve(i->cswitch->cases.size());
      value_counts.reserve(i->cswitch->cases.size());
      for (const ccase_t &c : i->cswitch->cases) {
        value_counts.push_back((uint32_t)c.values.size());
        for (uint64 val : c.values)
          values.push_back(val);
        bodies.push_back(stmt(&c)); // ccase_t is-a cinsn_t
      }
      return nodes->s_switch(ea, ex, slice_of(bodies), slice_of(value_counts), slice_of(values));
    }
    case cit_return:
      return nodes->s_return(ea, opt_expr(&i->creturn->expr));
    case cit_goto:
      return nodes->s_goto(ea, (int32_t)i->cgoto->label_num);
    case cit_asm: {
      std::vector<uint64_t> addrs;
      addrs.reserve(i->casm->size());
      for (ea_t a : *i->casm)
        addrs.push_back((uint64_t)a);
      return nodes->s_asm(ea, slice_of(addrs));
    }
    case cit_throw:
      return nodes->s_throw(ea, opt_expr(&i->cthrow->expr));
    case cit_try: {
      // ctry is-a cblock (the guarded body); each catch is a cblock too.
      uint32_t body = block(*i->ctry, ea);
      std::vector<uint32_t> catches;
      catches.reserve(i->ctry->catchs.size());
      for (const ccatch_t &cat : i->ctry->catchs)
        catches.push_back(block(cat, ea));
      return nodes->s_try(ea, body, slice_of(catches));
    }
    case cit_break:
      return nodes->s_break(ea);
    case cit_continue:
      return nodes->s_continue(ea);
    // cit_empty and any statement kind this facade doesn't model both emit an empty stmt.
    case cit_empty:
    default:
      return nodes->s_empty(ea);
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
      uint32_t atype = (uint32_t)loc.atype();
      uint32_t reg1 = 0;
      uint32_t reg2 = 0;
      int64_t sval = 0;
      std::vector<LocPiece> pieces;
      switch (loc.atype()) {
      case ALOC_STACK:
        sval = (int64_t)l.get_stkoff();
        break;
      case ALOC_REG1:
        reg1 = (uint32_t)loc.reg1();
        break;
      case ALOC_REG2:
        reg1 = (uint32_t)loc.reg1();
        reg2 = (uint32_t)loc.reg2();
        break;
      case ALOC_RREL: {
        const rrel_t &rr = loc.get_rrel();
        reg1 = (uint32_t)rr.reg;
        sval = (int64_t)rr.off;
        break;
      }
      case ALOC_STATIC:
        sval = (int64_t)loc.get_ea();
        break;
      case ALOC_DIST: {
        const scattered_aloc_t &sc = loc.scattered();
        pieces.reserve(sc.size());
        for (const argpart_t &p : sc) {
          LocPiece pc;
          pc.atype = (uint32_t)p.atype();
          pc.reg = 0;
          pc.sval = 0;
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
        break;
      }
      default:
        break; // ALOC_NONE / ALOC_CUSTOM: atype alone carries it
      }
      uint32_t ty = idakit_cxx::visit_walker_ty(vw, l.tif);
      nodes->l_lvar(bytes_of(l.name.c_str(), l.name.length()), ty, flags, (uint32_t)l.width,
                    bytes_of(l.cmt.c_str(), l.cmt.length()), atype, reg1, reg2, sval,
                    slice_of(pieces));
    }
  }
};

uint32_t cfunc_walk_ctree(const ::cfuncptr_t &cfunc, CtreeVisitor &nodes, size_t type_visitor) {
  try {
    cfunc_t *cf = cfunc;
    walker_t w;
    w.nodes = &nodes;
    // The guard frees the type walker on the normal return and on the exception path below.
    w.vw = idakit_cxx::visit_walker_new(reinterpret_cast<void *>(type_visitor));
    struct walker_guard {
      idakit_cxx::visit_walker_t *w;
      ~walker_guard() { idakit_cxx::visit_walker_free(w); }
    } guard{w.vw};
    w.lvars(cf);
    return w.stmt(&cf->body);
  } catch (...) {
    std::abort();
  }
}

} // namespace idakit_cxx
