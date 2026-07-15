// cxx extern "Rust" opaque-visitor ctree walk (namespace bridge). walker_t does the same
// depth-first cfunc_t recursion the deleted C-vtbl facade did, but emits through the extern "Rust"
// opaque visitor's member functions (nodes->e_num(...), nodes->s_if(...), nodes->l_lvar(...)) that
// cxx generates, not a function-pointer table and void* context. Node types are resolved through
// the shared tinfo walker (type_walker.h), one walker created per ctree walk and driven
// alongside the recursion exactly as the deleted facade did. Names, string literals, and comments
// cross as owned rust::String, decoded leniently (IDA emits UTF-8, undecodable units become
// U+FFFD); arrays cross as rust::Slice<T>, borrowed for the one call.

#include <pro.h>

#include <ida.hpp>

#include <cstring>
#include <vector>

#include <funcs.hpp> // get_func
#include <hexrays.hpp>
#include <name.hpp> // get_name

#include "ctree_bridge.h"
#include "type_walker.h"
// The generated visitor-bridge header defines the CtreeVisitor class (its member functions) and
// the LocPiece shared struct. OUT_DIR is on this TU's include path.
#include "gen_facade_consts.h" // gen::NONE
#include "gen_visitors.h"

namespace bridge {

namespace {

// Lenient-decode a facade C string into an owning rust::String for the one visitor call. IDA emits
// UTF-8, so lossy never rejects, yet a stray bad byte degrades to U+FFFD instead of unwinding.
rust::String lossy_str(const char *p, size_t n) { return rust::String::lossy(p, n); }

// Borrow a node-handle vector as a slice; an empty vector becomes an empty slice, never a
// dangling data() pointer.
rust::Slice<const uint32_t> slice_of(const std::vector<uint32_t> &v) {
  return v.empty() ? rust::Slice<const uint32_t>()
                   : rust::Slice<const uint32_t>(v.data(), v.size());
}

// Same borrow, for the uint64_t vectors (switch-case values, cit_asm instruction addresses).
rust::Slice<const uint64_t> slice_of(const std::vector<uint64_t> &v) {
  return v.empty() ? rust::Slice<const uint64_t>()
                   : rust::Slice<const uint64_t>(v.data(), v.size());
}

// Same borrow, for a scattered local's LocPiece fragments.
rust::Slice<const LocPiece> slice_of(const std::vector<LocPiece> &v) {
  return v.empty() ? rust::Slice<const LocPiece>()
                   : rust::Slice<const LocPiece>(v.data(), v.size());
}

// l_lvar flag bits: argument, return-value slot, captured by reference.
constexpr uint32_t LVAR_IS_ARG = 1u;
constexpr uint32_t LVAR_IS_RESULT = 2u;
constexpr uint32_t LVAR_IS_USED_BYREF = 4u;

} // namespace

// Full recursion driving the extern "Rust" CtreeVisitor, mirroring the deleted C-vtbl walker_t
// one-to-one; only the emission target changed.
struct walker_t {
  CtreeVisitor *nodes;
  // Walks node types into the shared type table via the cxx opaque visitor (see
  // type_walker.h); created/freed around the walk in cfunc_walk_ctree below.
  bridge::visit_walker_t *type_walker;

  // Convert one cexpr_t into a node id, recursing into operands first so each child is minted
  // before the parent node that references it.
  uint32_t expr(const cexpr_t *cexpr) {
    ea_t addr = cexpr->ea;
    uint32_t t = bridge::visit_walker_ty(type_walker, cexpr->type);
    switch (cexpr->op) {
    case cot_num:
      return nodes->e_num(addr, cexpr->n->value(cexpr->type), t);
    case cot_fnum: {
      double d = 0.0;
      cexpr->fpc->fnum.to_double(&d);
      return nodes->e_fnum(addr, d, t);
    }
    case cot_obj: {
      qstring nm;
      get_name(&nm, cexpr->obj_ea);
      return nodes->e_obj(addr, static_cast<uint64_t>(cexpr->obj_ea),
                          lossy_str(nm.c_str(), nm.length()), t);
    }
    case cot_var:
      return nodes->e_var(addr, static_cast<uint32_t>(cexpr->v.idx), t);
    case cot_str:
      return nodes->e_str(addr,
                          lossy_str(cexpr->string != nullptr ? cexpr->string : "",
                                    cexpr->string != nullptr ? strlen(cexpr->string) : 0),
                          t);
    case cot_helper:
      return nodes->e_helper(addr,
                             lossy_str(cexpr->helper != nullptr ? cexpr->helper : "",
                                       cexpr->helper != nullptr ? strlen(cexpr->helper) : 0),
                             t);
    case cot_ptr:
      return nodes->e_deref(addr, expr(cexpr->x), static_cast<uint32_t>(cexpr->ptrsize), t);
    case cot_memref:
      return nodes->e_memref(addr, expr(cexpr->x), cexpr->m, t);
    case cot_memptr:
      return nodes->e_memptr(addr, expr(cexpr->x), cexpr->m, t);
    case cot_call: {
      uint32_t callee = expr(cexpr->x);
      std::vector<uint32_t> args;
      if (cexpr->a != nullptr) {
        args.reserve(cexpr->a->size());
        for (const carg_t &arg : *cexpr->a)
          args.push_back(expr(&arg));
      }
      return nodes->e_call(addr, callee, slice_of(args), t);
    }
    default: {
      // Binary/assign/unary/ternary/cast/index/sizeof/empty/type/insn: operands by the
      // SDK's own predicates, ctype passed raw for the Rust side to classify.
      uint32_t x = op_uses_x(cexpr->op) ? expr(cexpr->x) : gen::NONE;
      uint32_t y = op_uses_y(cexpr->op) ? expr(cexpr->y) : gen::NONE;
      uint32_t z = op_uses_z(cexpr->op) ? expr(cexpr->z) : gen::NONE;
      return nodes->e_op(addr, static_cast<uint32_t>(cexpr->op), x, y, z, t);
    }
    }
  }

  // NONE for a null or cot_empty expression (an absent optional operand), else expr's own handle.
  uint32_t opt_expr(const cexpr_t *cexpr) {
    return (cexpr == nullptr || cexpr->op == cot_empty) ? gen::NONE : expr(cexpr);
  }

  // Walk a statement list into an s_block node, children in list order.
  uint32_t block(const cinsn_list_t &list, ea_t addr) {
    std::vector<uint32_t> kids;
    kids.reserve(list.size());
    for (const cinsn_t &child : list)
      kids.push_back(stmt(&child));
    return nodes->s_block(addr, slice_of(kids));
  }

  // Convert one cinsn_t into a node id, recursing into nested statements and expressions.
  uint32_t stmt(const cinsn_t *cinsn) {
    ea_t addr = cinsn->ea;
    switch (cinsn->op) {
    case cit_block:
      return block(*cinsn->cblock, addr);
    case cit_expr:
      return nodes->s_expr(addr, expr(cinsn->cexpr));
    case cit_if: {
      uint32_t cond = expr(&cinsn->cif->expr);
      uint32_t then_branch = stmt(cinsn->cif->ithen);
      uint32_t else_branch = cinsn->cif->ielse != nullptr ? stmt(cinsn->cif->ielse) : gen::NONE;
      return nodes->s_if(addr, cond, then_branch, else_branch);
    }
    case cit_for: {
      uint32_t init = opt_expr(&cinsn->cfor->init);
      uint32_t cond = opt_expr(&cinsn->cfor->expr);
      uint32_t step = opt_expr(&cinsn->cfor->step);
      return nodes->s_for(addr, init, cond, step, stmt(cinsn->cfor->body));
    }
    case cit_while: {
      uint32_t cond = expr(&cinsn->cwhile->expr);
      return nodes->s_while(addr, cond, stmt(cinsn->cwhile->body));
    }
    case cit_do: {
      uint32_t block = stmt(cinsn->cdo->body);
      return nodes->s_do(addr, block, expr(&cinsn->cdo->expr));
    }
    case cit_switch: {
      uint32_t cond = expr(&cinsn->cswitch->expr);
      std::vector<uint32_t> bodies;
      std::vector<uint32_t> value_counts;
      std::vector<uint64_t> values;
      bodies.reserve(cinsn->cswitch->cases.size());
      value_counts.reserve(cinsn->cswitch->cases.size());
      for (const ccase_t &case_ : cinsn->cswitch->cases) {
        // Each case's values flatten into one shared `values` vector; value_counts[i] tells
        // the Rust side how many trailing values belong to bodies[i].
        value_counts.push_back(static_cast<uint32_t>(case_.values.size()));
        for (uint64 val : case_.values)
          values.push_back(val);
        bodies.push_back(stmt(&case_)); // ccase_t is-a cinsn_t
      }
      return nodes->s_switch(addr, cond, slice_of(bodies), slice_of(value_counts),
                             slice_of(values));
    }
    case cit_return:
      return nodes->s_return(addr, opt_expr(&cinsn->creturn->expr));
    case cit_goto:
      return nodes->s_goto(addr, static_cast<int32_t>(cinsn->cgoto->label_num));
    case cit_asm: {
      std::vector<uint64_t> addrs;
      addrs.reserve(cinsn->casm->size());
      for (ea_t insn_addr : *cinsn->casm)
        addrs.push_back(static_cast<uint64_t>(insn_addr));
      return nodes->s_asm(addr, slice_of(addrs));
    }
    case cit_throw:
      return nodes->s_throw(addr, opt_expr(&cinsn->cthrow->expr));
    case cit_try: {
      // ctry is-a cblock (the guarded body); each catch is a cblock too.
      uint32_t body = block(*cinsn->ctry, addr);
      std::vector<uint32_t> catches;
      catches.reserve(cinsn->ctry->catchs.size());
      for (const ccatch_t &cat : cinsn->ctry->catchs)
        catches.push_back(block(cat, addr));
      return nodes->s_try(addr, body, slice_of(catches));
    }
    case cit_break:
      return nodes->s_break(addr);
    case cit_continue:
      return nodes->s_continue(addr);
    // cit_empty and any statement kind this facade doesn't model both emit an empty stmt.
    case cit_empty:
    default:
      return nodes->s_empty(addr);
    }
  }

  // Emit the lvar table in index order, so `e_var.idx` resolves against it.
  void lvars(cfunc_t *decompiled) {
    lvars_t *lv = decompiled->get_lvars();
    if (lv == nullptr)
      return;
    for (const lvar_t &lvar : *lv) {
      uint32_t flags = (lvar.is_arg_var() ? LVAR_IS_ARG : 0u) |
                       (lvar.is_result_var() ? LVAR_IS_RESULT : 0u) |
                       (lvar.is_used_byref() ? LVAR_IS_USED_BYREF : 0u);
      const vdloc_t &loc = lvar.location;
      uint32_t atype = static_cast<uint32_t>(loc.atype());
      uint32_t reg1 = 0;
      uint32_t reg2 = 0;
      int64_t sval = 0;
      std::vector<LocPiece> pieces;
      // vdloc_t is a tagged union over storage kind; only the fields the matching ALOC_*
      // below populates are meaningful, the rest stay at their zero default.
      switch (loc.atype()) {
      case ALOC_STACK:
        sval = static_cast<int64_t>(lvar.get_stkoff());
        break;
      case ALOC_REG1:
        reg1 = static_cast<uint32_t>(loc.reg1());
        break;
      case ALOC_REG2:
        reg1 = static_cast<uint32_t>(loc.reg1());
        reg2 = static_cast<uint32_t>(loc.reg2());
        break;
      case ALOC_RREL: {
        const rrel_t &rr = loc.get_rrel();
        reg1 = static_cast<uint32_t>(rr.reg);
        sval = static_cast<int64_t>(rr.off);
        break;
      }
      case ALOC_STATIC:
        sval = static_cast<int64_t>(loc.get_ea());
        break;
      case ALOC_DIST: {
        // A value scattered across multiple registers/stack slots; flatten each fragment into
        // its own LocPiece instead of the single reg1/reg2/sval triple above.
        const scattered_aloc_t &sc = loc.scattered();
        pieces.reserve(sc.size());
        for (const argpart_t &part : sc) {
          LocPiece piece;
          piece.atype = static_cast<uint32_t>(part.atype());
          piece.reg = 0;
          piece.sval = 0;
          if (part.is_reg1())
            piece.reg = static_cast<uint32_t>(part.reg1());
          else if (part.is_stkoff())
            piece.sval = static_cast<int64_t>(part.stkoff());
          else if (part.is_ea())
            piece.sval = static_cast<int64_t>(part.get_ea());
          piece.off = part.off;
          piece.size = part.size;
          pieces.push_back(piece);
        }
        break;
      }
      default:
        break; // ALOC_NONE / ALOC_CUSTOM: atype alone carries it
      }
      uint32_t ty = bridge::visit_walker_ty(type_walker, lvar.tif);
      nodes->l_lvar(lossy_str(lvar.name.c_str(), lvar.name.length()), ty, flags,
                    static_cast<uint32_t>(lvar.width),
                    lossy_str(lvar.cmt.c_str(), lvar.cmt.length()), atype, reg1, reg2, sval,
                    slice_of(pieces));
    }
  }
};

// Entry point cxx calls: walk cfunc's ctree body and lvar table into `nodes`, minting types
// through the walker at `type_visitor`. Returns the root statement's handle.
uint32_t cfunc_walk_ctree(const ::cfuncptr_t &cfunc, CtreeVisitor &nodes, size_t type_visitor) {
  // The visitor callbacks are all noexcept; this catches exceptions from the raw kernel calls
  // instead, since a plain uint32_t return has no Result channel to carry an error through.
  try {
    cfunc_t *decompiled = cfunc;
    walker_t walker;
    walker.nodes = &nodes;
    // The guard frees the type walker on the normal return and on the exception path below.
    walker.type_walker = bridge::visit_walker_new(reinterpret_cast<void *>(type_visitor));
    struct walker_guard {
      bridge::visit_walker_t *type_walker;
      ~walker_guard() { bridge::visit_walker_free(type_walker); }
    } guard{walker.type_walker};
    walker.lvars(decompiled);
    return walker.stmt(&decompiled->body);
  } catch (...) {
    std::abort();
  }
}

} // namespace bridge
