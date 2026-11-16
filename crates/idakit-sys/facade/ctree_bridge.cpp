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
#include <utility>
#include <vector>

#include <funcs.hpp> // get_func
#include <hexrays.hpp>
#include <name.hpp> // get_name

#include "ctree_bridge.h"
#include "type_walker.h"
// The generated visitor-bridge header defines the CtreeVisitor class (its member functions) and
// the ArgLoc / LocPiece shared structs. OUT_DIR is on this TU's include path.
#include "gen_facade_consts.h" // gen::NONE
#include "gen_visitors.h"
#include "wire.h"

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

// An lvar_t's CVAR_* word, rebuilt from its accessors since lvar_t keeps the field private.
uint32_t cvar_flags(const lvar_t &v) {
  const std::pair<bool, uint32_t> bits[] = {
      {v.used(), CVAR_USED},
      {v.typed(), CVAR_TYPE},
      {v.has_nice_name(), CVAR_NAME},
      {v.mreg_done(), CVAR_MREG},
      {v.is_unknown_width(), CVAR_NOWD},
      {v.has_user_name(), CVAR_UNAME},
      {v.has_user_type(), CVAR_UTYPE},
      {v.is_result_var(), CVAR_RESULT},
      {v.is_arg_var(), CVAR_ARG},
      {v.is_fake_var(), CVAR_FAKE},
      {v.is_overlapped_var(), CVAR_OVER},
      {v.is_floating_var(), CVAR_FLOAT},
      {v.is_spoiled_var(), CVAR_SPOILED},
      {v.is_mapdst_var(), CVAR_MAPDST},
      {v.is_partialy_typed(), CVAR_PARTIAL},
      {v.is_thisarg(), CVAR_THISARG},
      {v.is_split_var(), CVAR_SPLIT},
      {v.has_regname(), CVAR_REGNAME},
      {v.is_noptr_var(), CVAR_NOPTR},
      {v.is_dummy_arg(), CVAR_DUMMY},
      {v.is_notarg(), CVAR_NOTARG},
      {v.is_automapped(), CVAR_AUTOMAP},
      {v.is_used_byref(), CVAR_BYREF},
      {v.in_asm(), CVAR_INASM},
      {v.is_decl_unused(), CVAR_UNUSED},
      {v.is_shared(), CVAR_SHARED},
      {v.was_scattered_arg(), CVAR_SCARG},
      {v.is_noprop(), CVAR_NOPROP},
  };
  uint32_t out = 0;
  for (const auto &[set, bit] : bits)
    if (set)
      out |= bit;
  return out;
}

} // namespace

// Full recursion driving the extern "Rust" CtreeVisitor, mirroring the deleted C-vtbl walker_t
// one-to-one; only the emission target changed.
struct walker_t {
  CtreeVisitor *nodes;
  // Walks node types into the shared type table via the cxx opaque visitor (see
  // type_walker.h); created/freed around the walk in cfunc_walk_ctree below.
  bridge::visit_walker_t *type_walker;

  // Convert one cexpr_t into a node id, then attach its exflags word when it has one.
  uint32_t expr(const cexpr_t *cexpr) {
    uint32_t id = expr_node(cexpr);
    if (cexpr->exflags != 0)
      nodes->e_flags(id, cexpr->exflags);
    return id;
  }

  // Mint one cexpr_t's node, recursing into operands first so each child is minted before the
  // parent node that references it.
  uint32_t expr_node(const cexpr_t *cexpr) {
    const uint64_t addr = ea_wire(cexpr->ea);
    uint32_t t = bridge::visit_walker_ty(type_walker, cexpr->type);
    switch (cexpr->op) {
    case cot_num: {
      const number_format_t &nf = cexpr->n->nf;
      NumLiteral lit{};
      lit.value = cexpr->n->value(cexpr->type);
      if (nf.is_enum())
        lit.kind = gen::LITERAL_ENUM;
      else if (nf.is_char())
        lit.kind = gen::LITERAL_CHAR;
      else if (nf.is_stroff())
        lit.kind = gen::LITERAL_STRUCT_OFFSET;
      else
        lit.kind = gen::LITERAL_NUMBER;
      lit.radix = static_cast<uint32_t>(nf.get_radix());
      lit.type_name = lossy_str(nf.type_name.c_str(), nf.type_name.length());
      lit.serial = nf.serial;
      lit.properties = static_cast<uint8_t>(nf.props);
      lit.original_size = static_cast<uint8_t>(nf.org_nbytes);
      lit.operand = static_cast<uint8_t>(nf.opnum);
      lit.representation = nf.flags;
      return nodes->e_num(addr, lit, t);
    }
    case cot_fnum: {
      double d = 0.0;
      cexpr->fpc->fnum.to_double(&d);
      return nodes->e_fnum(addr, d, t);
    }
    case cot_obj: {
      qstring nm;
      get_name(&nm, cexpr->obj_ea);
      return nodes->e_obj(addr, ea_wire(cexpr->obj_ea), lossy_str(nm.c_str(), nm.length()), t);
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
      std::vector<CallArg> args;
      if (cexpr->a != nullptr) {
        args.reserve(cexpr->a->size());
        for (const carg_t &arg : *cexpr->a) {
          CallArg a{};
          a.expr = expr(&arg);
          a.is_vararg = arg.is_vararg;
          a.formal_type = arg.formal_type.empty()
                              ? gen::NONE
                              : bridge::visit_walker_ty(type_walker, arg.formal_type);
          args.push_back(a);
        }
      }
      rust::Slice<const CallArg> arg_slice =
          args.empty() ? rust::Slice<const CallArg>()
                       : rust::Slice<const CallArg>(args.data(), args.size());
      return nodes->e_call(addr, callee, arg_slice, t);
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
  uint32_t block(const cinsn_list_t &list, uint64_t addr) {
    std::vector<uint32_t> kids;
    kids.reserve(list.size());
    for (const cinsn_t &child : list)
      kids.push_back(stmt(&child));
    return nodes->s_block(addr, slice_of(kids));
  }

  // Convert one cinsn_t into a node id, recursing into nested statements and expressions.
  uint32_t stmt(const cinsn_t *cinsn) {
    const uint64_t addr = ea_wire(cinsn->ea);
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
        addrs.push_back(ea_wire(insn_addr));
      return nodes->s_asm(addr, slice_of(addrs));
    }
    case cit_throw:
      return nodes->s_throw(addr, opt_expr(&cinsn->cthrow->expr));
    case cit_try: {
      // ctry is-a cblock (the guarded body); each catch is a cblock too, plus what it catches.
      uint32_t body = block(*cinsn->ctry, addr);
      std::vector<CatchClause> catches;
      catches.reserve(cinsn->ctry->catchs.size());
      for (const ccatch_t &cat : cinsn->ctry->catchs) {
        CatchClause clause{};
        clause.body = block(cat, addr);
        for (const catchexpr_t &ce : cat.exprs) {
          CaughtExpr caught{};
          caught.object = opt_expr(&ce.obj);
          caught.fake_type = lossy_str(ce.fake_type.c_str(), ce.fake_type.length());
          clause.caught.push_back(std::move(caught));
        }
        catches.push_back(std::move(clause));
      }
      rust::Slice<const CatchClause> catch_slice =
          catches.empty() ? rust::Slice<const CatchClause>()
                          : rust::Slice<const CatchClause>(catches.data(), catches.size());
      return nodes->s_try(addr, body, catch_slice);
    }
    case cit_break:
      return nodes->s_break(addr);
    case cit_continue:
      return nodes->s_continue(addr);
    case cit_empty:
      return nodes->s_empty(addr);
    // An unmodelled statement kind is reported, so the sink can reject the walk.
    default:
      return nodes->s_unknown(addr, static_cast<uint32_t>(cinsn->op));
    }
  }

  // Emit the lvar table in index order, so `e_var.idx` resolves against it.
  void lvars(cfunc_t *decompiled) {
    lvars_t *lv = decompiled->get_lvars();
    if (lv == nullptr)
      return;
    for (const lvar_t &lvar : *lv) {
      uint32_t flags = cvar_flags(lvar);
      const vdloc_t &loc = lvar.location;
      // vdloc_t is a tagged union over storage kind; only the fields the matching ALOC_* below
      // populates are meaningful. Its register number spans the whole field and carries no
      // in-register offset, so regoff stays 0.
      ArgLoc location{};
      location.atype = static_cast<uint32_t>(loc.atype());
      switch (loc.atype()) {
      case ALOC_STACK:
        location.sval = static_cast<int64_t>(lvar.get_stkoff());
        break;
      case ALOC_REG1:
        location.reg1 = static_cast<uint32_t>(loc.reg1());
        break;
      case ALOC_REG2:
        location.reg1 = static_cast<uint32_t>(loc.reg1());
        location.reg2 = static_cast<uint32_t>(loc.reg2());
        break;
      case ALOC_RREL: {
        const rrel_t &rr = loc.get_rrel();
        location.reg1 = static_cast<uint32_t>(rr.reg);
        location.sval = static_cast<int64_t>(rr.off);
        break;
      }
      case ALOC_STATIC:
        location.sval = static_cast<int64_t>(ea_wire(loc.get_ea()));
        break;
      case ALOC_DIST:
        for (const argpart_t &part : loc.scattered()) {
          LocPiece piece{};
          piece.atype = static_cast<uint32_t>(part.atype());
          if (part.is_reg1())
            piece.reg = static_cast<uint32_t>(part.reg1());
          else if (part.is_stkoff())
            piece.sval = static_cast<int64_t>(part.stkoff());
          else if (part.is_ea())
            piece.sval = static_cast<int64_t>(ea_wire(part.get_ea()));
          piece.off = part.off;
          piece.size = part.size;
          location.pieces.push_back(piece);
        }
        break;
      default:
        break; // ALOC_NONE / ALOC_CUSTOM: atype alone carries it
      }
      uint32_t ty = bridge::visit_walker_ty(type_walker, lvar.tif);
      nodes->l_lvar(lossy_str(lvar.name.c_str(), lvar.name.length()), ty, flags,
                    static_cast<uint32_t>(lvar.width),
                    lossy_str(lvar.cmt.c_str(), lvar.cmt.length()), location);
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
