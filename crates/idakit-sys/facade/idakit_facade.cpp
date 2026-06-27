// idakit facade implementation. Includes the IDA SDK (C++) and exposes a clean C
// ABI. qstrings live and die here; callers get plain copied-out C strings.
//
// Include order mirrors the SDK's own idalib example (idacli.cpp): pro.h, ida.hpp,
// then the specific subsystem headers.

#include <pro.h>
#include <ida.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <bytes.hpp>    // get_bytes
#include <xref.hpp>     // xrefblk_t
#include <typeinf.hpp>  // tinfo_t, udt_type_data_t, print_type
#include <lines.hpp>   // tag_remove
#include <loader.hpp>  // load_plugin
#include <idp.hpp>     // HEXDSP / get_hexdsp
#include <hexrays.hpp>

#include <vector>
#include <set>
#include <string>
#include <cstring>
#include <cstdlib>  // std::abort

#include "idakit_facade.h"

extern "C" size_t idakit_func_qty(void)
{
  return get_func_qty();
}

extern "C" idakit_ea_t idakit_func_ea(size_t n)
{
  func_t *f = getn_func(n);
  return f != nullptr ? (idakit_ea_t)f->start_ea : (idakit_ea_t)BADADDR;
}

extern "C" int64_t idakit_func_name(idakit_ea_t ea, char *buf, size_t cap)
{
  // A C++ exception (e.g. std::bad_alloc from qstring/STL growth) must never unwind across
  // an extern "C" boundary into Rust frames -- that is undefined behavior. Every facade
  // body that can allocate traps it here and aborts rather than letting it escape.
  try
  {
    qstring out;
    ssize_t r = get_func_name(&out, (ea_t)ea);
    if ( r <= 0 )
    {
      if ( cap > 0 )
        buf[0] = 0;
      return r;
    }
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  }
  catch ( ... )
  {
    std::abort();
  }
}

extern "C" int idakit_seg_qty(void)
{
  return get_segm_qty();
}

extern "C" int64_t idakit_seg_name(int n, char *buf, size_t cap)
{
  try
  {
    segment_t *s = getnseg(n);
    if ( s == nullptr )
    {
      if ( cap > 0 )
        buf[0] = 0;
      return -1;
    }
    qstring out;
    get_visible_segm_name(&out, s);
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  }
  catch ( ... )
  {
    std::abort();
  }
}

extern "C" idakit_ea_t idakit_seg_start(int n)
{
  segment_t *s = getnseg(n);
  return s != nullptr ? (idakit_ea_t)s->start_ea : (idakit_ea_t)BADADDR;
}

extern "C" idakit_ea_t idakit_seg_end(int n)
{
  segment_t *s = getnseg(n);
  return s != nullptr ? (idakit_ea_t)s->end_ea : (idakit_ea_t)BADADDR;
}

extern "C" int64_t idakit_get_bytes(idakit_ea_t ea, void *buf, size_t size)
{
  return (int64_t)get_bytes(buf, (ssize_t)size, (ea_t)ea, GMB_READALL);
}

extern "C" size_t idakit_xrefs_to(idakit_ea_t ea, idakit_ea_t *from, uint8_t *type,
                                  uint8_t *iscode, size_t cap)
{
  xrefblk_t xb;
  size_t n = 0;
  for ( bool ok = xb.first_to((ea_t)ea, XREF_NOFLOW); ok; ok = xb.next_to() )
  {
    if ( n < cap )
    {
      from[n] = (idakit_ea_t)xb.from;
      type[n] = xb.type;
      iscode[n] = xb.iscode;
    }
    ++n;
  }
  return n;
}

extern "C" int64_t idakit_func_type(idakit_ea_t ea, char *buf, size_t cap)
{
  try
  {
    qstring out;
    if ( !print_type(&out, (ea_t)ea, PRTYPE_1LINE | PRTYPE_SEMI) )
    {
      if ( cap > 0 )
        buf[0] = 0;
      return -1;
    }
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  }
  catch ( ... )
  {
    std::abort();
  }
}

// A resolved named type plus its expanded member layout (if it is a struct/union).
struct idakit_type_t
{
  tinfo_t tif;
  udt_type_data_t udt;
  bool is_udt = false;
};

extern "C" void *idakit_type_open(const char *name)
{
  try
  {
    idakit_type_t *t = new idakit_type_t;
    if ( !t->tif.get_named_type(get_idati(), name) )
    {
      delete t;
      return nullptr;
    }
    t->is_udt = t->tif.get_udt_details(&t->udt);
    return t;
  }
  catch ( ... )
  {
    std::abort();
  }
}

extern "C" void idakit_type_dispose(void *h)
{
  delete reinterpret_cast<idakit_type_t *>(h);
}

extern "C" int64_t idakit_type_size(void *h)
{
  size_t s = reinterpret_cast<idakit_type_t *>(h)->tif.get_size();
  return s == BADSIZE ? -1 : (int64_t)s;
}

extern "C" int64_t idakit_type_print(void *h, char *buf, size_t cap)
{
  try
  {
    qstring out;
    if ( !reinterpret_cast<idakit_type_t *>(h)->tif.print(&out) )
    {
      if ( cap > 0 )
        buf[0] = 0;
      return -1;
    }
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  }
  catch ( ... )
  {
    std::abort();
  }
}

extern "C" size_t idakit_type_nmembers(void *h)
{
  idakit_type_t *t = reinterpret_cast<idakit_type_t *>(h);
  return t->is_udt ? t->udt.size() : 0;
}

// Split into a metadata call + two length-returning string getters so the caller
// can detect truncation and re-read; a combined call could only return a bool.
extern "C" int idakit_type_member_info(void *h, size_t i, uint64_t *offset, uint64_t *size)
{
  idakit_type_t *t = reinterpret_cast<idakit_type_t *>(h);
  if ( !t->is_udt || i >= t->udt.size() )
    return 0;
  const udm_t &m = t->udt[i];
  *offset = m.offset / 8;  // SDK reports member offset/size in bits
  *size = m.size / 8;
  return 1;
}

extern "C" int64_t idakit_type_member_name(void *h, size_t i, char *buf, size_t cap)
{
  idakit_type_t *t = reinterpret_cast<idakit_type_t *>(h);
  if ( !t->is_udt || i >= t->udt.size() )
  {
    if ( cap > 0 )
      buf[0] = 0;
    return -1;
  }
  const qstring &name = t->udt[i].name;
  qstrncpy(buf, name.c_str(), cap);
  return (int64_t)name.length();
}

extern "C" int64_t idakit_type_member_type(void *h, size_t i, char *buf, size_t cap)
{
  try
  {
    idakit_type_t *t = reinterpret_cast<idakit_type_t *>(h);
    if ( !t->is_udt || i >= t->udt.size() )
    {
      if ( cap > 0 )
        buf[0] = 0;
      return -1;
    }
    qstring ts;
    t->udt[i].type.print(&ts);
    qstrncpy(buf, ts.c_str(), cap);
    return (int64_t)ts.length();
  }
  catch ( ... )
  {
    std::abort();
  }
}

extern "C" size_t idakit_type_ordinal_count(void)
{
  return get_ordinal_count(get_idati());
}

extern "C" int64_t idakit_type_ordinal_name(uint32_t ordinal, char *buf, size_t cap)
{
  const char *nm = get_numbered_type_name(get_idati(), ordinal);
  if ( nm == nullptr )
  {
    if ( cap > 0 )
      buf[0] = 0;
    return -1;
  }
  qstrncpy(buf, nm, cap);
  return (int64_t)qstrlen(nm);
}

// The decompiler is a plugin; init_hexrays_plugin() wires HEXDSP via callui
// broadcast once the plugin is loaded. Headless, load hexx64 explicitly if needed.
extern "C" int idakit_hexrays_init(void)
{
  if ( init_hexrays_plugin() )
    return 1;
  load_plugin("hexx64");
  return init_hexrays_plugin() ? 1 : 0;
}

// On failure returns NULL and copies the reason into errbuf (the Hex-Rays
// `hexrays_failure_t`, which is the real channel for decompile errors -- IDA's
// thread-local `qerrno` is not set on this path).
extern "C" void *idakit_decompile(idakit_ea_t ea, char *errbuf, size_t cap)
{
  try
  {
    if ( cap > 0 )
      errbuf[0] = 0;
    func_t *pfn = get_func((ea_t)ea);
    if ( pfn == nullptr )
    {
      qstrncpy(errbuf, "no function at address", cap);
      return nullptr;
    }
    hexrays_failure_t hf;
    cfuncptr_t cf = decompile_func(pfn, &hf, 0);
    if ( cf == nullptr )
    {
      qstring desc = hf.desc();
      qstrncpy(errbuf, desc.c_str(), cap);
      return nullptr;
    }
    // Own a ref on the heap so the result survives past this call.
    return new cfuncptr_t(cf);
  }
  catch ( ... )
  {
    std::abort();
  }
}

extern "C" void idakit_cfunc_dispose(void *h)
{
  delete reinterpret_cast<cfuncptr_t *>(h);
}

extern "C" int64_t idakit_cfunc_pseudocode(void *h, char *buf, size_t cap)
{
  if ( h == nullptr )
    return -1;
  try
  {
    cfunc_t *cf = *reinterpret_cast<cfuncptr_t *>(h);
    const strvec_t &sv = cf->get_pseudocode();
    qstring out;
    for ( size_t i = 0; i < sv.size(); ++i )
    {
      qstring line;
      tag_remove(&line, sv[i].line);
      out.append(line);
      out.append('\n');
    }
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  }
  catch ( ... )
  {
    std::abort();
  }
}

// Read-only ctree traversal: count statements, expressions, and call sites.
// CV_FAST = don't maintain a parent stack (we don't need it here).
struct ctree_counter_t : public ctree_visitor_t
{
  int n_insn = 0;
  int n_expr = 0;
  int n_calls = 0;
  ctree_counter_t() : ctree_visitor_t(CV_FAST) {}
  int idaapi visit_insn(cinsn_t *) override
  {
    ++n_insn;
    return 0;
  }
  int idaapi visit_expr(cexpr_t *e) override
  {
    ++n_expr;
    if ( e->op == cot_call )
      ++n_calls;
    return 0;
  }
};

extern "C" void idakit_cfunc_ctree_counts(void *h, int *n_insn, int *n_expr, int *n_calls)
{
  if ( h == nullptr )
  {
    *n_insn = *n_expr = *n_calls = 0;
    return;
  }
  try
  {
    cfunc_t *cf = *reinterpret_cast<cfuncptr_t *>(h);
    ctree_counter_t v;
    v.apply_to(&cf->body, nullptr);
    *n_insn = v.n_insn;
    *n_expr = v.n_expr;
    *n_calls = v.n_calls;
  }
  catch ( ... )
  {
    std::abort();
  }
}

// Streaming ctree walk. The facade reads the SDK ctree depth-first and, per node, calls
// one Rust callback in `v` to mint the owned node; children are emitted before parents,
// so each call receives its children as the handles their own callbacks returned. The
// facade interns nothing: named types are referenced by name (recursion-safe) and filled
// once, guarded by `defined`. All identity, dedup, and meaning live on the Rust side.
namespace {

struct walker_t
{
  const idakit_emit_vtbl_t *v;
  void *ctx;
  std::set<std::string> defined; // named types already filled (recursion + dedup guard)

  // Mint the handle for a type, recursing into its components. Named aggregates resolve
  // through a by-name placeholder so a recursive member can point back before the body
  // is filled; structural types (ptr/array/func/scalar) are emitted directly.
  // A typedef alias resolves all structural predicates through to its target, so it must
  // be intercepted before them; everything else dispatches on the resolved shape.
  uint32_t ty(const tinfo_t &t)
  {
    if ( !t.empty() && t.is_typedef() )
      return ty_typedef(t);
    return ty_resolved(t);
  }

  uint32_t ty_resolved(const tinfo_t &t)
  {
    size_t sz = t.get_size();
    uint32_t has_size = (sz != BADSIZE && sz != 0) ? 1 : 0;
    uint64_t size = has_size ? (uint64_t)sz : 0;

    if ( t.empty() )       return v->t_scalar(ctx, 0, 0, 0, size, has_size);
    if ( t.is_ptr() )      return v->t_ptr(ctx, ty(t.get_pointed_object()), size, has_size);
    if ( t.is_array() )    return v->t_array(ctx, ty(t.get_array_element()),
                                             (uint64_t)t.get_array_nelems(), size, has_size);
    if ( t.is_func() )     return ty_func(t);
    if ( t.is_udt() )      return ty_udt(t, size, has_size);
    if ( t.is_enum() )     return ty_enum(t, size, has_size);
    if ( t.is_bool() )     return v->t_scalar(ctx, 2, 0, 0, size, has_size);
    if ( t.is_void() )     return v->t_scalar(ctx, 1, 0, 0, size, has_size);
    if ( t.is_floating() ) return v->t_scalar(ctx, 4, (uint32_t)sz, 0, size, has_size);
    if ( t.is_integral() ) return v->t_scalar(ctx, 3, (uint32_t)sz, t.is_signed() ? 1 : 0,
                                              size, has_size);
    return v->t_scalar(ctx, 0, 0, 0, size, has_size); // unknown
  }

  // Mint a placeholder: by name (deduped, recursion-safe) for a named aggregate, fresh
  // for an anonymous one. `*first` reports whether the body still needs filling.
  uint32_t placeholder(const tinfo_t &t, bool *first)
  {
    qstring nm;
    if ( t.get_type_name(&nm) && !nm.empty() )
    {
      uint32_t id = v->t_named_ref(ctx, nm.c_str(), nm.length());
      *first = defined.insert(std::string(nm.c_str(), nm.length())).second;
      return id;
    }
    *first = true;
    return v->t_anon(ctx);
  }

  uint32_t ty_udt(const tinfo_t &t, uint64_t size, uint32_t has_size)
  {
    bool first;
    uint32_t id = placeholder(t, &first);
    if ( first )
    {
      udt_type_data_t udt;
      std::vector<idakit_member_t> ms;
      if ( t.get_udt_details(&udt) )
      {
        ms.reserve(udt.size());
        for ( const udm_t &m : udt )
        {
          idakit_member_t md;
          md.name = m.name.c_str();
          md.name_len = m.name.length();
          md.bit_offset = m.offset;
          md.ty = ty(m.type);
          md.bitfield_width = m.is_bitfield() ? (uint32_t)m.size : 0;
          ms.push_back(md);
        }
      }
      v->t_fill_struct(ctx, id, t.is_union() ? 1 : 0, ms.data(), ms.size(), size, has_size);
    }
    return id;
  }

  uint32_t ty_enum(const tinfo_t &t, uint64_t size, uint32_t has_size)
  {
    bool first;
    uint32_t id = placeholder(t, &first);
    if ( first )
    {
      enum_type_data_t ed;
      std::vector<idakit_enum_const_t> cs;
      bool sgn = false;
      if ( t.get_enum_details(&ed) )
      {
        sgn = ed.is_number_signed();
        cs.reserve(ed.size());
        for ( const edm_t &m : ed )
          cs.push_back({ m.name.c_str(), m.name.length(), m.value });
      }
      uint32_t base_bytes = has_size ? (uint32_t)size : 4;
      uint32_t underlying = v->t_scalar(ctx, 3, base_bytes, sgn ? 1 : 0, size, has_size);
      v->t_fill_enum(ctx, id, underlying, cs.data(), cs.size(), size, has_size);
    }
    return id;
  }

  // A typedef link (`typedef T alias;`). Keep the alias name and peel exactly one level to
  // its target, so a chain (alias -> alias -> base) unwinds link by link. A named target
  // (another typedef, a struct/enum) is reached by name; an unnamed structural target has
  // no name to conflate with the alias, so it resolves straight off this same tinfo.
  uint32_t ty_typedef(const tinfo_t &t)
  {
    bool first;
    uint32_t id = placeholder(t, &first); // keyed by the alias name
    if ( first )
    {
      qstring next;
      tinfo_t und;
      uint32_t under;
      if ( t.get_next_type_name(&next)
        && und.get_named_type(get_idati(), next.c_str(), BTF_TYPEDEF, false) )
        under = ty(und);
      else
        under = ty_resolved(t);
      v->t_fill_typedef(ctx, id, under);
    }
    return id;
  }

  uint32_t ty_func(const tinfo_t &t)
  {
    func_type_data_t fd;
    std::vector<uint32_t> params;
    uint32_t ret;
    uint32_t vararg = 0;
    if ( t.get_func_details(&fd) )
    {
      ret = ty(fd.rettype);
      params.reserve(fd.size());
      for ( const funcarg_t &a : fd )
        params.push_back(ty(a.type));
      vararg = fd.is_vararg_cc() ? 1 : 0;
    }
    else
    {
      ret = v->t_scalar(ctx, 0, 0, 0, 0, 0);
    }
    return v->t_func(ctx, ret, params.data(), params.size(), vararg);
  }

  uint32_t expr(const cexpr_t *e)
  {
    ea_t ea = e->ea;
    uint32_t t = ty(e->type);
    switch ( e->op )
    {
      case cot_num: return v->e_num(ctx, ea, e->n->value(e->type), t);
      case cot_fnum:
      {
        double d = 0.0;
        e->fpc->fnum.to_double(&d);
        return v->e_fnum(ctx, ea, d, t);
      }
      case cot_obj:
      {
        qstring nm;
        get_name(&nm, e->obj_ea);
        return v->e_obj(ctx, ea, (uint64_t)e->obj_ea, nm.c_str(), nm.length(), t);
      }
      case cot_var:    return v->e_var(ctx, ea, (uint32_t)e->v.idx, t);
      case cot_str:    return v->e_str(ctx, ea,
                                       e->string != nullptr ? e->string : "",
                                       e->string != nullptr ? strlen(e->string) : 0, t);
      case cot_helper: return v->e_helper(ctx, ea,
                                          e->helper != nullptr ? e->helper : "",
                                          e->helper != nullptr ? strlen(e->helper) : 0, t);
      case cot_ptr:    return v->e_deref(ctx, ea, expr(e->x), (uint32_t)e->ptrsize, t);
      case cot_memref: return v->e_memref(ctx, ea, expr(e->x), e->m, t);
      case cot_memptr: return v->e_memptr(ctx, ea, expr(e->x), e->m, t);
      case cot_call:
      {
        uint32_t callee = expr(e->x);
        std::vector<uint32_t> args;
        if ( e->a != nullptr )
        {
          args.reserve(e->a->size());
          for ( const carg_t &arg : *e->a )
            args.push_back(expr(&arg));
        }
        return v->e_call(ctx, ea, callee, args.data(), args.size(), t);
      }
      default:
      {
        // Binary/assign/unary/ternary/cast/index/sizeof/empty/type/insn: operands by the
        // SDK's own predicates, ctype passed raw for the Rust side to classify.
        uint32_t x = op_uses_x(e->op) ? expr(e->x) : IDAKIT_NONE;
        uint32_t y = op_uses_y(e->op) ? expr(e->y) : IDAKIT_NONE;
        uint32_t z = op_uses_z(e->op) ? expr(e->z) : IDAKIT_NONE;
        return v->e_op(ctx, ea, (uint32_t)e->op, x, y, z, t);
      }
    }
  }

  uint32_t opt_expr(const cexpr_t *e)
  {
    return (e == nullptr || e->op == cot_empty) ? IDAKIT_NONE : expr(e);
  }

  uint32_t block(const cinsn_list_t &list, ea_t ea)
  {
    std::vector<uint32_t> kids;
    kids.reserve(list.size());
    for ( const cinsn_t &child : list )
      kids.push_back(stmt(&child));
    return v->s_block(ctx, ea, kids.data(), kids.size());
  }

  uint32_t stmt(const cinsn_t *i)
  {
    ea_t ea = i->ea;
    switch ( i->op )
    {
      case cit_block: return block(*i->cblock, ea);
      case cit_expr:  return v->s_expr(ctx, ea, expr(i->cexpr));
      case cit_if:
      {
        uint32_t c = expr(&i->cif->expr);
        uint32_t th = stmt(i->cif->ithen);
        uint32_t el = i->cif->ielse != nullptr ? stmt(i->cif->ielse) : IDAKIT_NONE;
        return v->s_if(ctx, ea, c, th, el);
      }
      case cit_for:
      {
        uint32_t in = opt_expr(&i->cfor->init);
        uint32_t co = opt_expr(&i->cfor->expr);
        uint32_t st = opt_expr(&i->cfor->step);
        return v->s_for(ctx, ea, in, co, st, stmt(i->cfor->body));
      }
      case cit_while:
      {
        uint32_t c = expr(&i->cwhile->expr);
        return v->s_while(ctx, ea, c, stmt(i->cwhile->body));
      }
      case cit_do:
      {
        uint32_t b = stmt(i->cdo->body);
        return v->s_do(ctx, ea, b, expr(&i->cdo->expr));
      }
      case cit_switch:
      {
        uint32_t ex = expr(&i->cswitch->expr);
        // Reserve so element addresses stay stable while `cs` references into `vals`.
        std::vector<std::vector<uint64_t>> vals;
        std::vector<idakit_case_t> cs;
        vals.reserve(i->cswitch->cases.size());
        cs.reserve(i->cswitch->cases.size());
        for ( const ccase_t &c : i->cswitch->cases )
        {
          std::vector<uint64_t> vv;
          vv.reserve(c.values.size());
          for ( uint64 val : c.values )
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
      case cit_return:   return v->s_return(ctx, ea, opt_expr(&i->creturn->expr));
      case cit_goto:     return v->s_goto(ctx, ea, (int32_t)i->cgoto->label_num);
      case cit_asm:
      {
        std::vector<uint64_t> addrs;
        addrs.reserve(i->casm->size());
        for ( ea_t a : *i->casm )
          addrs.push_back((uint64_t)a);
        return v->s_asm(ctx, ea, addrs.data(), addrs.size());
      }
      case cit_throw:    return v->s_throw(ctx, ea, opt_expr(&i->cthrow->expr));
      case cit_try:
      {
        // ctry is-a cblock (the guarded body); each catch is a cblock too.
        uint32_t body = block(*i->ctry, ea);
        std::vector<uint32_t> catches;
        catches.reserve(i->ctry->catchs.size());
        for ( const ccatch_t &cat : i->ctry->catchs )
          catches.push_back(block(cat, ea));
        return v->s_try(ctx, ea, body, catches.data(), catches.size());
      }
      case cit_break:    return v->s_break(ctx, ea);
      case cit_continue: return v->s_continue(ctx, ea);
      case cit_empty:    return v->s_empty(ctx, ea);
      default:           return v->s_empty(ctx, ea);
    }
  }

  // Emit the lvar table in index order, so `e_var.idx` resolves against it.
  void lvars(cfunc_t *cf)
  {
    lvars_t *lv = cf->get_lvars();
    if ( lv == nullptr )
      return;
    for ( const lvar_t &l : *lv )
    {
      uint32_t flags = (l.is_arg_var() ? 1u : 0u)
                     | (l.is_result_var() ? 2u : 0u)
                     | (l.is_used_byref() ? 4u : 0u);
      uint32_t loc_kind = 0;
      int64_t loc_val = 0;
      if ( l.is_stk_var() )      { loc_kind = 2; loc_val = (int64_t)l.get_stkoff(); }
      else if ( l.is_reg_var() ) { loc_kind = 1; loc_val = (int64_t)l.get_reg1(); }
      v->l_lvar(ctx, l.name.c_str(), l.name.length(), ty(l.tif), flags, (uint32_t)l.width,
                l.cmt.c_str(), l.cmt.length(), loc_kind, loc_val);
    }
  }
};

} // namespace

extern "C" int idakit_cfunc_walk_ctree(void *h, const idakit_emit_vtbl_t *v, void *ctx,
                                       uint32_t *root)
{
  if ( h == nullptr || v == nullptr || root == nullptr )
    return 1;
  try
  {
    cfunc_t *cf = *reinterpret_cast<cfuncptr_t *>(h);

    walker_t w;
    w.v = v;
    w.ctx = ctx;
    w.lvars(cf);
    *root = w.stmt(&cf->body);
    return 0;
  }
  catch ( ... )
  {
    std::abort();
  }
}
