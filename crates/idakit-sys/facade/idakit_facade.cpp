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
#include <map>
#include <string>
#include <cstring>

#include "idakit_facade.h"

// These must match the `#[repr(C)]` structs in idakit-sys and idakit's `tk` codes.
static_assert(sizeof(idakit_expr_rec_t) == 40, "ExprRec layout");
static_assert(sizeof(idakit_stmt_rec_t) == 40, "StmtRec layout");
static_assert(sizeof(idakit_type_rec_t) == 40, "TypeRec layout");
static_assert(sizeof(idakit_case_rec_t) == 16, "CaseRec layout");

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

extern "C" int idakit_seg_qty(void)
{
  return get_segm_qty();
}

extern "C" int64_t idakit_seg_name(int n, char *buf, size_t cap)
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

// A resolved named type plus its expanded member layout (if it is a struct/union).
struct idakit_type_t
{
  tinfo_t tif;
  udt_type_data_t udt;
  bool is_udt = false;
};

extern "C" void *idakit_type_open(const char *name)
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

extern "C" void idakit_cfunc_dispose(void *h)
{
  delete reinterpret_cast<cfuncptr_t *>(h);
}

extern "C" int64_t idakit_cfunc_pseudocode(void *h, char *buf, size_t cap)
{
  if ( h == nullptr )
    return -1;
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
  cfunc_t *cf = *reinterpret_cast<cfuncptr_t *>(h);
  ctree_counter_t v;
  v.apply_to(&cf->body, nullptr);
  *n_insn = v.n_insn;
  *n_expr = v.n_expr;
  *n_calls = v.n_calls;
}

// Flat ctree extraction. One depth-first walk emits records in post-order (each node's
// children and type precede it), so every reference points backwards. Operators emit
// their raw `ctype_t` as the tag and fill operands generically via op_uses_x/y/z; only
// the leaves and variadic kinds need bespoke handling. All meaning is reconstructed on
// the Rust side -- this side is a dumb transcriber.
namespace {

// Type-kind codes, matching idakit's `tk` module.
enum {
  TK_UNKNOWN = 0, TK_VOID = 1, TK_BOOL = 2, TK_INT = 3,
  TK_FLOAT = 4, TK_PTR = 5, TK_ARRAY = 6, TK_NAMED = 7,
};

const uint32_t NONE = 0xFFFFFFFFu; // absent optional edge

struct image_t
{
  std::vector<idakit_type_rec_t> types;
  std::vector<idakit_expr_rec_t> exprs;
  std::vector<idakit_stmt_rec_t> stmts;
  std::vector<uint32_t> nodes;
  std::vector<uint8_t> bytes;
  std::vector<uint64_t> longs;
  std::vector<idakit_case_rec_t> cases;
  std::map<std::string, uint32_t> type_cache;
  uint32_t root = 0;

  // Append a string to the bytes pool; report its [offset, length).
  void add_str(const char *s, uint32_t *off, uint32_t *len)
  {
    size_t n = s != nullptr ? strlen(s) : 0;
    *off = (uint32_t)bytes.size();
    *len = (uint32_t)n;
    bytes.insert(bytes.end(), s, s + n);
  }

  // Intern a type, decomposing scalars/pointers/arrays and falling back to a printed
  // name for aggregates (full struct/enum/func extraction is a later pass). Deduped by
  // printed form; children are interned first, so they get smaller indices.
  uint32_t intern_type(const tinfo_t &t)
  {
    qstring key;
    t.print(&key);
    std::string k(key.c_str(), key.length());
    auto it = type_cache.find(k);
    if ( it != type_cache.end() )
      return it->second;

    idakit_type_rec_t r;
    memset(&r, 0, sizeof(r));
    size_t sz = t.get_size();
    if ( sz != BADSIZE && sz != 0 )
    {
      r.has_size = 1;
      r.size = sz;
    }
    if ( t.empty() )
      r.tag = TK_UNKNOWN;
    else if ( t.is_void() )
      r.tag = TK_VOID;
    else if ( t.is_bool() )
      r.tag = TK_BOOL;
    else if ( t.is_floating() )
    {
      r.tag = TK_FLOAT;
      r.bytes = (uint32_t)sz;
    }
    else if ( t.is_integral() )
    {
      r.tag = TK_INT;
      r.bytes = (uint32_t)sz;
      r.is_signed = t.is_signed() ? 1 : 0;
    }
    else if ( t.is_ptr() )
    {
      uint32_t target = intern_type(t.get_pointed_object());
      r.tag = TK_PTR;
      r.a = target;
    }
    else if ( t.is_array() )
    {
      uint32_t elem = intern_type(t.get_array_element());
      r.tag = TK_ARRAY;
      r.a = elem;
      r.aux = (uint64_t)t.get_array_nelems();
    }
    else
    {
      r.tag = TK_NAMED;
      add_str(key.c_str(), &r.a, &r.b);
    }

    uint32_t idx = (uint32_t)types.size();
    types.push_back(r);
    type_cache[k] = idx;
    return idx;
  }

  uint32_t emit_expr(const cexpr_t *e)
  {
    idakit_expr_rec_t r;
    memset(&r, 0, sizeof(r));
    r.ea = (uint64_t)e->ea;
    r.tag = (uint32_t)e->op;
    r.ty = intern_type(e->type);
    switch ( e->op )
    {
      case cot_num:    r.aux = e->n->value(e->type); break;
      case cot_fnum:   r.aux = 0; break; // TODO: decode fnumber_t -> f64 bits
      case cot_obj:    r.aux = (uint64_t)e->obj_ea; break;
      case cot_var:    r.a = (uint32_t)e->v.idx; break;
      case cot_str:    add_str(e->string, &r.a, &r.b); break;
      case cot_helper: add_str(e->helper, &r.a, &r.b); break;
      case cot_ptr:    r.a = emit_expr(e->x); r.b = (uint32_t)e->ptrsize; break;
      case cot_memref:
      case cot_memptr: r.a = emit_expr(e->x); r.b = e->m; break;
      case cot_call:
      {
        r.a = emit_expr(e->x);
        std::vector<uint32_t> args;
        if ( e->a != nullptr )
          for ( const carg_t &arg : *e->a )
            args.push_back(emit_expr(&arg));
        r.b = (uint32_t)nodes.size();
        r.c = (uint32_t)args.size();
        nodes.insert(nodes.end(), args.begin(), args.end());
      }
      break;
      default:
        // Binary/unary/ternary/index/cast/sizeof: operands by the SDK's own predicates.
        if ( op_uses_x(e->op) ) r.a = emit_expr(e->x);
        if ( op_uses_y(e->op) ) r.b = emit_expr(e->y);
        if ( op_uses_z(e->op) ) r.c = emit_expr(e->z);
        break;
    }
    uint32_t idx = (uint32_t)exprs.size();
    exprs.push_back(r);
    return idx;
  }

  uint32_t emit_opt_expr(const cexpr_t *e)
  {
    return (e == nullptr || e->op == cot_empty) ? NONE : emit_expr(e);
  }

  // Emit a statement list as a `cit_block` record (children first).
  uint32_t emit_block(const cinsn_list_t &list, ea_t ea)
  {
    std::vector<uint32_t> kids;
    for ( const cinsn_t &child : list )
      kids.push_back(emit_stmt(&child));
    idakit_stmt_rec_t r;
    memset(&r, 0, sizeof(r));
    r.ea = (uint64_t)ea;
    r.tag = cit_block;
    r.a = (uint32_t)nodes.size();
    r.b = (uint32_t)kids.size();
    nodes.insert(nodes.end(), kids.begin(), kids.end());
    uint32_t idx = (uint32_t)stmts.size();
    stmts.push_back(r);
    return idx;
  }

  uint32_t emit_stmt(const cinsn_t *i)
  {
    if ( i->op == cit_block )
      return emit_block(*i->cblock, i->ea);

    idakit_stmt_rec_t r;
    memset(&r, 0, sizeof(r));
    r.ea = (uint64_t)i->ea;
    r.tag = (uint32_t)i->op;
    switch ( i->op )
    {
      case cit_expr: r.a = emit_expr(i->cexpr); break;
      case cit_if:
        r.a = emit_expr(&i->cif->expr);
        r.b = emit_stmt(i->cif->ithen);
        r.c = i->cif->ielse != nullptr ? emit_stmt(i->cif->ielse) : NONE;
        break;
      case cit_for:
        r.a = emit_opt_expr(&i->cfor->init);
        r.b = emit_opt_expr(&i->cfor->expr);
        r.c = emit_opt_expr(&i->cfor->step);
        r.aux = emit_stmt(i->cfor->body);
        break;
      case cit_while:
        r.a = emit_expr(&i->cwhile->expr);
        r.b = emit_stmt(i->cwhile->body);
        break;
      case cit_do:
        r.a = emit_stmt(i->cdo->body);
        r.b = emit_expr(&i->cdo->expr);
        break;
      case cit_switch:
      {
        r.a = emit_expr(&i->cswitch->expr);
        std::vector<idakit_case_rec_t> crs;
        for ( const ccase_t &c : i->cswitch->cases )
        {
          idakit_case_rec_t cr;
          memset(&cr, 0, sizeof(cr));
          cr.values_off = (uint32_t)longs.size();
          cr.values_len = (uint32_t)c.values.size();
          for ( uint64 v : c.values )
            longs.push_back(v);
          cr.body = emit_stmt(&c); // ccase_t is-a cinsn_t
          crs.push_back(cr);
        }
        r.b = (uint32_t)cases.size();
        r.c = (uint32_t)crs.size();
        cases.insert(cases.end(), crs.begin(), crs.end());
      }
      break;
      case cit_return: r.a = emit_opt_expr(&i->creturn->expr); break;
      case cit_goto:   r.a = (uint32_t)i->cgoto->label_num; break;
      case cit_asm:
        r.a = (uint32_t)longs.size();
        r.b = (uint32_t)i->casm->size();
        for ( ea_t a : *i->casm )
          longs.push_back((uint64_t)a);
        break;
      case cit_throw: r.a = emit_opt_expr(&i->cthrow->expr); break;
      case cit_try:
      {
        // ctry is-a cblock (the guarded body); each catch is a cblock too.
        r.a = emit_block(*i->ctry, i->ea);
        std::vector<uint32_t> kids;
        for ( const ccatch_t &cat : i->ctry->catchs )
          kids.push_back(emit_block(cat, i->ea));
        r.b = (uint32_t)nodes.size();
        r.c = (uint32_t)kids.size();
        nodes.insert(nodes.end(), kids.begin(), kids.end());
      }
      break;
      default: break; // cit_break / cit_continue / cit_empty carry nothing
    }
    uint32_t idx = (uint32_t)stmts.size();
    stmts.push_back(r);
    return idx;
  }
};

} // namespace

extern "C" void *idakit_cfunc_extract_ctree(void *h, idakit_ctree_view_t *out)
{
  if ( h == nullptr )
    return nullptr;
  cfunc_t *cf = *reinterpret_cast<cfuncptr_t *>(h);
  image_t *img = new image_t;
  img->root = img->emit_stmt(&cf->body);

  out->types = img->types.data(); out->n_types = img->types.size();
  out->exprs = img->exprs.data(); out->n_exprs = img->exprs.size();
  out->stmts = img->stmts.data(); out->n_stmts = img->stmts.size();
  out->nodes = img->nodes.data(); out->n_nodes = img->nodes.size();
  out->bytes = img->bytes.data(); out->n_bytes = img->bytes.size();
  out->longs = img->longs.data(); out->n_longs = img->longs.size();
  out->cases = img->cases.data(); out->n_cases = img->cases.size();
  out->root = img->root;
  return img;
}

extern "C" void idakit_ctree_dispose(void *h)
{
  delete reinterpret_cast<image_t *>(h);
}
