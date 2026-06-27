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
