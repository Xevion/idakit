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

// The decompiler is a plugin; init_hexrays_plugin() wires HEXDSP via callui
// broadcast once the plugin is loaded. Headless, load hexx64 explicitly if needed.
extern "C" int idakit_hexrays_init(void)
{
  if ( init_hexrays_plugin() )
    return 1;
  load_plugin("hexx64");
  return init_hexrays_plugin() ? 1 : 0;
}

extern "C" void *idakit_decompile(idakit_ea_t ea)
{
  func_t *pfn = get_func((ea_t)ea);
  if ( pfn == nullptr )
    return nullptr;
  hexrays_failure_t hf;
  cfuncptr_t cf = decompile_func(pfn, &hf, 0);
  if ( cf == nullptr )
    return nullptr;
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
