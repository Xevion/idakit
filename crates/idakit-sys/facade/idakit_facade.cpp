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
