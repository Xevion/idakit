// idakit facade: database queries -- functions, segments, bytes/item navigation,
// metadata, names, and cross-references.

#include <pro.h>

#include <ida.hpp>

#include <bytes.hpp>
#include <funcs.hpp>
#include <loader.hpp> // get_file_type_name
#include <nalt.hpp>   // get_input_file_path, get_root_filename, get_imagebase
#include <name.hpp>
#include <segment.hpp>
#include <xref.hpp> // xrefblk_t

#include <cstring>

#include "idakit_facade.h"

extern "C" size_t idakit_func_qty(void) { return get_func_qty(); }

extern "C" idakit_ea_t idakit_func_ea(size_t n) {
  func_t *f = getn_func(n);
  return f != nullptr ? (idakit_ea_t)f->start_ea : (idakit_ea_t)BADADDR;
}

extern "C" int64_t idakit_func_name(idakit_ea_t ea, char *buf, size_t cap) {
  // A C++ exception (e.g. std::bad_alloc from qstring/STL growth) must never unwind across
  // an extern "C" boundary into Rust frames -- that is undefined behavior. Every facade
  // body that can allocate traps it here and aborts rather than letting it escape.
  try {
    qstring out;
    ssize_t r = get_func_name(&out, (ea_t)ea);
    if (r <= 0) {
      if (cap > 0)
        buf[0] = 0;
      return r;
    }
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

extern "C" int idakit_func_chunk_qty(idakit_ea_t ea) {
  func_t *pfn = get_func((ea_t)ea);
  if (pfn == nullptr)
    return 0;
  int n = 0;
  func_tail_iterator_t fti(pfn);
  for (bool ok = fti.main(); ok; ok = fti.next())
    n++;
  return n;
}

// main() yields the entry chunk first, then next() walks the tails; a single-chunk function
// is just the entry chunk. get_func locks nothing lasting -- the iterator's dtor unlocks.
extern "C" int idakit_func_chunk(idakit_ea_t ea, int idx, idakit_ea_t *start, idakit_ea_t *end) {
  func_t *pfn = get_func((ea_t)ea);
  if (pfn == nullptr)
    return 0;
  int n = 0;
  func_tail_iterator_t fti(pfn);
  for (bool ok = fti.main(); ok; ok = fti.next(), n++) {
    if (n == idx) {
      const range_t &r = fti.chunk();
      *start = (idakit_ea_t)r.start_ea;
      *end = (idakit_ea_t)r.end_ea;
      return 1;
    }
  }
  return 0;
}

extern "C" int idakit_seg_qty(void) { return get_segm_qty(); }

extern "C" int64_t idakit_seg_name(int n, char *buf, size_t cap) {
  try {
    segment_t *s = getnseg(n);
    if (s == nullptr) {
      if (cap > 0)
        buf[0] = 0;
      return -1;
    }
    qstring out;
    get_visible_segm_name(&out, s);
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

extern "C" idakit_ea_t idakit_seg_start(int n) {
  segment_t *s = getnseg(n);
  return s != nullptr ? (idakit_ea_t)s->start_ea : (idakit_ea_t)BADADDR;
}

extern "C" idakit_ea_t idakit_seg_end(int n) {
  segment_t *s = getnseg(n);
  return s != nullptr ? (idakit_ea_t)s->end_ea : (idakit_ea_t)BADADDR;
}

extern "C" int64_t idakit_get_bytes(idakit_ea_t ea, void *buf, size_t size) {
  return (int64_t)get_bytes(buf, (ssize_t)size, (ea_t)ea, GMB_READALL);
}

extern "C" uint64_t idakit_get_flags(idakit_ea_t ea) { return (uint64_t)get_flags((ea_t)ea); }

extern "C" idakit_ea_t idakit_get_item_head(idakit_ea_t ea) {
  return (idakit_ea_t)get_item_head((ea_t)ea);
}

extern "C" idakit_ea_t idakit_get_item_end(idakit_ea_t ea) {
  return (idakit_ea_t)get_item_end((ea_t)ea);
}

extern "C" idakit_ea_t idakit_get_next_head(idakit_ea_t ea, idakit_ea_t maxea) {
  return (idakit_ea_t)next_head((ea_t)ea, (ea_t)maxea);
}

extern "C" idakit_ea_t idakit_get_prev_head(idakit_ea_t ea, idakit_ea_t minea) {
  return (idakit_ea_t)prev_head((ea_t)ea, (ea_t)minea);
}

extern "C" int idakit_bitness(void) { return (int)inf_get_app_bitness(); }

extern "C" idakit_ea_t idakit_image_base(void) { return (idakit_ea_t)get_imagebase(); }

extern "C" int64_t idakit_proc_name(char *buf, size_t cap) {
  try {
    qstring out = inf_get_procname();
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

extern "C" int64_t idakit_file_type_name(char *buf, size_t cap) {
  // get_file_type_name writes directly and returns the length it produced.
  return (int64_t)get_file_type_name(buf, cap);
}

extern "C" int64_t idakit_input_path(char *buf, size_t cap) {
  // get_input_file_path goes through getinf_buf, whose count includes the trailing NUL;
  // report the string length like the other getters so read_string slices it cleanly.
  ssize_t n = get_input_file_path(buf, cap);
  return n > 0 ? (int64_t)(n - 1) : -1;
}

extern "C" int64_t idakit_root_filename(char *buf, size_t cap) {
  return (int64_t)get_root_filename(buf, cap);
}

extern "C" int64_t idakit_get_ea_name(idakit_ea_t ea, char *buf, size_t cap) {
  try {
    qstring out;
    if (get_ea_name(&out, (ea_t)ea) <= 0) {
      if (cap > 0)
        buf[0] = 0;
      return -1;
    }
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

extern "C" idakit_ea_t idakit_get_name_ea(const char *name) {
  return (idakit_ea_t)get_name_ea(BADADDR, name);
}

// Full demangle (disable_mask 0). An unmangled name leaves `out` empty, reported as -1 so
// the caller sees "not mangled" rather than an empty string.
extern "C" int64_t idakit_demangle_name(const char *name, char *buf, size_t cap) {
  try {
    qstring out;
    demangle_name(&out, name, 0);
    if (out.empty()) {
      if (cap > 0)
        buf[0] = 0;
      return -1;
    }
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

extern "C" size_t idakit_nlist_size(void) { return get_nlist_size(); }

extern "C" idakit_ea_t idakit_nlist_ea(size_t idx) { return (idakit_ea_t)get_nlist_ea(idx); }

extern "C" int64_t idakit_nlist_name(size_t idx, char *buf, size_t cap) {
  const char *nm = get_nlist_name(idx);
  if (nm == nullptr) {
    if (cap > 0)
      buf[0] = 0;
    return -1;
  }
  qstrncpy(buf, nm, cap);
  return (int64_t)qstrlen(nm);
}

// Cursor state for a streaming xref walk. `started` distinguishes the first_* call
// (which seeds the block) from subsequent next_* steps.
struct idakit_xref_cursor {
  xrefblk_t xb;
  ea_t ea;
  bool is_to;
  bool started;
};

extern "C" void *idakit_xref_open(idakit_ea_t ea, uint8_t is_to) {
  auto *c = new idakit_xref_cursor;
  c->ea = (ea_t)ea;
  c->is_to = is_to != 0;
  c->started = false;
  return c;
}

extern "C" uint8_t idakit_xref_next(void *cursor, idakit_ea_t *from, idakit_ea_t *to, uint8_t *type,
                                    uint8_t *iscode) {
  auto *c = (idakit_xref_cursor *)cursor;
  bool ok;
  if (!c->started) {
    c->started = true;
    ok = c->is_to ? c->xb.first_to(c->ea, XREF_NOFLOW) : c->xb.first_from(c->ea, XREF_NOFLOW);
  } else {
    ok = c->is_to ? c->xb.next_to() : c->xb.next_from();
  }
  if (!ok)
    return 0;
  *from = (idakit_ea_t)c->xb.from;
  *to = (idakit_ea_t)c->xb.to;
  *type = c->xb.type;
  *iscode = c->xb.iscode;
  return 1;
}

extern "C" void idakit_xref_close(void *cursor) { delete (idakit_xref_cursor *)cursor; }
