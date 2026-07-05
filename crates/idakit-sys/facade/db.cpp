// idakit facade: database queries -- functions, segments, bytes/item navigation,
// metadata, names, and cross-references.

#include <pro.h>

#include <ida.hpp>

#include <bytes.hpp>
#include <funcs.hpp>
#include <gdl.hpp>    // qflow_chart_t
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

extern "C" idakit_ea_t idakit_func_end(idakit_ea_t ea) {
  func_t *f = get_func((ea_t)ea);
  return f != nullptr ? (idakit_ea_t)f->end_ea : (idakit_ea_t)BADADDR;
}

extern "C" uint64_t idakit_func_flags(idakit_ea_t ea) {
  func_t *f = get_func((ea_t)ea);
  return f != nullptr ? (uint64_t)f->flags : 0;
}

// Passing pfn with BADADDR bounds builds the flow chart over the whole function, tail chunks
// included; the constructor's refresh() materializes every block up front. Allocates and runs
// analysis, so it can throw -- guard the boundary.
extern "C" void *idakit_cfg_build(idakit_ea_t ea, int flags) {
  try {
    func_t *pfn = get_func((ea_t)ea);
    if (pfn == nullptr)
      return nullptr;
    return new qflow_chart_t("", pfn, BADADDR, BADADDR, flags);
  } catch (...) {
    std::abort();
  }
}

extern "C" int idakit_cfg_nblocks(const void *h) {
  const qflow_chart_t *fc = (const qflow_chart_t *)h;
  return fc != nullptr ? (int)fc->blocks.size() : 0;
}

extern "C" int idakit_cfg_nproper(const void *h) {
  const qflow_chart_t *fc = (const qflow_chart_t *)h;
  return fc != nullptr ? fc->nproper : 0;
}

extern "C" int idakit_cfg_block(const void *h, int n, idakit_ea_t *start, idakit_ea_t *end,
                                int *kind) {
  const qflow_chart_t *fc = (const qflow_chart_t *)h;
  if (fc == nullptr || n < 0 || (size_t)n >= fc->blocks.size())
    return 0;
  const qbasic_block_t &b = fc->blocks[n];
  *start = (idakit_ea_t)b.start_ea;
  *end = (idakit_ea_t)b.end_ea;
  *kind = (int)fc->calc_block_type((size_t)n);
  return 1;
}

extern "C" int idakit_cfg_nsucc(const void *h, int n) {
  const qflow_chart_t *fc = (const qflow_chart_t *)h;
  if (fc == nullptr || n < 0 || (size_t)n >= fc->blocks.size())
    return 0;
  return fc->nsucc(n);
}

extern "C" int idakit_cfg_succ(const void *h, int n, int i) {
  const qflow_chart_t *fc = (const qflow_chart_t *)h;
  if (fc == nullptr || n < 0 || (size_t)n >= fc->blocks.size() || i < 0 || i >= fc->nsucc(n))
    return -1;
  return fc->succ(n, i);
}

extern "C" int idakit_cfg_npred(const void *h, int n) {
  const qflow_chart_t *fc = (const qflow_chart_t *)h;
  if (fc == nullptr || n < 0 || (size_t)n >= fc->blocks.size())
    return 0;
  return fc->npred(n);
}

extern "C" int idakit_cfg_pred(const void *h, int n, int i) {
  const qflow_chart_t *fc = (const qflow_chart_t *)h;
  if (fc == nullptr || n < 0 || (size_t)n >= fc->blocks.size() || i < 0 || i >= fc->npred(n))
    return -1;
  return fc->pred(n, i);
}

extern "C" void idakit_cfg_free(void *h) { delete (qflow_chart_t *)h; }

extern "C" int idakit_seg_qty(void) { return get_segm_qty(); }

extern "C" int idakit_seg_perm(int n) {
  segment_t *s = getnseg(n);
  return s != nullptr ? (int)s->perm : 0;
}

extern "C" int idakit_seg_bitness(int n) {
  segment_t *s = getnseg(n);
  return s != nullptr ? (int)s->abits() : 0;
}

extern "C" int64_t idakit_seg_class(int n, char *buf, size_t cap) {
  try {
    segment_t *s = getnseg(n);
    qstring out;
    if (s == nullptr || get_segm_class(&out, s) <= 0) {
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

extern "C" idakit_ea_t idakit_min_ea(void) { return (idakit_ea_t)inf_get_min_ea(); }

extern "C" idakit_ea_t idakit_max_ea(void) { return (idakit_ea_t)inf_get_max_ea(); }

extern "C" void *idakit_binpat_compile(idakit_ea_t ea, const char *pattern, int radix, char *errbuf,
                                       size_t errcap) {
  try {
    compiled_binpat_vec_t *out = new compiled_binpat_vec_t;
    qstring err;
    if (!parse_binpat_str(out, (ea_t)ea, pattern, radix, PBSENC_DEF1BPU, &err)) {
      if (errcap > 0)
        qstrncpy(errbuf, err.c_str(), errcap);
      delete out;
      return nullptr;
    }
    return out;
  } catch (...) {
    std::abort();
  }
}

extern "C" void *idakit_binpat_from_bytes(const uint8_t *bytes, const uint8_t *mask, size_t len) {
  try {
    compiled_binpat_vec_t *v = new compiled_binpat_vec_t;
    compiled_binpat_t &b = v->push_back();
    b.bytes.append(bytes, len);
    if (mask != nullptr)
      b.mask.append(mask, len);
    return v;
  } catch (...) {
    std::abort();
  }
}

extern "C" void idakit_binpat_free(void *pat) {
  delete reinterpret_cast<compiled_binpat_vec_t *>(pat);
}

// Fills *total with the compiled pattern's byte length and *anchors with the count of
// concrete (non-wildcard) bytes -- mask[i] != 0, or every byte when the mask is empty.
// IDA's parser silently drops tokens it can't read, so a typo'd pattern lands here with
// anchors == 0: nothing to match on.
extern "C" void idakit_binpat_stats(const void *pat, size_t *total, size_t *anchors) {
  const compiled_binpat_vec_t *v = reinterpret_cast<const compiled_binpat_vec_t *>(pat);
  size_t t = 0, a = 0;
  if (!v->empty()) {
    const compiled_binpat_t &b = v->front();
    t = b.bytes.size();
    if (b.mask.empty()) {
      a = t;
    } else {
      for (size_t i = 0; i < b.mask.size(); i++)
        if (b.mask[i] != 0)
          a++;
    }
  }
  *total = t;
  *anchors = a;
}

extern "C" idakit_ea_t idakit_bin_search(idakit_ea_t start, idakit_ea_t end, const void *pat,
                                         int flags) {
  const compiled_binpat_vec_t *data = reinterpret_cast<const compiled_binpat_vec_t *>(pat);
  // NOBREAK/NOSHOW are mandatory headless: no Ctrl-Break polling, no UI progress.
  ea_t hit =
      bin_search((ea_t)start, (ea_t)end, *data, flags | BIN_SEARCH_NOBREAK | BIN_SEARCH_NOSHOW);
  return (idakit_ea_t)hit;
}

extern "C" int64_t idakit_get_cmt(idakit_ea_t ea, uint8_t rptble, char *buf, size_t cap) {
  try {
    qstring out;
    if (get_cmt(&out, (ea_t)ea, rptble != 0) < 0) {
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

extern "C" int idakit_patch_bytes(idakit_ea_t ea, const void *buf, size_t size) {
  // Reject the whole write if any target byte is outside the address space, so a bad address
  // fails cleanly instead of silently patching a truncated prefix.
  for (size_t i = 0; i < size; i++) {
    if (!is_mapped((ea_t)ea + i))
      return 0;
  }
  patch_bytes((ea_t)ea, buf, size);
  return 1;
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
