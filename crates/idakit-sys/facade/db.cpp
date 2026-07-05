// idakit facade: database queries -- functions, segments, bytes/item navigation,
// metadata, names, and cross-references.

#include <pro.h>

#include <ida.hpp>

#include <bytes.hpp>
#include <entry.hpp> // get_entry_qty, get_entry, get_entry_name
#include <frame.hpp> // get_func_frame, get_frame_size, soff_to_fpoff
#include <funcs.hpp>
#include <gdl.hpp>    // qflow_chart_t
#include <loader.hpp> // get_file_type_name
#include <nalt.hpp>   // get_input_file_path, get_root_filename, enum_import_names
#include <name.hpp>
#include <segment.hpp>
#include <strlist.hpp> // build_strlist, get_strlist_item
#include <typeinf.hpp> // tinfo_t, udt_type_data_t, udm_t
#include <xref.hpp>    // xrefblk_t

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

extern "C" size_t idakit_export_qty(void) { return get_entry_qty(); }

extern "C" idakit_ea_t idakit_export_ea(size_t idx) {
  return (idakit_ea_t)get_entry(get_entry_ordinal(idx));
}

extern "C" uint64_t idakit_export_ordinal(size_t idx) { return (uint64_t)get_entry_ordinal(idx); }

extern "C" int64_t idakit_export_name(size_t idx, char *buf, size_t cap) {
  try {
    qstring out;
    ssize_t r = get_entry_name(&out, get_entry_ordinal(idx));
    if (r <= 0) {
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

extern "C" int64_t idakit_export_forwarder(size_t idx, char *buf, size_t cap) {
  try {
    qstring out;
    ssize_t r = get_entry_forwarder(&out, get_entry_ordinal(idx));
    if (r <= 0) {
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

// Imports reach the caller only through enum_import_names' per-name callback, so there is no
// random-access index to expose lazily. The build collects every module's names into one flat,
// owned snapshot the Rust side indexes and then frees.
namespace {

struct import_row_t {
  ea_t ea;
  uval_t ord;   // 0 when imported by name
  qstring name; // empty when imported by ordinal
  qstring module;
};

struct import_list_t {
  qvector<import_row_t> rows;
};

struct import_ctx_t {
  import_list_t *list;
  const qstring *module;
};

int idaapi collect_import(ea_t ea, const char *name, uval_t ord, void *param) {
  import_ctx_t *ctx = (import_ctx_t *)param;
  import_row_t &row = ctx->list->rows.push_back();
  row.ea = ea;
  row.ord = ord;
  if (name != nullptr)
    row.name = name;
  row.module = *ctx->module;
  return 1; // continue enumeration
}

} // namespace

extern "C" void *idakit_imports_build(void) {
  try {
    import_list_t *list = new import_list_t;
    uint nmods = get_import_module_qty();
    for (uint m = 0; m < nmods; m++) {
      qstring module;
      get_import_module_name(&module, (int)m);
      import_ctx_t ctx{list, &module};
      enum_import_names((int)m, collect_import, &ctx);
    }
    return list;
  } catch (...) {
    std::abort();
  }
}

extern "C" size_t idakit_imports_qty(const void *h) {
  const import_list_t *list = (const import_list_t *)h;
  return list != nullptr ? list->rows.size() : 0;
}

extern "C" int idakit_imports_item(const void *h, size_t n, idakit_ea_t *ea, uint64_t *ord) {
  const import_list_t *list = (const import_list_t *)h;
  if (list == nullptr || n >= list->rows.size())
    return 0;
  const import_row_t &row = list->rows[n];
  *ea = (idakit_ea_t)row.ea;
  *ord = (uint64_t)row.ord;
  return 1;
}

extern "C" int64_t idakit_imports_name(const void *h, size_t n, char *buf, size_t cap) {
  const import_list_t *list = (const import_list_t *)h;
  if (list == nullptr || n >= list->rows.size() || list->rows[n].name.empty()) {
    if (cap > 0)
      buf[0] = 0;
    return -1;
  }
  const qstring &name = list->rows[n].name;
  qstrncpy(buf, name.c_str(), cap);
  return (int64_t)name.length();
}

extern "C" int64_t idakit_imports_module(const void *h, size_t n, char *buf, size_t cap) {
  const import_list_t *list = (const import_list_t *)h;
  if (list == nullptr || n >= list->rows.size()) {
    if (cap > 0)
      buf[0] = 0;
    return -1;
  }
  const qstring &module = list->rows[n].module;
  qstrncpy(buf, module.c_str(), cap);
  return (int64_t)module.length();
}

extern "C" void idakit_imports_free(void *h) { delete (import_list_t *)h; }

extern "C" void idakit_strlist_build(void) {
  try {
    build_strlist();
  } catch (...) {
    std::abort();
  }
}

extern "C" size_t idakit_strlist_qty(void) { return get_strlist_qty(); }

extern "C" int idakit_strlist_item(size_t n, idakit_ea_t *ea, int *length, int *type) {
  string_info_t si;
  if (!get_strlist_item(&si, n))
    return 0;
  *ea = (idakit_ea_t)si.ea;
  *length = si.length;
  *type = si.type;
  return 1;
}

extern "C" int64_t idakit_strlit_contents(idakit_ea_t ea, size_t len, int type, char *buf,
                                          size_t cap) {
  try {
    qstring out;
    ssize_t r = get_strlit_contents(&out, (ea_t)ea, len, type, nullptr, STRCONV_REPLCHAR);
    if (r < 0) {
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

extern "C" int64_t idakit_get_bytes(idakit_ea_t ea, void *buf, size_t size) {
  return (int64_t)get_bytes(buf, (ssize_t)size, (ea_t)ea, GMB_READALL);
}

namespace {
// A typed read must fail cleanly on a partly-mapped range, so gate on every covered byte.
bool range_loaded(ea_t ea, size_t n) {
  for (size_t i = 0; i < n; i++)
    if (!is_loaded(ea + i))
      return false;
  return true;
}
} // namespace

extern "C" int idakit_get_u8(idakit_ea_t ea, uint8_t *out) {
  if (!range_loaded((ea_t)ea, 1))
    return 0;
  *out = (uint8_t)get_byte((ea_t)ea);
  return 1;
}

extern "C" int idakit_get_u16(idakit_ea_t ea, uint16_t *out) {
  if (!range_loaded((ea_t)ea, 2))
    return 0;
  *out = (uint16_t)get_word((ea_t)ea);
  return 1;
}

extern "C" int idakit_get_u32(idakit_ea_t ea, uint32_t *out) {
  if (!range_loaded((ea_t)ea, 4))
    return 0;
  *out = (uint32_t)get_dword((ea_t)ea);
  return 1;
}

extern "C" int idakit_get_u64(idakit_ea_t ea, uint64_t *out) {
  if (!range_loaded((ea_t)ea, 8))
    return 0;
  *out = (uint64_t)get_qword((ea_t)ea);
  return 1;
}

extern "C" int64_t idakit_get_strlit(idakit_ea_t ea, int strtype, char *buf, size_t cap) {
  try {
    size_t len = get_max_strlit_length((ea_t)ea, strtype, ALOPT_IGNHEADS);
    if (len == 0) {
      if (cap > 0)
        buf[0] = 0;
      return -1;
    }
    qstring out;
    ssize_t r = get_strlit_contents(&out, (ea_t)ea, len, strtype, nullptr, STRCONV_REPLCHAR);
    if (r < 0) {
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

// A function frame is a UDT tinfo (get_func_frame). We snapshot it -- its size and every
// variable's fp-relative offset (as IDA displays them), byte size, name, type, and special-member
// kind -- into an owned handle so the Rust side indexes a flat, detached list.
namespace {

// bit0 = return address, bit1 = saved registers; both clear = an ordinary variable/argument.
constexpr uint32_t FRAME_VAR_RETADDR = 1;
constexpr uint32_t FRAME_VAR_SAVREGS = 2;

struct frame_var_row {
  int64_t offset; // fp-relative, e.g. var_18 -> -0x18
  uint64_t size;
  uint32_t flags;
  qstring name;
  qstring type;
};

struct frame_data {
  uint64_t size;
  qvector<frame_var_row> vars;
};

} // namespace

extern "C" void *idakit_frame_build(idakit_ea_t ea) {
  try {
    func_t *pfn = get_func((ea_t)ea);
    if (pfn == nullptr)
      return nullptr;
    tinfo_t tif;
    udt_type_data_t udt;
    if (!get_func_frame(&tif, pfn) || !tif.get_udt_details(&udt))
      return nullptr;
    auto *fd = new frame_data;
    fd->size = (uint64_t)get_frame_size(pfn);
    for (const udm_t &m : udt) {
      frame_var_row &row = fd->vars.push_back();
      // udm offset/size are in bits; soff_to_fpoff wants the byte struct offset.
      row.offset = (int64_t)soff_to_fpoff(pfn, (uval_t)(m.offset / 8));
      row.size = m.size / 8;
      row.flags =
          (m.is_retaddr() ? FRAME_VAR_RETADDR : 0) | (m.is_savregs() ? FRAME_VAR_SAVREGS : 0);
      row.name = m.name;
      m.type.print(&row.type);
    }
    return fd;
  } catch (...) {
    std::abort();
  }
}

extern "C" uint64_t idakit_frame_size(const void *h) {
  const frame_data *fd = (const frame_data *)h;
  return fd != nullptr ? fd->size : 0;
}

extern "C" size_t idakit_frame_nvars(const void *h) {
  const frame_data *fd = (const frame_data *)h;
  return fd != nullptr ? fd->vars.size() : 0;
}

extern "C" int idakit_frame_var(const void *h, size_t i, int64_t *offset, uint64_t *size,
                                uint32_t *flags) {
  const frame_data *fd = (const frame_data *)h;
  if (fd == nullptr || i >= fd->vars.size())
    return 0;
  const frame_var_row &row = fd->vars[i];
  *offset = row.offset;
  *size = row.size;
  *flags = row.flags;
  return 1;
}

extern "C" int64_t idakit_frame_var_name(const void *h, size_t i, char *buf, size_t cap) {
  const frame_data *fd = (const frame_data *)h;
  if (fd == nullptr || i >= fd->vars.size()) {
    if (cap > 0)
      buf[0] = 0;
    return -1;
  }
  const qstring &name = fd->vars[i].name;
  qstrncpy(buf, name.c_str(), cap);
  return (int64_t)name.length();
}

extern "C" int64_t idakit_frame_var_type(const void *h, size_t i, char *buf, size_t cap) {
  const frame_data *fd = (const frame_data *)h;
  if (fd == nullptr || i >= fd->vars.size()) {
    if (cap > 0)
      buf[0] = 0;
    return -1;
  }
  const qstring &type = fd->vars[i].type;
  qstrncpy(buf, type.c_str(), cap);
  return (int64_t)type.length();
}

extern "C" void idakit_frame_free(void *h) { delete (frame_data *)h; }
