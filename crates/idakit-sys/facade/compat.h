#pragma once

// Back-ports 9.4's ea-based function, frame, xref, flow-chart, and segment API onto 9.3.
//
// The facade is written against the 9.4 spelling only; each name below is an inline shim over the
// pointer call 9.4 deprecated, which carries no deprecation on 9.3. That is what keeps the facade
// free of blanket warning suppression.
//
// Delete this header when 9.3 support is dropped. Nothing else has to change.

#include <pro.h>

#if IDA_SDK_VERSION < 940

#include <frame.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <name.hpp> // GN_VISIBLE
#include <segment.hpp>
#include <xref.hpp>

inline ea_t get_func_start(ea_t ea) {
  func_t *pfn = get_func(ea);
  return pfn != nullptr ? pfn->start_ea : BADADDR;
}

inline ea_t get_func_ea_by_num(size_t n) {
  func_t *pfn = getn_func(n);
  return pfn != nullptr ? pfn->start_ea : BADADDR;
}

inline ssize_t get_func_cmt_ea(qstring *buf, ea_t ea, bool repeatable) {
  func_t *pfn = get_func(ea);
  return pfn != nullptr ? get_func_cmt(buf, pfn, repeatable) : -1;
}

inline int get_func_bits_ea(ea_t ea) {
  func_t *pfn = get_func(ea);
  return pfn != nullptr ? get_func_bits(pfn) : 16;
}

// 9.4's chunk descriptor: the chunk's range and flags, copied rather than borrowed. set_from is
// private so no call site can reach a member 9.4's own class lacks.
class fchunk_info_t : public range_t {
public:
  uint64 get_flags() const { return flags_; }

private:
  friend bool get_fchunk_info(fchunk_info_t *out, ea_t ea);

  void set_from(const func_t &chunk) {
    *static_cast<range_t *>(this) = chunk;
    flags_ = chunk.flags;
  }

  uint64 flags_ = 0;
};

inline bool get_fchunk_info(fchunk_info_t *out, ea_t ea) {
  func_t *chunk = get_fchunk(ea);
  if (chunk == nullptr)
    return false;
  if (out != nullptr)
    out->set_from(*chunk);
  return true;
}

inline size_t get_func_tail_qty(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  return pfn != nullptr ? static_cast<size_t>(pfn->tailqty) : 0;
}

inline asize_t get_frame_size_ea(ea_t func_ea) { return get_frame_size(get_func(func_ea)); }

inline bool get_func_frame_ea(tinfo_t *out, ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  return pfn != nullptr && get_func_frame(out, pfn);
}

inline sval_t soff_to_fpoff_ea(ea_t func_ea, uval_t soff) {
  return soff_to_fpoff(get_func(func_ea), soff);
}

inline bool has_external_refs_ea(ea_t func_ea, ea_t ea) {
  func_t *pfn = get_func(func_ea);
  return pfn != nullptr && has_external_refs(pfn, ea);
}

// 9.4's chunk iterator. Two members change shape from the 9.3 class it wraps: the key is an ea,
// and chunk() writes through an out-param instead of returning a reference into the locked func_t.
class function_tail_iterator_t : public func_tail_iterator_t {
public:
  function_tail_iterator_t() = default;
  explicit function_tail_iterator_t(ea_t func_ea, ea_t ea = BADADDR) { set(func_ea, ea); }

  bool set(ea_t func_ea, ea_t ea = BADADDR) {
    func_t *pfn = get_func(func_ea);
    return pfn != nullptr && func_tail_iterator_t::set(pfn, ea);
  }

  void chunk(range_t *out) const { *out = func_tail_iterator_t::chunk(); }
};

// 9.4's flow chart, keyed by start ea rather than by a func_t later analysis can invalidate.
// Every member the facade reads is inherited, so only construction differs.
class qflow_chart_ea_t : public qflow_chart_t {
public:
  qflow_chart_ea_t() = default;
  qflow_chart_ea_t(const char *title, ea_t func_ea, ea_t ea1, ea_t ea2, int flags)
      : qflow_chart_t(title, get_func(func_ea), ea1, ea2, flags) {}
};

// 9.4's segment descriptor. Only the numeric fields are here, being the ones with no ea-based
// accessor of their own; the strings have their own getters below, so 9.4's GSI_* fill flags
// gating them have nothing to select.
class segment_info_t : public range_t {
public:
  uchar get_align() const { return align_; }
  uchar get_comb() const { return comb_; }
  uchar get_perm() const { return perm_; }
  int abits() const { return 1 << (bitness_ + 4); }
  ushort get_flags() const { return flags_; }
  sel_t get_sel() const { return sel_; }
  uchar get_type() const { return type_; }
  bgcolor_t get_color() const { return color_; }

private:
  friend bool get_segment_info_by_num(segment_info_t *out, int n, int flags);

  void set_from(const segment_t &seg) {
    *static_cast<range_t *>(this) = seg;
    align_ = seg.align;
    comb_ = seg.comb;
    perm_ = seg.perm;
    bitness_ = seg.bitness;
    flags_ = seg.flags;
    sel_ = seg.sel;
    type_ = seg.type;
    color_ = seg.color;
  }

  uchar align_ = 0;
  uchar comb_ = 0;
  uchar perm_ = 0;
  uchar bitness_ = 0;
  ushort flags_ = 0;
  sel_t sel_ = 0;
  uchar type_ = SEG_NORM;
  bgcolor_t color_ = DEFCOLOR;
};

// flags is 9.4's GSI_* string-fill selector, accepted and ignored rather than dropped so the call
// sites stay identical across both SDKs.
inline bool get_segment_info_by_num(segment_info_t *out, int n, int flags = 0) {
  qnotused(flags);
  segment_t *seg = getnseg(n);
  if (seg == nullptr)
    return false;
  if (out != nullptr)
    out->set_from(*seg);
  return true;
}

inline ea_t get_segment_ea_by_num(int n) {
  segment_t *seg = getnseg(n);
  return seg != nullptr ? seg->start_ea : BADADDR;
}

inline ssize_t get_segment_name(qstring *buf, ea_t ea, int flags = 0) {
  return get_segm_name(buf, getseg(ea), flags);
}

inline ssize_t get_segment_class(qstring *buf, ea_t ea) { return get_segm_class(buf, getseg(ea)); }

inline ssize_t get_segment_cmt_by_ea(qstring *buf, ea_t ea, bool repeatable) {
  segment_t *seg = getseg(ea);
  return seg != nullptr ? get_segment_cmt(buf, seg, repeatable) : -1;
}

#endif // IDA_SDK_VERSION < 940
