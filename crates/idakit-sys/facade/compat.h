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

// A chunk's range and flags, copied rather than borrowed. set_from is private so no call site can
// reach a member the real class lacks.
class fchunk_info_t : public range_t {
public:
  uint64 get_flags() const { return flags_; }

protected:
  void set_from(const func_t &chunk) {
    *static_cast<range_t *>(this) = chunk;
    flags_ = chunk.flags;
  }

private:
  friend bool get_fchunk_info(fchunk_info_t *out, ea_t ea);

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

// Selects which optional strings an entry read fills. The gating is emulated here rather than
// mirrored, since the getters it skips are unconditional on this SDK.
#define GFI_NAME 0x0001
#define GFI_CMT 0x0002
#define GFI_CMT_RPT 0x0004
#define GFI_COMMENTS (GFI_CMT | GFI_CMT_RPT)
#define GFI_ALL (GFI_NAME | GFI_COMMENTS)

// A function entry: the chunk facts, the frame layout scalars, and the requested strings.
class func_entry_info_t : public fchunk_info_t {
public:
  uval_t get_frame_id() const { return frame_; }
  asize_t get_frsize() const { return frsize_; }
  ushort get_frregs() const { return frregs_; }
  asize_t get_argsize() const { return argsize_; }
  asize_t get_fpd() const { return fpd_; }
  bgcolor_t get_color() const { return color_; }
  const char *get_name() const { return name_.c_str(); }
  const char *get_cmt() const { return cmt_.c_str(); }
  const char *get_cmt_rpt() const { return cmt_rpt_.c_str(); }
  bool has(int gfi_flags) const { return (filled_ & gfi_flags) == gfi_flags; }

private:
  friend bool get_func_entry_info(func_entry_info_t *out, ea_t ea, int flags);

  void set_from(const func_t &pfn, int gfi_flags) {
    fchunk_info_t::set_from(pfn);
    frame_ = pfn.frame;
    frsize_ = pfn.frsize;
    frregs_ = pfn.frregs;
    argsize_ = pfn.argsize;
    fpd_ = pfn.fpd;
    color_ = pfn.color;
    // filled_ records what was asked for, so an empty string reads as "absent", not "unfilled".
    if ((gfi_flags & GFI_NAME) != 0) {
      get_func_name(&name_, pfn.start_ea);
      filled_ |= GFI_NAME;
    }
    if ((gfi_flags & GFI_CMT) != 0) {
      get_func_cmt(&cmt_, &pfn, false);
      filled_ |= GFI_CMT;
    }
    if ((gfi_flags & GFI_CMT_RPT) != 0) {
      get_func_cmt(&cmt_rpt_, &pfn, true);
      filled_ |= GFI_CMT_RPT;
    }
  }

  int filled_ = 0;
  uval_t frame_ = BADNODE;
  asize_t frsize_ = 0;
  ushort frregs_ = 0;
  asize_t argsize_ = 0;
  asize_t fpd_ = 0;
  bgcolor_t color_ = DEFCOLOR;
  qstring name_;
  qstring cmt_;
  qstring cmt_rpt_;
};

inline bool get_func_entry_info(func_entry_info_t *out, ea_t ea, int flags = 0) {
  func_t *pfn = get_func(ea);
  if (pfn == nullptr)
    return false;
  if (out != nullptr)
    out->set_from(*pfn, flags);
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

// Two members change shape from the class it wraps: the key is an ea, and chunk() writes through
// an out-param instead of returning a reference into the locked func_t.
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

// Keyed by start ea rather than by a func_t later analysis can invalidate. Every member the facade
// reads is inherited, so only construction differs.
class qflow_chart_ea_t : public qflow_chart_t {
public:
  qflow_chart_ea_t() = default;
  qflow_chart_ea_t(const char *title, ea_t func_ea, ea_t ea1, ea_t ea2, int flags)
      : qflow_chart_t(title, get_func(func_ea), ea1, ea2, flags) {}
};

// Only the numeric fields, being the ones with no ea-based accessor of their own; the strings have
// their own getters below, so the GSI_* fill flags have nothing to select.
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

// flags is the GSI_* string-fill selector, accepted and ignored so call sites stay identical.
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
