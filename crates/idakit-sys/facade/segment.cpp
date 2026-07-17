// Hand-written Custom bodies for the generated segment domain (namespace gen): the segment comment
// getter, whose extra `repeatable` argument doesn't fit the templated `seg_string` shape, plus the
// SEG_*/sa*/sc* alignment sources. Every other segment accessor is templated (gen_seg_bodies.cc),
// not here.

#include <ida.hpp>
#include <pro.h>

#include <segment.hpp>

#include <initializer_list>
#include <stdexcept>

#include "gen_seg.h"

namespace gen {

// The segment's comment (repeatable or regular) at index n; throws when n is out of range or that
// channel carries no comment.
rust::String gen_seg_cmt(int32_t n, bool repeatable) {
  segment_t *s = getnseg(n);
  if (s == nullptr)
    throw std::out_of_range("no segment at index");
  qstring out;
  if (get_segment_cmt(&out, s, repeatable) <= 0)
    throw std::runtime_error("no segment comment");
  return to_rust_string(out);
}

// Alignment sources. These name this SDK's own segment.hpp macros, each list ordered to match the
// discriminant order of the Rust enum mirroring it, so a header renumbering shows up as a mismatch
// in that enum's alignment test rather than as a silently mislabeled segment. The gaps are the
// SDK's own: SEG_* leaves 5 unassigned, sc* leaves 3. Header constants only, no kernel needed.

namespace {

rust::Vec<uint8_t> collect(std::initializer_list<uint8_t> codes) {
  rust::Vec<uint8_t> out;
  for (uint8_t c : codes)
    out.push_back(c);
  return out;
}

} // namespace

// idakit SegmentType.
rust::Vec<uint8_t> seg_type_ids() {
  return collect({SEG_NORM, SEG_XTRN, SEG_CODE, SEG_DATA, SEG_IMP, SEG_GRP, SEG_NULL, SEG_UNDF,
                  SEG_BSS, SEG_ABSSYM, SEG_COMM, SEG_IMEM});
}

// idakit SegmentAlign.
rust::Vec<uint8_t> seg_align_ids() {
  return collect({saAbs, saRelByte, saRelWord, saRelPara, saRelPage, saRelDble, saRel4K, saGroup,
                  saRel32Bytes, saRel64Bytes, saRelQword, saRel128Bytes, saRel512Bytes,
                  saRel1024Bytes, saRel2048Bytes});
}

// idakit SegmentComb.
rust::Vec<uint8_t> seg_comb_ids() {
  return collect({scPriv, scGroup, scPub, scPub2, scStack, scCommon, scPub3});
}

} // namespace gen
