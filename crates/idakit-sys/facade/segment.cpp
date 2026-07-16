// Hand-written Custom body for the generated segment domain (namespace gen): the segment comment
// getter, whose extra `repeatable` argument doesn't fit the templated `seg_string` shape. Every
// other segment accessor is templated (gen_seg_bodies.cc), not here.

#include <ida.hpp>
#include <pro.h>

#include <segment.hpp>

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

} // namespace gen
