// cxx-bridged segment facade (namespace idakit_cxx). Bodies are hand-written, same as the
// raw extern "C" facade; the declarations come from the cxx-generated bridge header. String
// returns are `rust::String`/`Result<String>`, so the raw layer's snprintf `(buf, cap)`
// marshalling and its explicit try/catch-abort sentinel dance are gone: a bad segment index
// throws, and cxx turns the throw into a Rust `Err`.

#include <pro.h>

#include <ida.hpp>

#include <segment.hpp>

#include <stdexcept>

#include "segment_cxx.h"

namespace idakit_cxx {

size_t seg_qty() { return (size_t)get_segm_qty(); }

uint64_t seg_start(int32_t n) {
  segment_t *s = getnseg(n);
  return s != nullptr ? (uint64_t)s->start_ea : (uint64_t)BADADDR;
}

uint64_t seg_end(int32_t n) {
  segment_t *s = getnseg(n);
  return s != nullptr ? (uint64_t)s->end_ea : (uint64_t)BADADDR;
}

int32_t seg_perm(int32_t n) {
  segment_t *s = getnseg(n);
  return s != nullptr ? (int32_t)s->perm : 0;
}

int32_t seg_bitness(int32_t n) {
  segment_t *s = getnseg(n);
  return s != nullptr ? (int32_t)s->abits() : 0;
}

rust::String seg_name(int32_t n) {
  segment_t *s = getnseg(n);
  if (s == nullptr)
    throw std::out_of_range("no segment at index");
  qstring out;
  get_visible_segm_name(&out, s);
  return rust::String(out.c_str(), out.length());
}

rust::String seg_class(int32_t n) {
  segment_t *s = getnseg(n);
  if (s == nullptr)
    throw std::out_of_range("no segment at index");
  qstring out;
  if (get_segm_class(&out, s) <= 0)
    throw std::runtime_error("segment has no class");
  return rust::String(out.c_str(), out.length());
}

} // namespace idakit_cxx
