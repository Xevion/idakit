// Hand-written bodies for the spec's BodyKind::Custom escape hatch. The declarations come from
// the generated gen_seg.h (in OUT_DIR); these definitions carry the SDK-specific control flow
// too bespoke to template. This proves the spec can declare a signature and defer its body.

#include <pro.h>

#include <ida.hpp>

#include <segment.hpp>

#include "gen_seg.h"

namespace idakit_gen {

uint64_t gen_seg_span_total() {
  uint64_t total = 0;
  int qty = get_segm_qty();
  for (int i = 0; i < qty; ++i) {
    segment_t *s = getnseg(i);
    if (s != nullptr)
      total += (uint64_t)(s->end_ea - s->start_ea);
  }
  return total;
}

} // namespace idakit_gen
