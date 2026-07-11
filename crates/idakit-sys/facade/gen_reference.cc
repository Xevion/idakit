// Hand-written Custom body for the generated reference domain (namespace idakit_gen). One walk of an
// xrefblk_t collects every cross-reference edge at an address into an owned rust::Vec<XrefRec>
// returned by value, retiring the raw facade's open-cursor -> next -> close dance. XrefRec is a cxx
// shared struct, defined by the cxx-generated gen_bridge.h.

#include <pro.h>
#include <ida.hpp>

#include <xref.hpp> // xrefblk_t, XREF_NOFLOW

#include "gen_reference.h"
// The cxx-generated header defines XrefRec (full definition needed to construct and push it) and
// instantiates rust::Vec<XrefRec>; gen_reference.h only forward-declares XrefRec.
#include "gen_bridge.h"

namespace idakit_gen {

rust::Vec<XrefRec> xrefs_build(uint64_t ea, bool is_to) {
  rust::Vec<XrefRec> rows;
  xrefblk_t xb;
  // XREF_NOFLOW drops ordinary next-instruction flow edges, matching the raw cursor.
  bool ok = is_to ? xb.first_to((ea_t)ea, XREF_NOFLOW) : xb.first_from((ea_t)ea, XREF_NOFLOW);
  for (; ok; ok = is_to ? xb.next_to() : xb.next_from()) {
    XrefRec rec;
    rec.from = (uint64_t)xb.from;
    rec.to = (uint64_t)xb.to;
    rec.type_ = (int32_t)xb.type;
    rec.iscode = xb.iscode != 0;
    rec.user = xb.user != 0;
    rows.push_back(std::move(rec));
  }
  return rows;
}

} // namespace idakit_gen
