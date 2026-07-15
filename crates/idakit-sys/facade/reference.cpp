// Hand-written Custom body for the generated reference domain (namespace gen). One walk of
// an xrefblk_t collects every cross-reference edge at an address into an owned rust::Vec<XrefRec>
// returned by value in a single crossing. XrefRec is a cxx
// shared struct, defined by the cxx-generated gen_bridge.h.

#include <ida.hpp>
#include <pro.h>

#include <nalt.hpp> // must precede xref.hpp: casevec_t (used by hexrays.hpp via gen_bridge.h) is
                    // guarded on NALT_HPP
#include <xref.hpp> // xrefblk_t, XREF_NOFLOW

#include "gen_reference.h"
// The cxx-generated header defines XrefRec (full definition needed to construct and push it) and
// instantiates rust::Vec<XrefRec>; gen_reference.h only forward-declares XrefRec.
#include "gen_bridge.h"

namespace gen {

rust::Vec<XrefRec> xrefs_build(uint64_t addr, bool is_to) {
  rust::Vec<XrefRec> rows;
  xrefblk_t xrefs;
  // XREF_NOFLOW drops ordinary next-instruction flow edges, matching the raw cursor.
  bool ok = is_to ? xrefs.first_to(static_cast<ea_t>(addr), XREF_NOFLOW)
                  : xrefs.first_from(static_cast<ea_t>(addr), XREF_NOFLOW);
  for (; ok; ok = is_to ? xrefs.next_to() : xrefs.next_from()) {
    XrefRec rec;
    rec.from = static_cast<uint64_t>(xrefs.from);
    rec.to = static_cast<uint64_t>(xrefs.to);
    rec.type_ = static_cast<int32_t>(xrefs.type);
    rec.iscode = xrefs.iscode != 0;
    rec.user = xrefs.user != 0;
    rows.push_back(rec);
  }
  return rows;
}

} // namespace gen
