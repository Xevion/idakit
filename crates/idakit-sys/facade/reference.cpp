// Hand-written Custom body for the generated reference domain (namespace gen). One walk of an
// xrefblk_t collects every cross-reference edge at an address into an owned rust::Vec<XrefRec>,
// returned by value in a single crossing. XrefRec is a cxx shared struct, defined by the
// cxx-generated gen_bridge.h.

#include <ida.hpp>
#include <pro.h>

#include <funcs.hpp> // func_t, get_func
#include <nalt.hpp>  // must precede xref.hpp: casevec_t (used by hexrays.hpp via gen_bridge.h) is
                     // guarded on NALT_HPP
#include <xref.hpp>  // xrefblk_t, XREF_FLOW, XREF_NOFLOW, has_external_refs, has_jump_or_flow_xref

#include "gen_reference.h"
// The cxx-generated header defines XrefRec (full definition needed to construct and push it) and
// instantiates rust::Vec<XrefRec>; gen_reference.h only forward-declares XrefRec.
#include "gen_bridge.h"

namespace gen {

// Every cross-reference edge to (is_to) or from addr, collected into an owned Vec; empty if there
// are none. flow selects whether ordinary next-instruction flow edges are included.
rust::Vec<XrefRec> xrefs_build(uint64_t addr, bool is_to, bool flow) {
  rust::Vec<XrefRec> rows;
  xrefblk_t xrefs;
  int mode = flow ? XREF_FLOW : XREF_NOFLOW;
  bool ok = is_to ? xrefs.first_to(static_cast<ea_t>(addr), mode)
                  : xrefs.first_from(static_cast<ea_t>(addr), mode);
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

// Whether addr has a reference from outside the function containing it; false when addr is not
// inside any function (has_external_refs itself requires a function).
bool has_external_refs(uint64_t addr) {
  ea_t ea = static_cast<ea_t>(addr);
  func_t *pfn = get_func(ea);
  return pfn != nullptr && ::has_external_refs(pfn, ea);
}

// Whether addr has an incoming jump or ordinary-flow code cross-reference.
bool has_jump_or_flow_xref(uint64_t addr) {
  return ::has_jump_or_flow_xref(static_cast<ea_t>(addr));
}

} // namespace gen
