// Hand-written Custom bodies for the generated Hex-Rays domain (namespace gen).
// Every read accessor takes a borrowed &CFunc and crosses the cfunc_t* pointer the qrefcnt owns; an
// absent SDK value throws std::runtime_error, which cxx maps to a Rust Err. decompile is the one
// function that hands back an owned handle, a cfuncptr_t under std::unique_ptr, instead of reading
// through an existing one.

#include <pro.h>

#include <ida.hpp>

#include <funcs.hpp>
#include <hexrays.hpp>
#include <idp.hpp>    // get_hexdsp
#include <lines.hpp>  // tag_remove
#include <loader.hpp> // load_plugin

#include <initializer_list>
#include <stdexcept>

#include "gen_hexrays.h"
#include "internal.h" // guarded<>, g_trapped
// The generated bridge header defines the shared structs (full definitions needed to construct them
// below); gen_hexrays.h only forward-declares them.
#include "gen_bridge.h"

using namespace facade;

namespace gen {

namespace {

// One histogram bucket per possible ctype_t byte value (cot_*).
constexpr int CTYPE_SLOTS = 256;

// Read-only ctree traversal: count statements, expressions, and call sites. CV_FAST = no parent
// stack (unneeded here).
struct ctree_counter_t : public ctree_visitor_t {
  int n_insn = 0;
  int n_expr = 0;
  int n_calls = 0;
  ctree_counter_t() : ctree_visitor_t(CV_FAST) {}
  // idaapi callback per statement visited.
  int idaapi visit_insn(cinsn_t *) override {
    ++n_insn;
    return 0;
  }
  // idaapi callback per expression visited; a cot_call expression also counts as a call site.
  int idaapi visit_expr(cexpr_t *expr) override {
    ++n_expr;
    if (expr->op == cot_call)
      ++n_calls;
    return 0;
  }
};

// Per-op expression histograms. `visited` counts every cexpr the SDK visits (ground truth);
// `materialized` counts every cexpr the extraction walker materializes, i.e. all except a
// cot_empty placeholder in an *optional* operand slot (a for(;;) init/cond/step or a bare
// return;/throw;) that the walker elides to None.
struct expr_gap_visitor_t : public ctree_visitor_t {
  int *visited;
  int *materialized;
  expr_gap_visitor_t(int *visited, int *materialized)
      : ctree_visitor_t(CV_PARENTS), visited(visited), materialized(materialized) {}
  // True for a cot_empty placeholder in an optional slot (a for-loop init/cond/step, or a bare
  // return/throw) that the extraction walker elides to None rather than materializing.
  bool elided_empty(const cexpr_t *expr) {
    if (expr->op != cot_empty)
      return false;
    const cinsn_t *p = parent_insn();
    if (p == nullptr)
      return false;
    switch (p->op) {
    case cit_for:
      return expr == &p->cfor->init || expr == &p->cfor->expr || expr == &p->cfor->step;
    case cit_return:
      return expr == &p->creturn->expr;
    case cit_throw:
      return expr == &p->cthrow->expr;
    default:
      return false;
    }
  }
  // idaapi callback per expression visited; tallies both the raw visit and, unless elided, the
  // post-extraction materialized count.
  int idaapi visit_expr(cexpr_t *expr) override {
    visited[expr->op]++;
    if (!elided_empty(expr))
      materialized[expr->op]++;
    return 0;
  }
};

// Tag-stripped pseudocode text from cfunc's already-generated ctext (get_pseudocode generates it
// on first use, so this is a no-op after the first call unless refresh_func_ctext invalidated it).
rust::String render_pseudocode(cfunc_t *cfunc) {
  const strvec_t &lines = cfunc->get_pseudocode();
  qstring out;
  for (size_t i = 0; i < lines.size(); ++i) {
    qstring line;
    tag_remove(&line, lines[i].line);
    out.append(line);
    out.append('\n');
  }
  return to_rust_string(out);
}

} // namespace

// Decompile the function at addr; throws (mapped to a Rust Err) on a missing function, a Hex-Rays
// failure, or a trapped decompiler fatal exit.
std::unique_ptr<::cfuncptr_t> decompile(uint64_t addr) {
  std::string reason;
  // guarded<> traps a decompiler fatal exit() into g_trapped (returns nullptr) instead of crashing.
  ::cfuncptr_t *result = guarded<::cfuncptr_t *>(nullptr, false, [&]() -> ::cfuncptr_t * {
    func_t *func = get_func(static_cast<ea_t>(addr));
    if (func == nullptr) {
      reason = "no function at address";
      return nullptr;
    }
    hexrays_failure_t hf;
    ::cfuncptr_t cfunc = decompile_func(func, &hf, 0);
    if (cfunc == nullptr) {
      reason = hf.desc().c_str();
      return nullptr;
    }
    // Own a ref on the heap so the result survives past this call (the local cfunc's dtor then
    // decrements, leaving exactly one ref).
    return new ::cfuncptr_t(cfunc);
  });
  if (result == nullptr) {
    // A trapped fatal is a dead kernel; idakit re-checks was_trapped() and ignores this message.
    if (g_trapped)
      reason = "the IDA kernel aborted during decompilation";
    throw std::runtime_error(reason);
  }
  return std::unique_ptr<::cfuncptr_t>(result);
}

// Tag-stripped pseudocode text for an already-decompiled cfunc.
rust::String cfunc_pseudocode(const ::cfuncptr_t &cfunc) {
  cfunc_t *p = cfunc;
  return render_pseudocode(p);
}

// Force ctext regeneration (e.g. after a rename or comment) and return the refreshed pseudocode.
rust::String cfunc_refresh_text(const ::cfuncptr_t &cfunc) {
  cfunc_t *p = cfunc;
  p->refresh_func_ctext();
  return render_pseudocode(p);
}

// Count statements, expressions, and call sites in cfunc's ctree body.
CtreeCounts cfunc_counts(const ::cfuncptr_t &cfunc) {
  cfunc_t *p = cfunc;
  ctree_counter_t vis;
  vis.apply_to(&p->body, nullptr);
  CtreeCounts out{};
  out.insns = vis.n_insn;
  out.expressions = vis.n_expr;
  out.calls = vis.n_calls;
  return out;
}

// Per-op visited vs materialized expression histograms, for idakit's extraction-completeness test.
ExprGap cfunc_expr_gap(const ::cfuncptr_t &cfunc) {
  cfunc_t *p = cfunc;
  int visited_hist[CTYPE_SLOTS] = {0};
  int materialized_hist[CTYPE_SLOTS] = {0};
  expr_gap_visitor_t vis(visited_hist, materialized_hist);
  vis.apply_to(&p->body, nullptr);
  int visitor_total = 0;
  int expected = 0;
  for (int k = 0; k < CTYPE_SLOTS; ++k) {
    visitor_total += visited_hist[k];
    expected += materialized_hist[k];
  }
  ExprGap out{};
  out.visitor_total = visitor_total;
  out.expected = expected;
  return out;
}

// Initialize Hex-Rays, loading the decompiler plugin first if it is not already resident; false if
// no decompiler is available for this arch.
bool hexrays_init() {
  if (init_hexrays_plugin())
    return true;
  load_plugin("hexx64");
  return init_hexrays_plugin();
}

// Erase addr's cached decompilation, forcing a re-decompile on next access; false if Hex-Rays isn't
// loaded (get_hexdsp() is null before init) or there was no cache entry.
bool mark_cfunc_dirty(uint64_t addr, bool close_views) {
  if (get_hexdsp() == nullptr)
    return false;
  return ::mark_cfunc_dirty(static_cast<ea_t>(addr), close_views);
}

// Drop every cached cfunc; a no-op if Hex-Rays isn't loaded.
void clear_cached_cfuncs() {
  if (get_hexdsp() == nullptr)
    return;
  ::clear_cached_cfuncs();
}

// Whether addr already has a cached decompilation; false if Hex-Rays isn't loaded.
bool has_cached_cfunc(uint64_t addr) {
  if (get_hexdsp() == nullptr)
    return false;
  return ::has_cached_cfunc(static_cast<ea_t>(addr));
}

// Alignment sources. These name this SDK's own ctype_t enumerators, each list ordered to match the
// discriminant order of the Rust enum mirroring it, so a header renumbering shows up as a mismatch
// in that enum's alignment test rather than as a silently mislabeled node. Header constants only,
// no kernel or decompiler needed.

namespace {

rust::Vec<uint32_t> collect(std::initializer_list<ctype_t> tags) {
  rust::Vec<uint32_t> out;
  for (ctype_t t : tags)
    out.push_back(static_cast<uint32_t>(t));
  return out;
}

} // namespace

// idakit BinaryOp.
rust::Vec<uint32_t> binop_ctype_ids() {
  return collect({cot_comma, cot_lor,  cot_land, cot_bor,  cot_xor,  cot_band, cot_eq,   cot_ne,
                  cot_sge,   cot_uge,  cot_sle,  cot_ule,  cot_sgt,  cot_ugt,  cot_slt,  cot_ult,
                  cot_sshr,  cot_ushr, cot_shl,  cot_add,  cot_sub,  cot_mul,  cot_sdiv, cot_udiv,
                  cot_smod,  cot_umod, cot_fadd, cot_fsub, cot_fmul, cot_fdiv});
}

// idakit AssignmentOp.
rust::Vec<uint32_t> assignop_ctype_ids() {
  return collect({cot_asg, cot_asgbor, cot_asgxor, cot_asgband, cot_asgadd, cot_asgsub, cot_asgmul,
                  cot_asgsshr, cot_asgushr, cot_asgshl, cot_asgsdiv, cot_asgudiv, cot_asgsmod,
                  cot_asgumod});
}

// idakit UnaryOp. cot_cast/cot_ptr are absent on purpose: they carry a type or an access size, so
// idakit models them as their own expression variants rather than bare unaries.
rust::Vec<uint32_t> unop_ctype_ids() {
  return collect({cot_fneg, cot_neg, cot_lnot, cot_bnot, cot_ref, cot_postinc, cot_postdec,
                  cot_preinc, cot_predec});
}

// idakit StructuralTag: the non-operator ctype_t values the extraction walker dispatches on.
rust::Vec<uint32_t> structural_tag_ctype_ids() {
  return collect({cot_empty, cot_tern, cot_cast, cot_idx, cot_insn, cot_sizeof, cot_type});
}

} // namespace gen
