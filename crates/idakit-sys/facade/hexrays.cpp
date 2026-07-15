// Hand-written Custom bodies for the generated Hex-Rays domain (namespace gen). decompile
// hands back a cfuncptr_t owned by std::unique_ptr, so cxx's deleter runs ~cfuncptr_t (release())
// on drop, retiring the raw new/delete + dispose. It wraps decompile_func in guarded<> so a
// decompiler fatal exit() surfaces as a trap (g_trapped) instead of a crash, then throws on failure
// so cxx maps it to a Rust Err; idakit re-checks was_trapped() to split a trapped exit from an
// ordinary miss. The read accessors take a borrowed &CFunc and cross the cfunc_t* the qrefcnt
// holds.

#include <pro.h>

#include <ida.hpp>

#include <funcs.hpp>
#include <hexrays.hpp>
#include <idp.hpp>    // get_hexdsp
#include <lines.hpp>  // tag_remove
#include <loader.hpp> // load_plugin

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
  int idaapi visit_insn(cinsn_t *) override {
    ++n_insn;
    return 0;
  }
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

rust::String cfunc_pseudocode(const ::cfuncptr_t &cfunc) {
  cfunc_t *p = cfunc;
  return render_pseudocode(p);
}

rust::String cfunc_refresh_text(const ::cfuncptr_t &cfunc) {
  cfunc_t *p = cfunc;
  p->refresh_func_ctext();
  return render_pseudocode(p);
}

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

bool hexrays_init() {
  if (init_hexrays_plugin())
    return true;
  load_plugin("hexx64");
  return init_hexrays_plugin();
}

bool mark_cfunc_dirty(uint64_t addr, bool close_views) {
  if (get_hexdsp() == nullptr)
    return false;
  return ::mark_cfunc_dirty(static_cast<ea_t>(addr), close_views);
}

void clear_cached_cfuncs() {
  if (get_hexdsp() == nullptr)
    return;
  ::clear_cached_cfuncs();
}

bool has_cached_cfunc(uint64_t addr) {
  if (get_hexdsp() == nullptr)
    return false;
  return ::has_cached_cfunc(static_cast<ea_t>(addr));
}

} // namespace gen
