// Opaque handle to the shared depth-first tinfo_t walker driving an extern "Rust" TypeWalkVisitor
// (namespace idakit_cxx). Recursion is guarded by a placeholder plus a `defined`-set dedup, so a
// self-referential type (e.g. a struct pointing at itself) resolves instead of looping; emitting
// happens through the cxx opaque visitor's member functions. Its full definition lives in
// typewalk_cxx.cc, which is compiled in the cxx bridge (with the generated visitor header on its
// include path); the ctree walk (ctree_cxx.cc) is a plain facade TU without that path, so it drives
// the walker only through this opaque handle. One walker per type source (a named type, a
// prototype, a whole ctree), so shared named types dedup across it.
#ifndef IDAKIT_TYPEWALK_WALKER_HPP
#define IDAKIT_TYPEWALK_WALKER_HPP

#include <cstdint>

// tinfo_t lives in the global namespace (typeinf.hpp); forward-declared so this header needs no SDK
// or cxx-generated include.
class tinfo_t;

namespace idakit_cxx {

struct visit_walker_t;

// Create a walker driving `visitor` (an opaque idakit_cxx::TypeWalkVisitor*), released with
// visit_walker_free.
visit_walker_t *visit_walker_new(void *visitor);
// Walk `t` into the visitor, returning the handle it minted for the type.
uint32_t visit_walker_ty(visit_walker_t *w, const tinfo_t &t);
void visit_walker_free(visit_walker_t *w);

} // namespace idakit_cxx

#endif // IDAKIT_TYPEWALK_WALKER_HPP
