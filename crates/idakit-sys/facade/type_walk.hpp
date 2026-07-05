// Shared tinfo_t -> type-callback walker, reused by the ctree walk and the bare-tinfo
// (frame/member) walks.
#ifndef IDAKIT_TYPE_WALK_HPP
#define IDAKIT_TYPE_WALK_HPP

#include <set>
#include <string>

#include <typeinf.hpp> // tinfo_t and the *_type_data_t detail structs

#include "idakit_facade.h"

namespace idakit_facade {

// Reads an arbitrary tinfo_t depth-first and drives an idakit_type_vtbl_t to mint the
// corresponding interned type on the consumer side. Named aggregates/typedefs resolve through
// a by-name placeholder (recursion-safe), deduped within one walk by `defined`; components are
// emitted before their container. One instance walks one type source (a ctree, a frame): reuse
// it across that source's types so shared named types are filled once.
struct type_walker_t {
  const idakit_type_vtbl_t *v;
  void *ctx;
  std::set<std::string> defined; // named types already filled (recursion + dedup guard)

  uint32_t ty(const tinfo_t &t);

private:
  uint32_t ty_resolved(const tinfo_t &t);
  uint32_t placeholder(const tinfo_t &t, bool *first);
  uint32_t ty_udt(const tinfo_t &t, uint64_t size, uint32_t has_size);
  uint32_t ty_enum(const tinfo_t &t, uint64_t size, uint32_t has_size);
  uint32_t ty_typedef(const tinfo_t &t);
  uint32_t ty_func(const tinfo_t &t);
  uint32_t ty_bitfield(const tinfo_t &t);
  uint32_t ty_opaque(const tinfo_t &t);
};

} // namespace idakit_facade

#endif // IDAKIT_TYPE_WALK_HPP
