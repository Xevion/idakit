// idakit facade: the shared tinfo_t -> type-callback walker (see type_walk.hpp).

#include <vector>

#include "type_walk.hpp"

namespace idakit_facade {

// Mint the handle for a type, recursing into its components. Named aggregates resolve through
// a by-name placeholder so a recursive member can point back before the body is filled;
// structural types (ptr/array/func/scalar) are emitted directly. A typedef alias resolves all
// structural predicates through to its target, so it must be intercepted before them;
// everything else dispatches on the resolved shape.
uint32_t type_walker_t::ty(const tinfo_t &t) {
  if (!t.empty() && t.is_typedef())
    return ty_typedef(t);
  return ty_resolved(t);
}

uint32_t type_walker_t::ty_resolved(const tinfo_t &t) {
  size_t sz = t.get_size();
  uint32_t has_size = (sz != BADSIZE && sz != 0) ? 1 : 0;
  uint64_t size = has_size ? (uint64_t)sz : 0;
  // BADSIZE is (size_t)-1; without has_size, report 0 bytes rather than the sentinel.
  uint32_t bytes = has_size ? (uint32_t)sz : 0;

  if (t.empty())
    return ty_opaque(t);
  if (t.is_ptr())
    return v->t_ptr(ctx, ty(t.get_pointed_object()), size, has_size);
  if (t.is_array())
    return v->t_array(ctx, ty(t.get_array_element()), (uint64_t)t.get_array_nelems(), size,
                      has_size);
  if (t.is_func())
    return ty_func(t);
  if (t.is_udt())
    return ty_udt(t, size, has_size);
  if (t.is_enum())
    return ty_enum(t, size, has_size);
  if (t.is_bool())
    return v->t_scalar(ctx, 2, 0, 0, size, has_size);
  if (t.is_void())
    return v->t_scalar(ctx, 1, 0, 0, size, has_size);
  if (t.is_floating())
    return v->t_scalar(ctx, 4, bytes, 0, size, has_size);
  if (t.is_integral())
    return v->t_scalar(ctx, 3, bytes, t.is_signed() ? 1 : 0, size, has_size);
  if (t.is_bitfield())
    return ty_bitfield(t);
  return ty_opaque(t); // named-but-bodyless / unresolved
}

// A bitfield's storage is an integer of nbytes; its bit width lives at the member level
// (udm_t::size), so the type itself resolves to that base integer.
uint32_t type_walker_t::ty_bitfield(const tinfo_t &t) {
  bitfield_type_data_t bi;
  if (t.get_bitfield_details(&bi)) {
    uint32_t nb = (uint32_t)bi.nbytes;
    return v->t_scalar(ctx, 3, nb, bi.is_unsigned ? 0 : 1, nb, nb != 0 ? 1 : 0);
  }
  return ty_opaque(t);
}

// A named type IDA can name but not structurally describe here (a forward-declared or
// incomplete aggregate, an unresolved reference): emit it as a leaf carrying the resolved name.
// get_type_name resolves an ordinal reference to its real name (no `#256` form); print() is the
// nameless fallback, and `?` the last resort.
uint32_t type_walker_t::ty_opaque(const tinfo_t &t) {
  qstring nm;
  if (t.get_type_name(&nm) && !nm.empty())
    return v->t_opaque(ctx, nm.c_str(), nm.length());
  if (t.print(&nm) && !nm.empty())
    return v->t_opaque(ctx, nm.c_str(), nm.length());
  static const char unk[] = "?";
  return v->t_opaque(ctx, unk, 1);
}

// Mint a placeholder: by name (deduped, recursion-safe) for a named aggregate, fresh for an
// anonymous one. `*first` reports whether the body still needs filling.
uint32_t type_walker_t::placeholder(const tinfo_t &t, bool *first) {
  qstring nm;
  if (t.get_type_name(&nm) && !nm.empty()) {
    uint32_t id = v->t_named_ref(ctx, nm.c_str(), nm.length());
    *first = defined.insert(std::string(nm.c_str(), nm.length())).second;
    return id;
  }
  *first = true;
  return v->t_anon(ctx);
}

uint32_t type_walker_t::ty_udt(const tinfo_t &t, uint64_t size, uint32_t has_size) {
  bool first;
  uint32_t id = placeholder(t, &first);
  if (first) {
    udt_type_data_t udt;
    std::vector<idakit_member_t> ms;
    if (t.get_udt_details(&udt)) {
      ms.reserve(udt.size());
      for (const udm_t &m : udt) {
        idakit_member_t md;
        md.name = m.name.c_str();
        md.name_len = m.name.length();
        md.bit_offset = m.offset;
        md.ty = ty(m.type);
        md.bitfield_width = m.is_bitfield() ? (uint32_t)m.size : 0;
        ms.push_back(md);
      }
    }
    v->t_fill_struct(ctx, id, t.is_union() ? 1 : 0, ms.data(), ms.size(), size, has_size);
  }
  return id;
}

uint32_t type_walker_t::ty_enum(const tinfo_t &t, uint64_t size, uint32_t has_size) {
  bool first;
  uint32_t id = placeholder(t, &first);
  if (first) {
    enum_type_data_t ed;
    std::vector<idakit_enum_const_t> cs;
    bool sgn = false;
    if (t.get_enum_details(&ed)) {
      sgn = ed.is_number_signed();
      cs.reserve(ed.size());
      for (const edm_t &m : ed)
        cs.push_back({m.name.c_str(), m.name.length(), m.value});
    }
    uint32_t base_bytes = has_size ? (uint32_t)size : 4;
    uint32_t underlying = v->t_scalar(ctx, 3, base_bytes, sgn ? 1 : 0, size, has_size);
    v->t_fill_enum(ctx, id, underlying, cs.data(), cs.size(), size, has_size);
  }
  return id;
}

// A typedef link (`typedef T alias;`). Keep the alias name and peel exactly one level to its
// target, so a chain (alias -> alias -> base) unwinds link by link. A named target (another
// typedef, a struct/enum) is reached by name; an unnamed structural target has no name to
// conflate with the alias, so it resolves straight off this same tinfo.
uint32_t type_walker_t::ty_typedef(const tinfo_t &t) {
  bool first;
  uint32_t id = placeholder(t, &first); // keyed by the alias name
  if (first) {
    qstring next;
    tinfo_t und;
    uint32_t under;
    if (t.get_next_type_name(&next) &&
        und.get_named_type(get_idati(), next.c_str(), BTF_TYPEDEF, false))
      under = ty(und);
    else
      under = ty_resolved(t);
    v->t_fill_typedef(ctx, id, under);
  }
  return id;
}

uint32_t type_walker_t::ty_func(const tinfo_t &t) {
  func_type_data_t fd;
  std::vector<uint32_t> params;
  uint32_t ret;
  uint32_t vararg = 0;
  if (t.get_func_details(&fd)) {
    ret = ty(fd.rettype);
    params.reserve(fd.size());
    for (const funcarg_t &a : fd)
      params.push_back(ty(a.type));
    vararg = fd.is_vararg_cc() ? 1 : 0;
  } else {
    ret = v->t_scalar(ctx, 0, 0, 0, 0, 0);
  }
  return v->t_func(ctx, ret, params.data(), params.size(), vararg);
}

} // namespace idakit_facade
