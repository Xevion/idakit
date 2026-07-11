// cxx extern "Rust" opaque-visitor type walk (namespace idakit_cxx). visit_walker_t (declared in
// typewalk_walker.hpp) does a depth-first tinfo_t recursion guarded by a placeholder plus a
// `defined`-set dedup, so a self-referential type resolves instead of looping. It emits through the
// extern "Rust" opaque visitor's member functions (vis->scalar(...), vis->named_ref(...),
// vis->fill_struct(...)) that cxx generates, not a C function-pointer table. Per-call names cross as
// rust::Str and arrays as rust::Slice, borrowed for the one call.

#include <pro.h>

#include <ida.hpp>

#include <frame.hpp>   // get_func_frame, get_frame_size, soff_to_fpoff
#include <funcs.hpp>   // get_func
#include <typeinf.hpp> // tinfo_t and the *_type_data_t detail structs; get_tinfo, get_idati

#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "typewalk_cxx.h"
#include "typewalk_walker.hpp"
// The generated header defines the TypeWalkVisitor class (its member functions) and the MemberInfo
// / EnumConstInfo / FrameVar / FrameWalk shared structs. This TU is compiled in the cxx bridge, so
// its include path resolves the generated header; the ctree walk drives visit_walker_t only through
// the opaque handle in typewalk_walker.hpp.
#include "idakit-sys/src/bridge_typewalk.rs.h"

namespace idakit_cxx {

namespace {

// A rust::Str borrowing a qstring's buffer for the duration of one visitor call (zero-copy). The
// qstring must outlive the call; every use below keeps it on the stack across the call.
rust::Str borrow(const qstring &s) { return rust::Str(s.c_str(), s.length()); }

rust::Str borrow(const char *p, size_t n) { return rust::Str(p, n); }

} // namespace

// Full definition of the walker the opaque handle in typewalk_walker.hpp fronts. Holds the visitor
// by pointer so the ctree walk can create one and rebind it per walk.
struct visit_walker_t {
  TypeWalkVisitor *vis = nullptr;
  std::set<std::string> defined; // named types already filled (recursion + dedup guard)

  uint32_t ty(const tinfo_t &t);
  uint32_t ty_resolved(const tinfo_t &t);
  uint32_t placeholder(const tinfo_t &t, bool *first);
  uint32_t ty_udt(const tinfo_t &t, uint64_t size, uint32_t has_size);
  uint32_t ty_enum(const tinfo_t &t, uint64_t size, uint32_t has_size);
  uint32_t ty_typedef(const tinfo_t &t);
  uint32_t ty_func(const tinfo_t &t);
  uint32_t ty_bitfield(const tinfo_t &t);
  uint32_t ty_opaque(const tinfo_t &t);
};

uint32_t visit_walker_t::ty(const tinfo_t &t) {
  if (!t.empty() && t.is_typedef())
    return ty_typedef(t);
  return ty_resolved(t);
}

uint32_t visit_walker_t::ty_resolved(const tinfo_t &t) {
  size_t sz = t.get_size();
  uint32_t has_size = (sz != BADSIZE && sz != 0) ? 1 : 0;
  uint64_t size = has_size ? (uint64_t)sz : 0;
  uint32_t bytes = has_size ? (uint32_t)sz : 0;

  if (t.empty())
    return ty_opaque(t);
  if (t.is_ptr())
    return vis->ptr(ty(t.get_pointed_object()), size, has_size);
  if (t.is_array())
    return vis->array(ty(t.get_array_element()), (uint64_t)t.get_array_nelems(), size, has_size);
  if (t.is_func())
    return ty_func(t);
  if (t.is_udt())
    return ty_udt(t, size, has_size);
  if (t.is_enum())
    return ty_enum(t, size, has_size);
  if (t.is_bool())
    return vis->scalar(2, 0, 0, size, has_size);
  if (t.is_void())
    return vis->scalar(1, 0, 0, size, has_size);
  if (t.is_floating())
    return vis->scalar(4, bytes, 0, size, has_size);
  if (t.is_integral())
    return vis->scalar(3, bytes, t.is_signed() ? 1 : 0, size, has_size);
  if (t.is_bitfield())
    return ty_bitfield(t);
  return ty_opaque(t);
}

uint32_t visit_walker_t::ty_bitfield(const tinfo_t &t) {
  bitfield_type_data_t bi;
  if (t.get_bitfield_details(&bi)) {
    uint32_t nb = (uint32_t)bi.nbytes;
    return vis->scalar(3, nb, bi.is_unsigned ? 0 : 1, nb, nb != 0 ? 1 : 0);
  }
  return ty_opaque(t);
}

uint32_t visit_walker_t::ty_opaque(const tinfo_t &t) {
  qstring nm;
  if (t.get_type_name(&nm) && !nm.empty())
    return vis->opaque(borrow(nm));
  if (t.print(&nm) && !nm.empty())
    return vis->opaque(borrow(nm));
  return vis->opaque(borrow("?", 1));
}

uint32_t visit_walker_t::placeholder(const tinfo_t &t, bool *first) {
  qstring nm;
  if (t.get_type_name(&nm) && !nm.empty()) {
    uint32_t id = vis->named_ref(borrow(nm));
    *first = defined.insert(std::string(nm.c_str(), nm.length())).second;
    return id;
  }
  *first = true;
  return vis->anon();
}

uint32_t visit_walker_t::ty_udt(const tinfo_t &t, uint64_t size, uint32_t has_size) {
  bool first;
  uint32_t id = placeholder(t, &first);
  if (first) {
    udt_type_data_t udt;
    // Handles must be minted before the members slice is built (the members carry them), and the
    // udt's qstrings must outlive the fill_struct call the names borrow into -- so keep `udt` and
    // `ms` alive across the call below.
    std::vector<MemberInfo> ms;
    if (t.get_udt_details(&udt)) {
      ms.reserve(udt.size());
      for (const udm_t &m : udt) {
        MemberInfo md;
        md.name = borrow(m.name);
        md.bit_offset = m.offset;
        md.ty = ty(m.type);
        md.bitfield_width = m.is_bitfield() ? (uint32_t)m.size : 0;
        ms.push_back(md);
      }
    }
    rust::Slice<const MemberInfo> slice =
        ms.empty() ? rust::Slice<const MemberInfo>()
                   : rust::Slice<const MemberInfo>(ms.data(), ms.size());
    vis->fill_struct(id, t.is_union(), slice, size, has_size);
  }
  return id;
}

uint32_t visit_walker_t::ty_enum(const tinfo_t &t, uint64_t size, uint32_t has_size) {
  bool first;
  uint32_t id = placeholder(t, &first);
  if (first) {
    enum_type_data_t ed;
    std::vector<EnumConstInfo> cs;
    bool sgn = false;
    if (t.get_enum_details(&ed)) {
      sgn = ed.is_number_signed();
      cs.reserve(ed.size());
      for (const edm_t &m : ed) {
        EnumConstInfo ec;
        ec.name = borrow(m.name);
        ec.value = m.value;
        cs.push_back(ec);
      }
    }
    uint32_t base_bytes = has_size ? (uint32_t)size : 4;
    uint32_t underlying = vis->scalar(3, base_bytes, sgn ? 1 : 0, size, has_size);
    rust::Slice<const EnumConstInfo> slice =
        cs.empty() ? rust::Slice<const EnumConstInfo>()
                   : rust::Slice<const EnumConstInfo>(cs.data(), cs.size());
    vis->fill_enum(id, underlying, slice, size, has_size);
  }
  return id;
}

uint32_t visit_walker_t::ty_typedef(const tinfo_t &t) {
  bool first;
  uint32_t id = placeholder(t, &first);
  if (first) {
    qstring next;
    tinfo_t und;
    uint32_t under;
    if (t.get_next_type_name(&next) &&
        und.get_named_type(get_idati(), next.c_str(), BTF_TYPEDEF, false))
      under = ty(und);
    else
      under = ty_resolved(t);
    vis->fill_typedef(id, under);
  }
  return id;
}

uint32_t visit_walker_t::ty_func(const tinfo_t &t) {
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
    ret = vis->scalar(0, 0, 0, 0, 0);
  }
  rust::Slice<const uint32_t> slice =
      params.empty() ? rust::Slice<const uint32_t>()
                     : rust::Slice<const uint32_t>(params.data(), params.size());
  return vis->func(ret, slice, vararg);
}

visit_walker_t *visit_walker_new(void *visitor) {
  visit_walker_t *w = new visit_walker_t;
  w->vis = reinterpret_cast<TypeWalkVisitor *>(visitor);
  return w;
}

uint32_t visit_walker_ty(visit_walker_t *w, const tinfo_t &t) { return w->ty(t); }

void visit_walker_free(visit_walker_t *w) { delete w; }

uint32_t type_walk_visit_named(rust::Str name, TypeWalkVisitor &visitor) {
  tinfo_t tif;
  // rust::Str is not NUL-terminated; get_named_type wants a C string, so materialize one.
  std::string nm(name.data(), name.size());
  if (!tif.get_named_type(get_idati(), nm.c_str()))
    throw std::runtime_error("no such named type");
  visit_walker_t w;
  w.vis = &visitor;
  return w.ty(tif);
}

uint32_t type_walk_visit_ordinal(uint32_t ordinal, TypeWalkVisitor &visitor) {
  tinfo_t tif;
  if (!tif.get_numbered_type(get_idati(), ordinal))
    throw std::runtime_error("no type at ordinal");
  visit_walker_t w;
  w.vis = &visitor;
  return w.ty(tif);
}

uint32_t func_type_walk_visit(uint64_t ea, TypeWalkVisitor &visitor) {
  tinfo_t tif;
  if (!get_tinfo(&tif, (ea_t)ea) || tif.empty())
    throw std::runtime_error("function has no type info");
  visit_walker_t w;
  w.vis = &visitor;
  return w.ty(tif);
}

FrameWalk frame_type_walk_visit(uint64_t ea, TypeWalkVisitor &visitor) {
  // Sentinel for a reserved/untyped slot, matching IDAKIT_NONE on the Rust side.
  constexpr uint32_t NONE = 0xFFFFFFFFu;
  func_t *pfn = get_func((ea_t)ea);
  if (pfn == nullptr)
    throw std::runtime_error("no function at ea");
  tinfo_t tif;
  udt_type_data_t udt;
  if (!get_func_frame(&tif, pfn) || !tif.get_udt_details(&udt))
    throw std::runtime_error("function has no frame");

  FrameWalk out;
  out.size = (uint64_t)get_frame_size(pfn);
  visit_walker_t w;
  w.vis = &visitor;
  for (const udm_t &m : udt) {
    // bit0 = return address, bit1 = saved registers; both clear = an ordinary variable/argument.
    uint32_t flags = (m.is_retaddr() ? 1u : 0u) | (m.is_savregs() ? 2u : 0u);
    // Only a real, typed variable carries a structured type; reserved and untyped slots report
    // NONE, so the table holds only types a variable references.
    uint32_t ty = (flags == 0 && !m.type.empty()) ? w.ty(m.type) : NONE;
    FrameVar fv;
    fv.name = rust::String::lossy(std::string(m.name.c_str(), m.name.length()));
    // udm offset/size are in bits; soff_to_fpoff wants the byte struct offset.
    fv.offset = (int64_t)soff_to_fpoff(pfn, (uval_t)(m.offset / 8));
    fv.size = m.size / 8;
    fv.flags = flags;
    fv.ty = ty;
    out.vars.push_back(std::move(fv));
  }
  return out;
}

} // namespace idakit_cxx
