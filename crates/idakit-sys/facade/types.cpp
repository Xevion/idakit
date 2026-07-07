// idakit facade: local named types -- resolve a tinfo by name and expand its members.

#include <pro.h>

#include <ida.hpp>

#include <typeinf.hpp> // tinfo_t, print_type, get_tinfo, get_named_type

#include "idakit_facade.h"
#include "type_walk.hpp"

extern "C" int64_t idakit_func_type(idakit_ea_t ea, char *buf, size_t cap) {
  try {
    qstring out;
    if (!print_type(&out, (ea_t)ea, PRTYPE_1LINE | PRTYPE_SEMI)) {
      if (cap > 0)
        buf[0] = 0;
      return -1;
    }
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

// idakit_type_walk / idakit_func_type_walk drive the shared tinfo walker so a named type or
// function prototype resolves into one interned type table on the consumer side, with the root
// handle written to *root -- the structured counterpart to idakit_func_type's rendered string.
extern "C" int idakit_type_walk(const char *name, const idakit_type_vtbl_t *v, void *ctx,
                                uint32_t *root) {
  if (v == nullptr || root == nullptr)
    return 1;
  try {
    tinfo_t tif;
    if (!tif.get_named_type(get_idati(), name))
      return 1;
    idakit_facade::type_walker_t tw;
    tw.v = v;
    tw.ctx = ctx;
    *root = tw.ty(tif);
    return 0;
  } catch (...) {
    std::abort();
  }
}

extern "C" int idakit_func_type_walk(idakit_ea_t ea, const idakit_type_vtbl_t *v, void *ctx,
                                     uint32_t *root) {
  if (v == nullptr || root == nullptr)
    return 1;
  try {
    tinfo_t tif;
    // get_tinfo yields the function's stored prototype; a function IDA never typed has none.
    if (!get_tinfo(&tif, (ea_t)ea) || tif.empty())
      return 1;
    idakit_facade::type_walker_t tw;
    tw.v = v;
    tw.ctx = ctx;
    *root = tw.ty(tif);
    return 0;
  } catch (...) {
    std::abort();
  }
}

// Local-type enumeration. Ordinals run 1..limit; get_ordinal_limit is the exclusive upper bound.
extern "C" uint32_t idakit_type_ordinal_limit() {
  try {
    return get_ordinal_limit(get_idati());
  } catch (...) {
    std::abort();
  }
}

// Name of the type at `ordinal`: full length written snprintf-style, 0 for an anonymous type
// (empty name), -1 if no type occupies the ordinal.
extern "C" int64_t idakit_type_name_at(uint32_t ordinal, char *buf, size_t cap) {
  try {
    const char *name = get_numbered_type_name(get_idati(), ordinal);
    if (name == nullptr) {
      if (cap > 0)
        buf[0] = 0;
      return -1;
    }
    qstring out(name);
    qstrncpy(buf, out.c_str(), cap);
    return (int64_t)out.length();
  } catch (...) {
    std::abort();
  }
}

// Walk the type at `ordinal` into one interned table, the ordinal counterpart to idakit_type_walk.
extern "C" int idakit_type_walk_ordinal(uint32_t ordinal, const idakit_type_vtbl_t *v, void *ctx,
                                        uint32_t *root) {
  if (v == nullptr || root == nullptr)
    return 1;
  try {
    tinfo_t tif;
    if (!tif.get_numbered_type(get_idati(), ordinal))
      return 1;
    idakit_facade::type_walker_t tw;
    tw.v = v;
    tw.ctx = ctx;
    *root = tw.ty(tif);
    return 0;
  } catch (...) {
    std::abort();
  }
}
