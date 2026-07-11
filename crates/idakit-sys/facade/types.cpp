// idakit facade: local type reads. Render a function's prototype and enumerate the local type
// library. The structured type walks are the cxx opaque-visitor entries (typewalk_cxx.cc); the
// type writes (apply/define/build) live in type_build.cpp.

#include <pro.h>

#include <ida.hpp>

#include <typeinf.hpp> // tinfo_t, print_type

#include "idakit_facade.h"

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
