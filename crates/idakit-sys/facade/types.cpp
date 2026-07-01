// idakit facade: local named types -- resolve a tinfo by name and expand its members.

#include <pro.h>

#include <ida.hpp>

#include <typeinf.hpp> // tinfo_t, udt_type_data_t, print_type

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

// A resolved named type plus its expanded member layout (if it is a struct/union).
struct idakit_type_t {
  tinfo_t tif;
  udt_type_data_t udt;
  bool is_udt = false;
};

extern "C" void *idakit_type_open(const char *name) {
  try {
    idakit_type_t *t = new idakit_type_t;
    if (!t->tif.get_named_type(get_idati(), name)) {
      delete t;
      return nullptr;
    }
    t->is_udt = t->tif.get_udt_details(&t->udt);
    return t;
  } catch (...) {
    std::abort();
  }
}

extern "C" void idakit_type_dispose(void *h) { delete reinterpret_cast<idakit_type_t *>(h); }

extern "C" int64_t idakit_type_size(void *h) {
  size_t s = reinterpret_cast<idakit_type_t *>(h)->tif.get_size();
  return s == BADSIZE ? -1 : (int64_t)s;
}

extern "C" int64_t idakit_type_print(void *h, char *buf, size_t cap) {
  try {
    qstring out;
    if (!reinterpret_cast<idakit_type_t *>(h)->tif.print(&out)) {
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

extern "C" size_t idakit_type_nmembers(void *h) {
  idakit_type_t *t = reinterpret_cast<idakit_type_t *>(h);
  return t->is_udt ? t->udt.size() : 0;
}

// Split into a metadata call + two length-returning string getters so the caller
// can detect truncation and re-read; a combined call could only return a bool.
extern "C" int idakit_type_member_info(void *h, size_t i, uint64_t *offset, uint64_t *size) {
  idakit_type_t *t = reinterpret_cast<idakit_type_t *>(h);
  if (!t->is_udt || i >= t->udt.size())
    return 0;
  const udm_t &m = t->udt[i];
  *offset = m.offset / 8; // SDK reports member offset/size in bits
  *size = m.size / 8;
  return 1;
}

extern "C" int64_t idakit_type_member_name(void *h, size_t i, char *buf, size_t cap) {
  idakit_type_t *t = reinterpret_cast<idakit_type_t *>(h);
  if (!t->is_udt || i >= t->udt.size()) {
    if (cap > 0)
      buf[0] = 0;
    return -1;
  }
  const qstring &name = t->udt[i].name;
  qstrncpy(buf, name.c_str(), cap);
  return (int64_t)name.length();
}

extern "C" int64_t idakit_type_member_type(void *h, size_t i, char *buf, size_t cap) {
  try {
    idakit_type_t *t = reinterpret_cast<idakit_type_t *>(h);
    if (!t->is_udt || i >= t->udt.size()) {
      if (cap > 0)
        buf[0] = 0;
      return -1;
    }
    qstring ts;
    t->udt[i].type.print(&ts);
    qstrncpy(buf, ts.c_str(), cap);
    return (int64_t)ts.length();
  } catch (...) {
    std::abort();
  }
}

extern "C" size_t idakit_type_ordinal_count(void) { return get_ordinal_count(get_idati()); }

extern "C" int64_t idakit_type_ordinal_name(uint32_t ordinal, char *buf, size_t cap) {
  const char *nm = get_numbered_type_name(get_idati(), ordinal);
  if (nm == nullptr) {
    if (cap > 0)
      buf[0] = 0;
    return -1;
  }
  qstrncpy(buf, nm, cap);
  return (int64_t)qstrlen(nm);
}
