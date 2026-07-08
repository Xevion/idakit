// idakit facade: local named types -- resolve a tinfo by name, expand its members, and apply
// a parsed or named type to an address.

#include <pro.h>

#include <ida.hpp>

#include <kernwin.hpp> // msg (printer_t for parse_decls)
#include <typeinf.hpp> // tinfo_t, print_type, get_tinfo, get_named_type, parse_decl, apply_tinfo

#include "idakit_facade.h"
#include "idakit_facade_internal.hpp" // guarded<>, g_output (msg-channel capture)
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

namespace {
// Copy the last guarded call's captured diagnostics (IDA's messages, caught off the msg channel
// by the HT_UI hook) into errbuf snprintf-style; empty when nothing was captured.
void copy_captured_reason(char *errbuf, size_t cap) {
  if (errbuf != nullptr && cap != 0)
    qstrncpy(errbuf, idakit_facade::g_output.c_str(), cap);
}
} // namespace

// Parse `decl` against the local til and apply the resulting type at ea, forcing TINFO_DEFINITE
// (caller `flags` add TINFO_DELAYFUNC/STRICT). PT_SIL is deliberately NOT set: without it IDA
// emits its parse diagnostic, which the guarded capture intercepts off the msg channel with no
// dialog (headless), giving a real reason. Returns IDAKIT_TYPE_OK / _ERR_INPUT (parse failed) /
// _ERR_APPLY (apply_tinfo rejected it); the reason lands in errbuf on a parse failure.
extern "C" int idakit_apply_type_decl(idakit_ea_t ea, const char *decl, int flags, char *errbuf,
                                      size_t cap) {
  try {
    using namespace idakit_facade;
    if (errbuf != nullptr && cap != 0)
      errbuf[0] = 0;
    int code = guarded<int>(IDAKIT_TYPE_ERR_APPLY, true, [&]() -> int {
      tinfo_t tif;
      qstring name;
      if (!parse_decl(&tif, &name, get_idati(), decl, PT_SEMICOLON))
        return IDAKIT_TYPE_ERR_INPUT;
      if (!apply_tinfo((ea_t)ea, tif, (uint32)flags | TINFO_DEFINITE))
        return IDAKIT_TYPE_ERR_APPLY;
      return IDAKIT_TYPE_OK;
    });
    copy_captured_reason(errbuf, cap);
    return code;
  } catch (...) {
    std::abort();
  }
}

// Resolve the existing named type `name` in the local til and apply it at ea, under the same
// fatal-trap guard as the decl path (capture=false: this path emits no msg to capture). No error
// channel; the result code alone distinguishes not-found (_ERR_INPUT) from an apply rejection
// (_ERR_APPLY), so the by-name path yields a clean TypeNotFound on the Rust side.
extern "C" int idakit_apply_named_type(idakit_ea_t ea, const char *name) {
  try {
    using namespace idakit_facade;
    return guarded<int>(IDAKIT_TYPE_ERR_APPLY, false, [&]() -> int {
      tinfo_t tif;
      if (!tif.get_named_type(get_idati(), name))
        return IDAKIT_TYPE_ERR_INPUT;
      if (!apply_tinfo((ea_t)ea, tif, TINFO_DEFINITE))
        return IDAKIT_TYPE_ERR_APPLY;
      return IDAKIT_TYPE_OK;
    });
  } catch (...) {
    std::abort();
  }
}

// Parse the C declaration(s) in `input` into the database's local til (get_idati()), routing each
// error through `msg` so the guarded capture folds it into errbuf. Returns the error count (0 =
// ok); parse_decls always applies HTI_DCL, so redeclarations are tolerated.
extern "C" int idakit_define_type(const char *input, char *errbuf, size_t cap) {
  try {
    using namespace idakit_facade;
    if (errbuf != nullptr && cap != 0)
      errbuf[0] = 0;
    int nerr = guarded<int>(1, true,
                            [&]() -> int { return parse_decls(get_idati(), input, msg, HTI_DCL); });
    copy_captured_reason(errbuf, cap);
    return nerr;
  } catch (...) {
    std::abort();
  }
}
