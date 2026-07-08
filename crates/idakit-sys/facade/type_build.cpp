// idakit facade: type writes. Parse/resolve/build a tinfo and apply it, define types into the
// local til, and construct tinfos from a recipe. Two lowering shapes share one set of leaf/wrap
// helpers: the serialize-and-build interpreter (idakit_apply_type_recipe, idakit's preferred path)
// and the granular idakit_tinfo_* primitives (the node-at-a-time path for direct FFI).

#include <string>
#include <vector>

#include <pro.h>

#include <ida.hpp>

#include <kernwin.hpp> // msg (parse_decls error sink)
#include <nalt.hpp>    // get_tinfo, set_tinfo (address-level type note)
#include <typeinf.hpp> // tinfo_t, parse_decl, parse_decls, apply_tinfo, get_named_type, create_*

#include "idakit_facade.h"
#include "idakit_facade_internal.hpp" // guarded<>, g_output (msg-channel capture)

namespace {

// Copy the last guarded call's captured diagnostics (IDA's messages, caught off the msg channel
// by the HT_UI hook) into errbuf snprintf-style; empty when nothing was captured.
void copy_captured_reason(char *errbuf, size_t cap) {
  if (errbuf != nullptr && cap != 0)
    qstrncpy(errbuf, idakit_facade::g_output.c_str(), cap);
}

// Map a scalar integer leaf (width in bytes, signedness) onto the SDK's sized int types. False for
// a width IDA has no integer type for.
bool build_int(tinfo_t &out, uint8_t bytes, bool is_signed) {
  type_t base;
  switch (bytes) {
  case 1:
    base = BT_INT8;
    break;
  case 2:
    base = BT_INT16;
    break;
  case 4:
    base = BT_INT32;
    break;
  case 8:
    base = BT_INT64;
    break;
  case 16:
    base = BT_INT128;
    break;
  default:
    return false;
  }
  return out.create_simple_type(base | (is_signed ? BTMT_SIGNED : BTMT_UNSIGNED));
}

// Map a float leaf (4 -> float, 8 -> double) onto BT_FLOAT. False for any other width.
bool build_float(tinfo_t &out, uint8_t bytes) {
  type_t mt;
  switch (bytes) {
  case 4:
    mt = BTMT_FLOAT;
    break;
  case 8:
    mt = BTMT_DOUBLE;
    break;
  default:
    return false;
  }
  return out.create_simple_type(BT_FLOAT | mt);
}

// Resolve `name` to a typedef ref (resolve=false keeps the name in the applied type rather than
// its expansion, so `Foo *` stays `Foo *`). False if the local til has no such type.
bool build_named(tinfo_t &out, const char *name) {
  return out.get_named_type(get_idati(), name, BTF_TYPEDEF, false);
}

// A bounds-checked cursor over a recipe buffer: every read verifies it stays within the buffer,
// leaving `ok` false (and yielding zeros) on an over-read so the interpreter bails to ERR_INPUT.
struct recipe_reader {
  const uint8_t *p;
  size_t len;
  size_t pos = 0;
  bool ok = true;

  bool has_more() const { return ok && pos < len; }

  uint8_t u8() {
    if (pos + 1 > len) {
      ok = false;
      return 0;
    }
    return p[pos++];
  }

  uint64_t uint_le(size_t n) {
    if (pos + n > len) {
      ok = false;
      return 0;
    }
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++)
      v |= (uint64_t)p[pos++] << (8 * i);
    return v;
  }

  // A u32-length-prefixed byte string (a type name or a decl; neither carries an interior NUL).
  bool str(std::string &out) {
    uint64_t n = uint_le(4);
    if (!ok || pos + (size_t)n > len) {
      ok = false;
      return false;
    }
    out.assign((const char *)(p + pos), (size_t)n);
    pos += (size_t)n;
    return true;
  }
};

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

// Clear any type applied at ea (set_tinfo to null). Idempotent: an address with no type note (or an
// unmapped one) is already clear and reports OK; _ERR_APPLY means the kernel refused to remove an
// existing type.
extern "C" int idakit_clear_type(idakit_ea_t ea) {
  try {
    using namespace idakit_facade;
    return guarded<int>(IDAKIT_TYPE_ERR_APPLY, false, [&]() -> int {
      tinfo_t cur;
      if (!get_tinfo(&cur, (ea_t)ea) || cur.empty())
        return IDAKIT_TYPE_OK;
      return set_tinfo((ea_t)ea, nullptr) ? IDAKIT_TYPE_OK : IDAKIT_TYPE_ERR_APPLY;
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

namespace {
// Run the postfix recipe in (buf, len) over a tinfo stack, leaving the single resulting type in
// `out`: a leaf op pushes a type, a transform pops one and pushes the wrapped result, and a
// well-formed recipe leaves exactly one. IDAKIT_TYPE_OK with `out` set, else IDAKIT_TYPE_ERR_INPUT
// (malformed buffer, unresolved named leaf, or unparseable embedded decl). The shared lowering
// behind idakit_apply_type_recipe and the signature-surgery shims; callers wrap it in guarded<>
// (parse_decl/get_named_type/create_func may emit or trap).
int build_recipe(const uint8_t *buf, size_t len, tinfo_t &out) {
  recipe_reader r{buf, len};
  std::vector<tinfo_t> stack;
  while (r.has_more()) {
    uint8_t op = r.u8();
    switch (op) {
    case IDAKIT_RECIPE_VOID: {
      tinfo_t t;
      if (!t.create_simple_type(BTF_VOID))
        return IDAKIT_TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case IDAKIT_RECIPE_BOOL: {
      tinfo_t t;
      if (!t.create_simple_type(BT_BOOL))
        return IDAKIT_TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case IDAKIT_RECIPE_INT: {
      uint8_t bytes = r.u8();
      uint8_t is_signed = r.u8();
      tinfo_t t;
      if (!r.ok || !build_int(t, bytes, is_signed != 0))
        return IDAKIT_TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case IDAKIT_RECIPE_FLOAT: {
      uint8_t bytes = r.u8();
      tinfo_t t;
      if (!r.ok || !build_float(t, bytes))
        return IDAKIT_TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case IDAKIT_RECIPE_NAMED: {
      std::string name;
      if (!r.str(name))
        return IDAKIT_TYPE_ERR_INPUT;
      tinfo_t t;
      if (!build_named(t, name.c_str()))
        return IDAKIT_TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case IDAKIT_RECIPE_DECL: {
      std::string decl;
      if (!r.str(decl))
        return IDAKIT_TYPE_ERR_INPUT;
      tinfo_t t;
      qstring pname;
      if (!parse_decl(&t, &pname, get_idati(), decl.c_str(), PT_SEMICOLON))
        return IDAKIT_TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case IDAKIT_RECIPE_PTR: {
      if (stack.empty())
        return IDAKIT_TYPE_ERR_INPUT;
      tinfo_t inner = stack.back();
      stack.pop_back();
      tinfo_t t;
      if (!t.create_ptr(inner))
        return IDAKIT_TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case IDAKIT_RECIPE_ARRAY: {
      uint64_t nelems = r.uint_le(8);
      if (!r.ok || nelems > 0xffffffffULL || stack.empty())
        return IDAKIT_TYPE_ERR_INPUT;
      tinfo_t inner = stack.back();
      stack.pop_back();
      tinfo_t t;
      if (!t.create_array(inner, (uint32)nelems))
        return IDAKIT_TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case IDAKIT_RECIPE_CONST: {
      if (stack.empty())
        return IDAKIT_TYPE_ERR_INPUT;
      stack.back().set_const();
      break;
    }
    case IDAKIT_RECIPE_VOLATILE: {
      if (stack.empty())
        return IDAKIT_TYPE_ERR_INPUT;
      stack.back().set_volatile();
      break;
    }
    case IDAKIT_RECIPE_FUNCTION: {
      uint64_t nparams = r.uint_le(4);
      uint8_t varargs = r.u8();
      uint64_t cc = r.uint_le(2);
      std::vector<std::string> names((size_t)nparams);
      for (uint64_t i = 0; i < nparams && r.ok; i++)
        r.str(names[(size_t)i]);
      // The return type sits just below the params on the stack (return pushed first).
      if (!r.ok || stack.size() < (size_t)nparams + 1)
        return IDAKIT_TYPE_ERR_INPUT;
      func_type_data_t ftd;
      size_t base = stack.size() - (size_t)nparams;
      ftd.rettype = stack[base - 1];
      for (size_t i = 0; i < (size_t)nparams; i++) {
        funcarg_t arg;
        arg.type = stack[base + i];
        arg.name = names[i].c_str();
        ftd.push_back(arg);
      }
      stack.resize(base - 1);
      // Varargs is IDA's ellipsis convention; an explicit cc otherwise, else the default.
      if (varargs != 0)
        ftd.set_cc(CM_CC_ELLIPSIS);
      else if (cc != 0)
        ftd.set_cc((callcnv_t)cc);
      tinfo_t t;
      if (!t.create_func(ftd))
        return IDAKIT_TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    default:
      return IDAKIT_TYPE_ERR_INPUT;
    }
  }
  if (!r.ok || stack.size() != 1)
    return IDAKIT_TYPE_ERR_INPUT;
  out = stack[0];
  return IDAKIT_TYPE_OK;
}

// Read ea's function type into (tif, ftd); false if ea carries no function type to edit. Reads
// without recomputing arg locations (GTD_NO_ARGLOCS); rebuild_and_apply forces a recompute.
bool read_func_details(ea_t ea, tinfo_t &tif, func_type_data_t &ftd) {
  return get_tinfo(&tif, ea) && !tif.empty() && tif.get_func_details(&ftd, GTD_NO_ARGLOCS);
}

// Rebuild the function type from mutated details and re-apply it at ea. Clears any explicit arg
// locations the edit invalidated so create_func recomputes them. IDAKIT_SIG_APPLY if create_func or
// apply_tinfo rejects the result.
int rebuild_and_apply(ea_t ea, func_type_data_t &ftd) {
  ftd.flags &= ~(FTI_ARGLOCS | FTI_EXPLOCS);
  tinfo_t nt;
  if (!nt.create_func(ftd))
    return IDAKIT_SIG_APPLY;
  if (!apply_tinfo(ea, nt, TINFO_DEFINITE))
    return IDAKIT_SIG_APPLY;
  return IDAKIT_SIG_OK;
}
} // namespace

// Build the tinfo the postfix recipe in (buf, len) encodes and apply it at ea (apply_tinfo,
// TINFO_DEFINITE | flags). ERR_INPUT is a malformed buffer, an unresolved named leaf, or an
// unparseable embedded decl; apply_tinfo rejection is _ERR_APPLY. Build+apply run under one
// fatal-trap guard, with any decl/apply diagnostic captured into errbuf.
extern "C" int idakit_apply_type_recipe(idakit_ea_t ea, const uint8_t *buf, size_t len, int flags,
                                        char *errbuf, size_t cap) {
  try {
    using namespace idakit_facade;
    if (errbuf != nullptr && cap != 0)
      errbuf[0] = 0;
    int code = guarded<int>(IDAKIT_TYPE_ERR_APPLY, true, [&]() -> int {
      tinfo_t t;
      int rc = build_recipe(buf, len, t);
      if (rc != IDAKIT_TYPE_OK)
        return rc;
      if (!apply_tinfo((ea_t)ea, t, (uint32)flags | TINFO_DEFINITE))
        return IDAKIT_TYPE_ERR_APPLY;
      return IDAKIT_TYPE_OK;
    });
    copy_captured_reason(errbuf, cap);
    return code;
  } catch (...) {
    std::abort();
  }
}

namespace {
// A handle is a heap tinfo_t; each builder mints one, apply reads one, free disposes one.
tinfo_t *as_tif(const void *h) { return (tinfo_t *)h; }
void *heap(const tinfo_t &t) { return (void *)new tinfo_t(t); }
} // namespace

extern "C" void *idakit_tinfo_void(void) {
  try {
    tinfo_t t;
    return t.create_simple_type(BTF_VOID) ? heap(t) : nullptr;
  } catch (...) {
    std::abort();
  }
}

extern "C" void *idakit_tinfo_bool(void) {
  try {
    tinfo_t t;
    return t.create_simple_type(BT_BOOL) ? heap(t) : nullptr;
  } catch (...) {
    std::abort();
  }
}

extern "C" void *idakit_tinfo_int(uint8_t bytes, int is_signed) {
  try {
    tinfo_t t;
    return build_int(t, bytes, is_signed != 0) ? heap(t) : nullptr;
  } catch (...) {
    std::abort();
  }
}

extern "C" void *idakit_tinfo_float(uint8_t bytes) {
  try {
    tinfo_t t;
    return build_float(t, bytes) ? heap(t) : nullptr;
  } catch (...) {
    std::abort();
  }
}

extern "C" void *idakit_tinfo_named(const char *name) {
  try {
    tinfo_t t;
    return build_named(t, name) ? heap(t) : nullptr;
  } catch (...) {
    std::abort();
  }
}

extern "C" void *idakit_tinfo_decl(const char *decl, char *errbuf, size_t cap) {
  try {
    using namespace idakit_facade;
    if (errbuf != nullptr && cap != 0)
      errbuf[0] = 0;
    tinfo_t t;
    bool ok = guarded<bool>(false, true, [&]() -> bool {
      qstring pname;
      return parse_decl(&t, &pname, get_idati(), decl, PT_SEMICOLON);
    });
    copy_captured_reason(errbuf, cap);
    return ok ? heap(t) : nullptr;
  } catch (...) {
    std::abort();
  }
}

extern "C" void *idakit_tinfo_ptr(const void *inner) {
  try {
    if (inner == nullptr)
      return nullptr;
    tinfo_t t;
    return t.create_ptr(*as_tif(inner)) ? heap(t) : nullptr;
  } catch (...) {
    std::abort();
  }
}

extern "C" void *idakit_tinfo_array(const void *inner, uint64_t nelems) {
  try {
    if (inner == nullptr || nelems > 0xffffffffULL)
      return nullptr;
    tinfo_t t;
    return t.create_array(*as_tif(inner), (uint32)nelems) ? heap(t) : nullptr;
  } catch (...) {
    std::abort();
  }
}

extern "C" void *idakit_tinfo_const(const void *inner) {
  try {
    if (inner == nullptr)
      return nullptr;
    tinfo_t t(*as_tif(inner));
    t.set_const();
    return heap(t);
  } catch (...) {
    std::abort();
  }
}

extern "C" void *idakit_tinfo_volatile(const void *inner) {
  try {
    if (inner == nullptr)
      return nullptr;
    tinfo_t t(*as_tif(inner));
    t.set_volatile();
    return heap(t);
  } catch (...) {
    std::abort();
  }
}

extern "C" int idakit_tinfo_apply(idakit_ea_t ea, const void *handle, int flags, char *errbuf,
                                  size_t cap) {
  try {
    using namespace idakit_facade;
    if (errbuf != nullptr && cap != 0)
      errbuf[0] = 0;
    if (handle == nullptr)
      return IDAKIT_TYPE_ERR_INPUT;
    int code = guarded<int>(IDAKIT_TYPE_ERR_APPLY, true, [&]() -> int {
      if (!apply_tinfo((ea_t)ea, *as_tif(handle), (uint32)flags | TINFO_DEFINITE))
        return IDAKIT_TYPE_ERR_APPLY;
      return IDAKIT_TYPE_OK;
    });
    copy_captured_reason(errbuf, cap);
    return code;
  } catch (...) {
    std::abort();
  }
}

extern "C" void idakit_tinfo_free(void *handle) {
  try {
    delete as_tif(handle);
  } catch (...) {
    std::abort();
  }
}

// Prototype surgery: each shim reads ea's function type, mutates one field, and rebuilds+re-applies
// (create_func -> apply_tinfo) under one fatal-trap guard. SIG_NO_PROTOTYPE if ea has no function
// type; SIG_ARG_RANGE if an index is past the last parameter (the current count is written to
// `arity`); SIG_BUILD if a replacement-type recipe does not build; SIG_APPLY if the kernel rejects
// the rebuilt signature. Any parse/apply diagnostic is captured into errbuf.

extern "C" int idakit_func_set_rettype(idakit_ea_t ea, const uint8_t *recipe, size_t len,
                                       char *errbuf, size_t cap) {
  try {
    using namespace idakit_facade;
    if (errbuf != nullptr && cap != 0)
      errbuf[0] = 0;
    int code = guarded<int>(IDAKIT_SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return IDAKIT_SIG_NO_PROTOTYPE;
      tinfo_t rt;
      if (build_recipe(recipe, len, rt) != IDAKIT_TYPE_OK)
        return IDAKIT_SIG_BUILD;
      ftd.rettype = rt;
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    copy_captured_reason(errbuf, cap);
    return code;
  } catch (...) {
    std::abort();
  }
}

extern "C" int idakit_func_set_argtype(idakit_ea_t ea, size_t idx, const uint8_t *recipe,
                                       size_t len, size_t *arity, char *errbuf, size_t cap) {
  try {
    using namespace idakit_facade;
    if (errbuf != nullptr && cap != 0)
      errbuf[0] = 0;
    if (arity != nullptr)
      *arity = 0;
    int code = guarded<int>(IDAKIT_SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return IDAKIT_SIG_NO_PROTOTYPE;
      if (arity != nullptr)
        *arity = ftd.size();
      if (idx >= ftd.size())
        return IDAKIT_SIG_ARG_RANGE;
      tinfo_t at;
      if (build_recipe(recipe, len, at) != IDAKIT_TYPE_OK)
        return IDAKIT_SIG_BUILD;
      ftd[idx].type = at;
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    copy_captured_reason(errbuf, cap);
    return code;
  } catch (...) {
    std::abort();
  }
}

extern "C" int idakit_func_rename_arg(idakit_ea_t ea, size_t idx, const char *name, size_t *arity,
                                      char *errbuf, size_t cap) {
  try {
    using namespace idakit_facade;
    if (errbuf != nullptr && cap != 0)
      errbuf[0] = 0;
    if (arity != nullptr)
      *arity = 0;
    int code = guarded<int>(IDAKIT_SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return IDAKIT_SIG_NO_PROTOTYPE;
      if (arity != nullptr)
        *arity = ftd.size();
      if (idx >= ftd.size())
        return IDAKIT_SIG_ARG_RANGE;
      ftd[idx].name = name;
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    copy_captured_reason(errbuf, cap);
    return code;
  } catch (...) {
    std::abort();
  }
}

extern "C" int idakit_func_set_cc(idakit_ea_t ea, int cc, char *errbuf, size_t cap) {
  try {
    using namespace idakit_facade;
    if (errbuf != nullptr && cap != 0)
      errbuf[0] = 0;
    int code = guarded<int>(IDAKIT_SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return IDAKIT_SIG_NO_PROTOTYPE;
      ftd.set_cc((callcnv_t)cc);
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    copy_captured_reason(errbuf, cap);
    return code;
  } catch (...) {
    std::abort();
  }
}

extern "C" int idakit_func_prepend_this(idakit_ea_t ea, const uint8_t *recipe, size_t len,
                                        char *errbuf, size_t cap) {
  try {
    using namespace idakit_facade;
    if (errbuf != nullptr && cap != 0)
      errbuf[0] = 0;
    int code = guarded<int>(IDAKIT_SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return IDAKIT_SIG_NO_PROTOTYPE;
      tinfo_t pt;
      if (build_recipe(recipe, len, pt) != IDAKIT_TYPE_OK)
        return IDAKIT_SIG_BUILD;
      funcarg_t self_arg;
      self_arg.type = pt;
      self_arg.name = "this";
      ftd.insert(ftd.begin(), self_arg);
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    copy_captured_reason(errbuf, cap);
    return code;
  } catch (...) {
    std::abort();
  }
}
