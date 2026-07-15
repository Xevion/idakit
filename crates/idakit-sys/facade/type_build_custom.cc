// Hand-written Custom bodies for the generated type-write domain (namespace idakit_gen). Each fn
// parses/resolves/builds a tinfo and applies it, defines types into the local til, or edits a
// UDT/enum member, then reports an int result code plus captured diagnostic through a
// TypeWriteResult/SigWriteResult shared struct: `code` carries the outcome, `reason` the
// captured diagnostic (empty where a call has no error channel), and `arity` (signature surgery)
// the parameter count. The leaf/recipe/surgery helpers have internal linkage and cannot be shared
// across the translation-unit boundary, so this TU carries its own copies.

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <pro.h>

#include <ida.hpp>

#include <kernwin.hpp> // msg (parse_decls error sink)
#include <nalt.hpp>    // get_tinfo, set_tinfo (address-level type note)
#include <typeinf.hpp> // tinfo_t, parse_decl, parse_decls, apply_tinfo, create_*

#include "idakit_facade_internal.hpp" // guarded<>, g_output (msg-channel capture)
#include "gen_type_build.h"
// The generated bridge header defines the shared structs (full definitions needed to construct them
// below); gen_type_build.h only forward-declares them.
#include "gen_bridge.h"

using namespace idakit_facade;

namespace idakit_gen {

namespace {

// The last guarded call's captured diagnostics (IDA's messages, caught off the msg channel by the
// HT_UI hook) as an owned string; empty when nothing was captured. This is the one genuinely
// untrusted byte source (arbitrary msg() text, not a sanitized database string), so it decodes
// leniently: the throwing ctor would std::terminate inside these by-value, non-Result bodies.
rust::String captured_reason() {
  return to_rust_string(g_output.c_str(), g_output.length());
}

// Map a scalar integer leaf (width in bytes, signedness) onto the SDK's sized int types. False for
// a width IDA has no integer type for.
bool build_int(tinfo_t &out, uint32_t bytes, bool is_signed) {
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
bool build_float(tinfo_t &out, uint32_t bytes) {
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
// its expansion, so `Foo *` stays `Foo *`). With resolve=false this returns true even for a name
// absent from the local til, building a forward reference the caller must existence-check itself.
bool build_named(tinfo_t &out, const char *name) {
  return out.get_named_type(get_idati(), name, BTF_TYPEDEF, false);
}

// Build a bitfield leaf (create_bitfield): nbytes is the container width in bytes, width the
// field's bit width. False if the kernel rejects the combination (e.g. width exceeding nbytes*8).
bool build_bitfield(tinfo_t &out, uint8_t nbytes, uint8_t width, bool is_unsigned) {
  return out.create_bitfield(nbytes, width, is_unsigned);
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

// Run the postfix recipe in (buf, len) over a tinfo stack, leaving the single resulting type in
// `out`: a leaf op pushes a type, a transform pops one and pushes the wrapped result, and a
// well-formed recipe leaves exactly one. TYPE_OK with `out` set, else TYPE_ERR_INPUT
// (malformed buffer, unresolved named leaf, or unparseable embedded decl). Callers wrap it in
// guarded<> (parse_decl/get_named_type/create_func may emit or trap).
int build_recipe(const uint8_t *buf, size_t len, tinfo_t &out) {
  recipe_reader r{buf, len};
  std::vector<tinfo_t> stack;
  while (r.has_more()) {
    uint8_t op = r.u8();
    switch (op) {
    case RECIPE_VOID: {
      tinfo_t t;
      if (!t.create_simple_type(BTF_VOID))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case RECIPE_BOOL: {
      tinfo_t t;
      if (!t.create_simple_type(BT_BOOL))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case RECIPE_INT: {
      uint8_t bytes = r.u8();
      uint8_t is_signed = r.u8();
      tinfo_t t;
      if (!r.ok || !build_int(t, bytes, is_signed != 0))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case RECIPE_FLOAT: {
      uint8_t bytes = r.u8();
      tinfo_t t;
      if (!r.ok || !build_float(t, bytes))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case RECIPE_NAMED: {
      std::string name;
      if (!r.str(name))
        return TYPE_ERR_INPUT;
      tinfo_t t;
      if (!build_named(t, name.c_str()))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case RECIPE_DECL: {
      std::string decl;
      if (!r.str(decl))
        return TYPE_ERR_INPUT;
      tinfo_t t;
      qstring pname;
      if (!parse_decl(&t, &pname, get_idati(), decl.c_str(), PT_SEMICOLON))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case RECIPE_PTR: {
      if (stack.empty())
        return TYPE_ERR_INPUT;
      tinfo_t inner = stack.back();
      stack.pop_back();
      tinfo_t t;
      if (!t.create_ptr(inner))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case RECIPE_ARRAY: {
      uint64_t nelems = r.uint_le(8);
      if (!r.ok || nelems > 0xffffffffULL || stack.empty())
        return TYPE_ERR_INPUT;
      tinfo_t inner = stack.back();
      stack.pop_back();
      tinfo_t t;
      if (!t.create_array(inner, (uint32)nelems))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case RECIPE_CONST: {
      if (stack.empty())
        return TYPE_ERR_INPUT;
      stack.back().set_const();
      break;
    }
    case RECIPE_VOLATILE: {
      if (stack.empty())
        return TYPE_ERR_INPUT;
      stack.back().set_volatile();
      break;
    }
    case RECIPE_FUNCTION: {
      uint64_t nparams = r.uint_le(4);
      uint8_t varargs = r.u8();
      uint64_t cc = r.uint_le(2);
      std::vector<std::string> names((size_t)nparams);
      for (uint64_t i = 0; i < nparams && r.ok; i++)
        r.str(names[(size_t)i]);
      // The return type sits just below the params on the stack (return pushed first).
      if (!r.ok || stack.size() < (size_t)nparams + 1)
        return TYPE_ERR_INPUT;
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
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case RECIPE_BITFIELD: {
      uint8_t nbytes = r.u8();
      uint8_t width = r.u8();
      uint8_t is_signed = r.u8();
      tinfo_t t;
      if (!r.ok || !build_bitfield(t, nbytes, width, is_signed == 0))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    default:
      return TYPE_ERR_INPUT;
    }
  }
  if (!r.ok || stack.size() != 1)
    return TYPE_ERR_INPUT;
  out = stack[0];
  return TYPE_OK;
}

// Read ea's function type into (tif, ftd); false if ea carries no function type to edit. Reads
// without recomputing arg locations (GTD_NO_ARGLOCS); rebuild_and_apply forces a recompute.
bool read_func_details(ea_t ea, tinfo_t &tif, func_type_data_t &ftd) {
  return get_tinfo(&tif, ea) && !tif.empty() && tif.get_func_details(&ftd, GTD_NO_ARGLOCS);
}

// Rebuild the function type from mutated details and re-apply it at ea. Clears any explicit arg
// locations the edit invalidated so create_func recomputes them. SIG_APPLY if create_func or
// apply_tinfo rejects the result.
int rebuild_and_apply(ea_t ea, func_type_data_t &ftd) {
  ftd.flags &= ~(FTI_ARGLOCS | FTI_EXPLOCS);
  tinfo_t nt;
  if (!nt.create_func(ftd))
    return SIG_APPLY;
  if (!apply_tinfo(ea, nt, TINFO_DEFINITE))
    return SIG_APPLY;
  return SIG_OK;
}

// Link `tif` to the named type in the local til for editing. Edits to the returned typeref save
// back to the til and propagate to every reference (ETF_NO_SAVE stays unset). False if no such
// type. Resolves ANY named type without checking it's a UDT vs enum: the kernel verb that follows
// (add_udm, get_edm, ...) already rejects a mismatched target.
bool load_named_type(const char *type_name, tinfo_t &tif) {
  return tif.get_named_type(get_idati(), type_name) && !tif.empty();
}

// Resolve a member index in `tif`: by name when `member_name` is non-null, else by bit offset.
// -1 if no member matches.
int resolve_member(const tinfo_t &tif, const char *member_name, uint64_t member_bit) {
  udm_t key;
  int flags;
  if (member_name != nullptr) {
    key.name = member_name;
    flags = STRMEM_NAME;
  } else {
    key.offset = member_bit;
    flags = STRMEM_OFFSET;
  }
  return tif.find_udm(&key, flags);
}

// Resolve an enum constant index by name; -1 if not found. Constants are keyed by name (values may
// repeat within a bitmask enum, names are unique).
ssize_t resolve_edm(const tinfo_t &tif, const char *name) {
  edm_t edm;
  return tif.get_edm(&edm, name);
}

// A bitfield member's declared field width in bits, or false for an ordinary type. add_udm's
// auto-size path (the name/type/offset overload) derives a member's size from the type's byte
// size, which for a bitfield tinfo_t is its container width, not the narrower field it actually
// occupies; callers that add or retype a member must set udm_t::size to this width explicitly
// instead of relying on that auto-size path.
bool bitfield_width_bits(const tinfo_t &mt, uint16 &width) {
  if (!mt.is_bitfield())
    return false;
  bitfield_type_data_t bi;
  if (!mt.get_bitfield_details(&bi))
    return false;
  width = bi.width;
  return true;
}

} // namespace

TypeWriteResult apply_type_decl(uint64_t ea, rust::Str decl, int32_t flags) {
  try {
    TypeWriteResult out{};
    std::string decls(decl.data(), decl.size());
    out.code = guarded<int>(TYPE_ERR_APPLY, true, [&]() -> int {
      tinfo_t tif;
      qstring name;
      if (!parse_decl(&tif, &name, get_idati(), decls.c_str(), PT_SEMICOLON))
        return TYPE_ERR_INPUT;
      if (!apply_tinfo((ea_t)ea, tif, (uint32)flags | TINFO_DEFINITE))
        return TYPE_ERR_APPLY;
      return TYPE_OK;
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult apply_named_type(uint64_t ea, rust::Str name) {
  try {
    TypeWriteResult out{};
    std::string names(name.data(), name.size());
    out.code = guarded<int>(TYPE_ERR_APPLY, false, [&]() -> int {
      tinfo_t tif;
      if (!tif.get_named_type(get_idati(), names.c_str()))
        return TYPE_ERR_INPUT;
      if (!apply_tinfo((ea_t)ea, tif, TINFO_DEFINITE))
        return TYPE_ERR_APPLY;
      return TYPE_OK;
    });
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult clear_type(uint64_t ea) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(TYPE_ERR_APPLY, false, [&]() -> int {
      tinfo_t cur;
      if (!get_tinfo(&cur, (ea_t)ea) || cur.empty())
        return TYPE_OK;
      return set_tinfo((ea_t)ea, nullptr) ? TYPE_OK : TYPE_ERR_APPLY;
    });
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult apply_type_recipe(uint64_t ea, rust::Slice<const uint8_t> recipe, int32_t flags) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(TYPE_ERR_APPLY, true, [&]() -> int {
      tinfo_t t;
      int rc = build_recipe(recipe.data(), recipe.size(), t);
      if (rc != TYPE_OK)
        return rc;
      if (!apply_tinfo((ea_t)ea, t, (uint32)flags | TINFO_DEFINITE))
        return TYPE_ERR_APPLY;
      return TYPE_OK;
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult define_type(rust::Str input) {
  try {
    TypeWriteResult out{};
    std::string inputs(input.data(), input.size());
    out.code = guarded<int>(1, true, [&]() -> int {
      return parse_decls(get_idati(), inputs.c_str(), msg, HTI_DCL);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult delete_type(rust::Str type_name) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      // NTF_TYPE selects the type namespace; without it del_named_type looks up a symbol name
      // instead and reports the type as not found.
      bool deleted = del_named_type(get_idati(), tn.c_str(), NTF_TYPE);
      return deleted ? TYPE_OK : (int)TERR_SAVE_ERROR;
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult rename_type(rust::Str type_name, rust::Str new_name) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string nn(new_name.data(), new_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      return (int)tif.rename_type(nn.c_str());
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult forward_declare_type(rust::Str type_name, uint32_t decl_type) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      return (int)tif.create_forward_decl(get_idati(), (type_t)decl_type, tn.c_str());
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult func_set_rettype(uint64_t ea, rust::Slice<const uint8_t> recipe) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return SIG_NO_PROTOTYPE;
      tinfo_t rt;
      if (build_recipe(recipe.data(), recipe.size(), rt) != TYPE_OK)
        return SIG_BUILD;
      ftd.rettype = rt;
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

SigWriteResult func_set_argtype(uint64_t ea, size_t idx, rust::Slice<const uint8_t> recipe) {
  try {
    SigWriteResult out{};
    size_t arity = 0;
    out.code = guarded<int>(SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return SIG_NO_PROTOTYPE;
      arity = ftd.size();
      if (idx >= ftd.size())
        return SIG_ARG_RANGE;
      tinfo_t at;
      if (build_recipe(recipe.data(), recipe.size(), at) != TYPE_OK)
        return SIG_BUILD;
      ftd[idx].type = at;
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    out.arity = arity;
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

SigWriteResult func_rename_arg(uint64_t ea, size_t idx, rust::Str name) {
  try {
    SigWriteResult out{};
    std::string names(name.data(), name.size());
    size_t arity = 0;
    out.code = guarded<int>(SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return SIG_NO_PROTOTYPE;
      arity = ftd.size();
      if (idx >= ftd.size())
        return SIG_ARG_RANGE;
      ftd[idx].name = names.c_str();
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    out.arity = arity;
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult func_set_cc(uint64_t ea, int32_t cc) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return SIG_NO_PROTOTYPE;
      ftd.set_cc((callcnv_t)cc);
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult func_prepend_this(uint64_t ea, rust::Slice<const uint8_t> recipe) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(SIG_APPLY, true, [&]() -> int {
      tinfo_t tif;
      func_type_data_t ftd;
      if (!read_func_details((ea_t)ea, tif, ftd))
        return SIG_NO_PROTOTYPE;
      tinfo_t pt;
      if (build_recipe(recipe.data(), recipe.size(), pt) != TYPE_OK)
        return SIG_BUILD;
      funcarg_t self_arg;
      self_arg.type = pt;
      self_arg.name = "this";
      ftd.insert(ftd.begin(), self_arg);
      return rebuild_and_apply((ea_t)ea, ftd);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult udt_add_member(rust::Str type_name, rust::Str member_name,
                               rust::Slice<const uint8_t> recipe, uint64_t member_bit) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    // A cxx rust::Str is never null, so an empty member name is the by-bit/anonymous selector.
    const char *mnp = member_name.empty() ? nullptr : mn.c_str();
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      tinfo_t mt;
      if (build_recipe(recipe.data(), recipe.size(), mt) != TYPE_OK)
        return TEDIT_BUILD;
      // Append means "past the last member": offset 0 for a union (all members share it), the
      // current byte size in bits for a struct.
      uint64_t offset = member_bit;
      if (offset == MEMBER_APPEND) {
        asize_t sz = tif.is_union() ? 0 : tif.get_size();
        offset = (sz == BADSIZE ? 0 : (uint64_t)sz) * 8;
      }
      uint16 width;
      if (bitfield_width_bits(mt, width)) {
        udm_t udm;
        udm.name = mnp != nullptr ? mnp : "";
        udm.type = mt;
        udm.offset = offset;
        udm.size = width;
        return (int)tif.add_udm(udm);
      }
      return (int)tif.add_udm(mnp, mt, offset);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult udt_set_member_type(rust::Str type_name, rust::Str member_name, uint64_t member_bit,
                                    rust::Slice<const uint8_t> recipe, uint32_t etf_flags) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    const char *mnp = member_name.empty() ? nullptr : mn.c_str();
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      int idx = resolve_member(tif, mnp, member_bit);
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      tinfo_t mt;
      if (build_recipe(recipe.data(), recipe.size(), mt) != TYPE_OK)
        return TEDIT_BUILD;
      return (int)tif.set_udm_type((size_t)idx, mt, etf_flags);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult udt_rename_member(rust::Str type_name, rust::Str member_name, uint64_t member_bit,
                                  rust::Str new_name) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    std::string nn(new_name.data(), new_name.size());
    const char *mnp = member_name.empty() ? nullptr : mn.c_str();
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      int idx = resolve_member(tif, mnp, member_bit);
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      return (int)tif.rename_udm((size_t)idx, nn.c_str());
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult udt_set_member_comment(rust::Str type_name, rust::Str member_name,
                                       uint64_t member_bit, rust::Str comment) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    std::string cn(comment.data(), comment.size());
    const char *mnp = member_name.empty() ? nullptr : mn.c_str();
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      int idx = resolve_member(tif, mnp, member_bit);
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      return (int)tif.set_udm_cmt((size_t)idx, cn.c_str());
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

// vtype is a value_repr_t FRB_* value-type nibble (FRB_NUMB/NUMO/NUMH/NUMD/CHAR); idakit maps its
// own NumberFormat enum onto it and never forwards an info-carrying nibble (FRB_ENUM, FRB_OFFSET,
// ...) here.
TypeWriteResult udt_set_member_repr(rust::Str type_name, rust::Str member_name, uint64_t member_bit,
                                    uint32_t vtype, bool is_signed, bool leading_zeros) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    const char *mnp = member_name.empty() ? nullptr : mn.c_str();
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      int idx = resolve_member(tif, mnp, member_bit);
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      value_repr_t repr;
      repr.set_vtype(vtype);
      repr.set_signed(is_signed);
      repr.set_lzeroes(leading_zeros);
      return (int)tif.set_udm_repr((size_t)idx, repr);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult udt_del_member(rust::Str type_name, rust::Str member_name, uint64_t member_bit) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    const char *mnp = member_name.empty() ? nullptr : mn.c_str();
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      int idx = resolve_member(tif, mnp, member_bit);
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      return (int)tif.del_udm((size_t)idx);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult enum_add_member(rust::Str type_name, rust::Str member_name, uint64_t value,
                                uint64_t bmask, uint32_t etf_flags) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      return (int)tif.add_edm(mn.c_str(), value, (bmask64_t)bmask, etf_flags);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult enum_set_bitmask(rust::Str type_name, bool on) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      return (int)tif.set_enum_is_bitmask(on ? tinfo_t::ENUMBM_ON : tinfo_t::ENUMBM_OFF);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

// vtype is a value_repr_t FRB_* value-type nibble, same convention as udt_set_member_repr.
TypeWriteResult enum_set_repr(rust::Str type_name, uint32_t vtype, bool is_signed,
                              bool leading_zeros) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      value_repr_t repr;
      repr.set_vtype(vtype);
      repr.set_signed(is_signed);
      repr.set_lzeroes(leading_zeros);
      return (int)tif.set_enum_repr(repr);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult enum_set_width(rust::Str type_name, int32_t nbytes) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      return (int)tif.set_enum_width(nbytes);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult enum_set_member_value(rust::Str type_name, rust::Str member_name, uint64_t value) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      ssize_t idx = resolve_edm(tif, mn.c_str());
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      return (int)tif.edit_edm((size_t)idx, value);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult enum_rename_member(rust::Str type_name, rust::Str member_name, rust::Str new_name,
                                   uint32_t etf_flags) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    std::string nn(new_name.data(), new_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      ssize_t idx = resolve_edm(tif, mn.c_str());
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      return (int)tif.rename_edm((size_t)idx, nn.c_str(), etf_flags);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult enum_del_member(rust::Str type_name, rust::Str member_name) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string mn(member_name.data(), member_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      ssize_t idx = resolve_edm(tif, mn.c_str());
      if (idx < 0)
        return TEDIT_NO_MEMBER;
      return (int)tif.del_edm((size_t)idx);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult enum_del_member_by_value(rust::Str type_name, uint64_t value) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    out.code = guarded<int>((int)TERR_SAVE_ERROR, true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      return (int)tif.del_edm_by_value(value, 0, DEFMASK64, 0);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

// Granular tinfo_t construction: each builder mints a fresh heap tinfo_t owned by a UniquePtr, whose
// cxx deleter (~tinfo_t) frees it on drop. A build failure returns a null handle (an Err only for
// the parse-driven tinfo_decl). The transform builders copy the borrowed `inner`, never consuming
// it, so the caller's input handle stays live.

std::unique_ptr<::tinfo_t> tinfo_void() {
  try {
    auto t = std::make_unique<::tinfo_t>();
    if (!t->create_simple_type(BTF_VOID))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

std::unique_ptr<::tinfo_t> tinfo_bool() {
  try {
    auto t = std::make_unique<::tinfo_t>();
    if (!t->create_simple_type(BT_BOOL))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

std::unique_ptr<::tinfo_t> tinfo_int(uint32_t bytes, bool is_signed) {
  try {
    auto t = std::make_unique<::tinfo_t>();
    if (!build_int(*t, bytes, is_signed))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

std::unique_ptr<::tinfo_t> tinfo_float(uint32_t bytes) {
  try {
    auto t = std::make_unique<::tinfo_t>();
    if (!build_float(*t, bytes))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

std::unique_ptr<::tinfo_t> tinfo_named(rust::Str name) {
  try {
    std::string names(name.data(), name.size());
    auto t = std::make_unique<::tinfo_t>();
    if (!build_named(*t, names.c_str()))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

// The one builder with a parse step: throw the captured reason on failure so cxx maps it to a Rust
// Err (hence no abort shell, matching the decompile body in hexrays_custom.cc).
std::unique_ptr<::tinfo_t> tinfo_decl(rust::Str decl) {
  std::string decls(decl.data(), decl.size());
  auto t = std::make_unique<::tinfo_t>();
  bool ok = guarded<bool>(false, true, [&]() -> bool {
    qstring pname;
    return parse_decl(t.get(), &pname, get_idati(), decls.c_str(), PT_SEMICOLON);
  });
  if (!ok)
    throw std::runtime_error(std::string(g_output.c_str(), g_output.length()));
  return t;
}

std::unique_ptr<::tinfo_t> tinfo_ptr(const ::tinfo_t &inner) {
  try {
    auto t = std::make_unique<::tinfo_t>();
    if (!t->create_ptr(inner))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

std::unique_ptr<::tinfo_t> tinfo_array(const ::tinfo_t &inner, uint64_t nelems) {
  try {
    if (nelems > 0xffffffffULL)
      return nullptr;
    auto t = std::make_unique<::tinfo_t>();
    if (!t->create_array(inner, (uint32)nelems))
      return nullptr;
    return t;
  } catch (...) {
    std::abort();
  }
}

std::unique_ptr<::tinfo_t> tinfo_const(const ::tinfo_t &inner) {
  try {
    auto t = std::make_unique<::tinfo_t>(inner);
    t->set_const();
    return t;
  } catch (...) {
    std::abort();
  }
}

std::unique_ptr<::tinfo_t> tinfo_volatile(const ::tinfo_t &inner) {
  try {
    auto t = std::make_unique<::tinfo_t>(inner);
    t->set_volatile();
    return t;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult tinfo_apply(uint64_t ea, const ::tinfo_t &handle, int32_t flags) {
  try {
    TypeWriteResult out{};
    out.code = guarded<int>(TYPE_ERR_APPLY, true, [&]() -> int {
      if (!apply_tinfo((ea_t)ea, handle, (uint32)flags | TINFO_DEFINITE))
        return TYPE_ERR_APPLY;
      return TYPE_OK;
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

} // namespace idakit_gen
