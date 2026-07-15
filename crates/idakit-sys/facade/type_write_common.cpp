// Shared internal helpers for the type-write domain's split TUs (namespace gen). See
// type_write_common.h.

#include <cstdint>
#include <string>
#include <vector>

#include <pro.h>

#include <ida.hpp>

#include <typeinf.hpp> // tinfo_t, parse_decl, func_type_data_t, funcarg_t

#include "gen_type_build.h"
#include "internal.h" // g_output (msg-channel capture)
#include "type_write_common.h"

using namespace facade;

namespace gen {

rust::String captured_reason() { return to_rust_string(g_output.c_str(), g_output.length()); }

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

bool build_named(tinfo_t &out, const char *name) {
  return out.get_named_type(get_idati(), name, BTF_TYPEDEF, false);
}

namespace {

// Build a bitfield leaf (create_bitfield): nbytes is the container width in bytes, width the
// field's bit width. False if the kernel rejects the combination (e.g. width exceeding nbytes*8).
// Only ever called from build_recipe below, so this stays file-local.
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

} // namespace

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

bool load_named_type(const char *type_name, tinfo_t &tif) {
  return tif.get_named_type(get_idati(), type_name) && !tif.empty();
}

} // namespace gen
