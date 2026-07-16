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
  type_t mod;
  switch (bytes) {
  case 4:
    mod = BTMT_FLOAT;
    break;
  case 8:
    mod = BTMT_DOUBLE;
    break;
  default:
    return false;
  }
  return out.create_simple_type(BT_FLOAT | mod);
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
      v |= static_cast<uint64_t>(p[pos++]) << (8 * i);
    return v;
  }

  // A u32-length-prefixed byte string (a type name or a decl; neither carries an interior NUL).
  bool str(std::string &out) {
    uint64_t n = uint_le(4);
    if (!ok || pos + static_cast<size_t>(n) > len) {
      ok = false;
      return false;
    }
    out.assign(reinterpret_cast<const char *>(p + pos), static_cast<size_t>(n));
    pos += static_cast<size_t>(n);
    return true;
  }
};

} // namespace

int build_recipe(const uint8_t *buf, size_t len, tinfo_t &out) {
  recipe_reader reader{buf, len};
  std::vector<tinfo_t> stack;
  while (reader.has_more()) {
    uint8_t op = reader.u8();
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
      uint8_t bytes = reader.u8();
      uint8_t is_signed = reader.u8();
      tinfo_t t;
      if (!reader.ok || !build_int(t, bytes, is_signed != 0))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case RECIPE_FLOAT: {
      uint8_t bytes = reader.u8();
      tinfo_t t;
      if (!reader.ok || !build_float(t, bytes))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case RECIPE_NAMED: {
      std::string name;
      if (!reader.str(name))
        return TYPE_ERR_INPUT;
      tinfo_t t;
      if (!build_named(t, name.c_str()))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case RECIPE_DECL: {
      std::string decl;
      if (!reader.str(decl))
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
      // create_array's count param is a uint32, so a wider recipe value can't fit it.
      constexpr uint64_t MAX_ARRAY_ELEMS = 0xffffffffULL;
      uint64_t nelems = reader.uint_le(8); // element count is an 8-byte field
      if (!reader.ok || nelems > MAX_ARRAY_ELEMS || stack.empty())
        return TYPE_ERR_INPUT;
      tinfo_t inner = stack.back();
      stack.pop_back();
      tinfo_t t;
      if (!t.create_array(inner, static_cast<uint32>(nelems)))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case RECIPE_CONST: {
      if (stack.empty())
        return TYPE_ERR_INPUT;
      stack.back().set_const(); // mutates top-of-stack in place, no pop/push needed
      break;
    }
    case RECIPE_VOLATILE: {
      if (stack.empty())
        return TYPE_ERR_INPUT;
      stack.back().set_volatile(); // same in-place mutation as RECIPE_CONST
      break;
    }
    case RECIPE_FUNCTION: {
      uint64_t nparams = reader.uint_le(4); // param count is a 4-byte field
      uint8_t varargs = reader.u8();
      uint64_t cc = reader.uint_le(2); // calling-convention code is a 2-byte field
      // Each param entry costs at least its own 4-byte length prefix, so reject a count the rest
      // of the buffer cannot hold before allocating on it.
      if (!reader.ok || nparams > (reader.len - reader.pos) / 4)
        return TYPE_ERR_INPUT;
      std::vector<std::string> names(static_cast<size_t>(nparams));
      for (uint64_t i = 0; i < nparams && reader.ok; i++)
        reader.str(names[static_cast<size_t>(i)]);
      // The return type sits just below the params on the stack (return pushed first).
      if (!reader.ok || stack.size() < static_cast<size_t>(nparams) + 1)
        return TYPE_ERR_INPUT;
      func_type_data_t ftd;
      size_t base = stack.size() - static_cast<size_t>(nparams);
      ftd.rettype = stack[base - 1];
      for (size_t i = 0; i < static_cast<size_t>(nparams); i++) {
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
        ftd.set_cc(static_cast<callcnv_t>(cc));
      tinfo_t t;
      if (!t.create_func(ftd))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    case RECIPE_BITFIELD: {
      uint8_t nbytes = reader.u8();
      uint8_t width = reader.u8();
      uint8_t is_signed = reader.u8();
      tinfo_t t;
      if (!reader.ok || !build_bitfield(t, nbytes, width, is_signed == 0))
        return TYPE_ERR_INPUT;
      stack.push_back(t);
      break;
    }
    default:
      return TYPE_ERR_INPUT;
    }
  }
  if (!reader.ok || stack.size() != 1)
    return TYPE_ERR_INPUT;
  out = stack[0];
  return TYPE_OK;
}

bool load_named_type(const char *type_name, tinfo_t &tif) {
  return tif.get_named_type(get_idati(), type_name) && !tif.empty();
}

} // namespace gen
