// idakit facade: byte reads, binary-pattern search, byte patching, and the structured
// frame-type walk.

#include <pro.h>

#include <ida.hpp>

#include <bytes.hpp>
#include <frame.hpp> // get_func_frame, get_frame_size, soff_to_fpoff
#include <funcs.hpp>
#include <typeinf.hpp> // tinfo_t, udt_type_data_t, udm_t

#include "idakit_facade.h"
#include "type_walk.hpp"

extern "C" int64_t idakit_get_bytes(idakit_ea_t ea, void *buf, size_t size) {
  return (int64_t)get_bytes(buf, (ssize_t)size, (ea_t)ea, GMB_READALL);
}

extern "C" void *idakit_binpat_compile(idakit_ea_t ea, const char *pattern, int radix, char *errbuf,
                                       size_t errcap) {
  try {
    compiled_binpat_vec_t *out = new compiled_binpat_vec_t;
    qstring err;
    if (!parse_binpat_str(out, (ea_t)ea, pattern, radix, PBSENC_DEF1BPU, &err)) {
      if (errcap > 0)
        qstrncpy(errbuf, err.c_str(), errcap);
      delete out;
      return nullptr;
    }
    return out;
  } catch (...) {
    std::abort();
  }
}

extern "C" void *idakit_binpat_from_bytes(const uint8_t *bytes, const uint8_t *mask, size_t len) {
  try {
    compiled_binpat_vec_t *v = new compiled_binpat_vec_t;
    compiled_binpat_t &b = v->push_back();
    b.bytes.append(bytes, len);
    if (mask != nullptr)
      b.mask.append(mask, len);
    return v;
  } catch (...) {
    std::abort();
  }
}

extern "C" void idakit_binpat_free(void *pat) {
  delete reinterpret_cast<compiled_binpat_vec_t *>(pat);
}

// Fills *total with the compiled pattern's byte length and *anchors with the count of
// concrete (non-wildcard) bytes -- mask[i] != 0, or every byte when the mask is empty.
// IDA's parser silently drops tokens it can't read, so a typo'd pattern lands here with
// anchors == 0: nothing to match on.
extern "C" void idakit_binpat_stats(const void *pat, size_t *total, size_t *anchors) {
  const compiled_binpat_vec_t *v = reinterpret_cast<const compiled_binpat_vec_t *>(pat);
  size_t t = 0, a = 0;
  if (!v->empty()) {
    const compiled_binpat_t &b = v->front();
    t = b.bytes.size();
    if (b.mask.empty()) {
      a = t;
    } else {
      for (size_t i = 0; i < b.mask.size(); i++)
        if (b.mask[i] != 0)
          a++;
    }
  }
  *total = t;
  *anchors = a;
}

extern "C" idakit_ea_t idakit_bin_search(idakit_ea_t start, idakit_ea_t end, const void *pat,
                                         int flags) {
  const compiled_binpat_vec_t *data = reinterpret_cast<const compiled_binpat_vec_t *>(pat);
  // NOBREAK/NOSHOW are mandatory headless: no Ctrl-Break polling, no UI progress.
  ea_t hit =
      bin_search((ea_t)start, (ea_t)end, *data, flags | BIN_SEARCH_NOBREAK | BIN_SEARCH_NOSHOW);
  return (idakit_ea_t)hit;
}

extern "C" int idakit_patch_bytes(idakit_ea_t ea, const void *buf, size_t size) {
  // Reject the whole write if any target byte is outside the address space, so a bad address
  // fails cleanly instead of silently patching a truncated prefix.
  for (size_t i = 0; i < size; i++) {
    if (!is_mapped((ea_t)ea + i))
      return 0;
  }
  patch_bytes((ea_t)ea, buf, size);
  return 1;
}

// A function frame is a UDT tinfo (get_func_frame); idakit_frame_type_walk drives the shared type
// walker over its members. These flags mark the two members IDA reserves in every frame.
namespace {

// bit0 = return address, bit1 = saved registers; both clear = an ordinary variable/argument.
constexpr uint32_t FRAME_VAR_RETADDR = 1;
constexpr uint32_t FRAME_VAR_SAVREGS = 2;

} // namespace

// One shared type walk over the frame UDT, so a named type used by two variables is emitted once,
// reporting each variable with its resolved type handle instead of a printed string.
extern "C" int idakit_frame_type_walk(idakit_ea_t ea, const idakit_frame_vtbl_t *v, void *ctx,
                                      uint64_t *frame_size) {
  if (v == nullptr || frame_size == nullptr)
    return 1;
  try {
    func_t *pfn = get_func((ea_t)ea);
    if (pfn == nullptr)
      return 1;
    tinfo_t tif;
    udt_type_data_t udt;
    if (!get_func_frame(&tif, pfn) || !tif.get_udt_details(&udt))
      return 1;
    *frame_size = (uint64_t)get_frame_size(pfn);
    idakit_facade::type_walker_t tw;
    tw.v = &v->types;
    tw.ctx = ctx;
    for (const udm_t &m : udt) {
      uint32_t flags =
          (m.is_retaddr() ? FRAME_VAR_RETADDR : 0) | (m.is_savregs() ? FRAME_VAR_SAVREGS : 0);
      // Only a real, typed variable carries a structured type; reserved slots and untyped
      // stack slots report IDAKIT_NONE, so the table holds only types a variable references.
      uint32_t ty = (flags == 0 && !m.type.empty()) ? tw.ty(m.type) : IDAKIT_NONE;
      // udm offset/size are in bits; soff_to_fpoff wants the byte struct offset.
      int64_t offset = (int64_t)soff_to_fpoff(pfn, (uval_t)(m.offset / 8));
      uint64_t size = m.size / 8;
      v->f_var(ctx, m.name.c_str(), m.name.length(), offset, size, flags, ty);
    }
    return 0;
  } catch (...) {
    std::abort();
  }
}
