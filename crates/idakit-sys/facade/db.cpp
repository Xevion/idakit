// idakit facade: byte reads, binary-pattern search, and byte patching.

#include <pro.h>

#include <ida.hpp>

#include <bytes.hpp>

#include "idakit_facade.h"

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
// concrete (non-wildcard) bytes: mask[i] != 0, or every byte when the mask is empty.
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
