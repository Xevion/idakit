// Hand-written Custom bodies for the generated function domain (namespace idakit_gen). Scalar
// lookup accessors over get_func/getn_func, plus the name as a rust::String (Err on no name).
// func_qty is templated (gen_function_bodies.cc), not here.

#include <ida.hpp>
#include <pro.h>

#include <funcs.hpp>
#include <name.hpp>

#include <stdexcept>

#include "gen_function.h"

namespace idakit_gen {

uint64_t func_ea(size_t n) {
  func_t *f = getn_func(n);
  return f != nullptr ? (uint64_t)f->start_ea : (uint64_t)BADADDR;
}

uint64_t func_start(uint64_t ea) {
  func_t *f = get_func((ea_t)ea);
  return f != nullptr ? (uint64_t)f->start_ea : (uint64_t)BADADDR;
}

uint64_t func_end(uint64_t ea) {
  func_t *f = get_func((ea_t)ea);
  return f != nullptr ? (uint64_t)f->end_ea : (uint64_t)BADADDR;
}

uint64_t func_flags(uint64_t ea) {
  func_t *f = get_func((ea_t)ea);
  return f != nullptr ? (uint64_t)f->flags : 0;
}

int32_t func_chunk_qty(uint64_t ea) {
  func_t *pfn = get_func((ea_t)ea);
  if (pfn == nullptr)
    return 0;
  int32_t n = 0;
  func_tail_iterator_t fti(pfn);
  for (bool ok = fti.main(); ok; ok = fti.next())
    n++;
  return n;
}

rust::String func_name(uint64_t ea) {
  qstring out;
  if (get_func_name(&out, (ea_t)ea) <= 0)
    throw std::runtime_error("no function name at address");
  return to_rust_string(out);
}

} // namespace idakit_gen
