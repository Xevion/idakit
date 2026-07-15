// Hand-written Custom bodies for the generated function domain (namespace gen). Scalar
// lookup accessors over get_func/getn_func, plus the name as a rust::String (Err on no name).
// func_qty is templated (gen_function_bodies.cc), not here.

#include <ida.hpp>
#include <pro.h>

#include <funcs.hpp>
#include <name.hpp>

#include <stdexcept>

#include "gen_function.h"

namespace gen {

uint64_t func_ea(size_t n) {
  func_t *func = getn_func(n);
  return func != nullptr ? static_cast<uint64_t>(func->start_ea) : static_cast<uint64_t>(BADADDR);
}

uint64_t func_start(uint64_t addr) {
  func_t *func = get_func(static_cast<ea_t>(addr));
  return func != nullptr ? static_cast<uint64_t>(func->start_ea) : static_cast<uint64_t>(BADADDR);
}

uint64_t func_end(uint64_t addr) {
  func_t *func = get_func(static_cast<ea_t>(addr));
  return func != nullptr ? static_cast<uint64_t>(func->end_ea) : static_cast<uint64_t>(BADADDR);
}

uint64_t func_flags(uint64_t addr) {
  func_t *func = get_func(static_cast<ea_t>(addr));
  return func != nullptr ? static_cast<uint64_t>(func->flags) : 0;
}

int32_t func_chunk_qty(uint64_t addr) {
  func_t *func = get_func(static_cast<ea_t>(addr));
  if (func == nullptr)
    return 0;
  int32_t n = 0;
  func_tail_iterator_t fti(func);
  for (bool ok = fti.main(); ok; ok = fti.next())
    n++;
  return n;
}

rust::String func_name(uint64_t addr) {
  qstring out;
  if (get_func_name(&out, static_cast<ea_t>(addr)) <= 0)
    throw std::runtime_error("no function name at address");
  return to_rust_string(out);
}

} // namespace gen
