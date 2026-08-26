// Hand-written Custom bodies for the generated function domain (namespace gen): scalar lookup
// accessors keyed by address returning BADADDR (or 0) when there is no function, the name and
// comment as rust::String (throw, a Rust Err, when absent), and the function's bitness.
// func_qty and func_does_return are templated (gen_function_bodies.cc), not here.

#include <ida.hpp>
#include <pro.h>

#include <funcs.hpp>
#include <name.hpp>

#include <stdexcept>

#include "gen_function.h"
// The generated bridge header defines FunctionEntryInfo (needed in full to construct it below);
// gen_function.h only forward-declares it.
#include "gen_bridge.h"

#include "compat.h"

namespace gen {

// Start address of the nth function in the functions list, or BADADDR when n is out of range.
uint64_t func_ea(size_t n) { return static_cast<uint64_t>(get_func_ea_by_num(n)); }

// Start address of the function containing addr, or BADADDR when there is none.
uint64_t func_start(uint64_t addr) {
  return static_cast<uint64_t>(get_func_start(static_cast<ea_t>(addr)));
}

// End address (exclusive) of the function containing addr, or BADADDR when there is none. Keyed on
// the entry chunk, so an address in a tail answers for the whole function.
uint64_t func_end(uint64_t addr) {
  fchunk_info_t entry;
  if (!get_fchunk_info(&entry, get_func_start(static_cast<ea_t>(addr))))
    return static_cast<uint64_t>(BADADDR);
  return static_cast<uint64_t>(entry.end_ea);
}

// The function's flags word at addr, or 0 when addr is not inside a function.
uint64_t func_flags(uint64_t addr) {
  fchunk_info_t entry;
  if (!get_fchunk_info(&entry, get_func_start(static_cast<ea_t>(addr))))
    return 0;
  return entry.get_flags();
}

// Number of chunks (main body plus tails) making up the function at addr, or 0 when there is none.
int32_t func_chunk_qty(uint64_t addr) {
  ea_t func_ea = get_func_start(static_cast<ea_t>(addr));
  if (func_ea == BADADDR)
    return 0;
  return static_cast<int32_t>(get_func_tail_qty(func_ea)) + 1;
}

// The function's name at addr; throws when the function is missing or unnamed.
rust::String func_name(uint64_t addr) {
  qstring out;
  if (get_func_name(&out, static_cast<ea_t>(addr)) <= 0)
    throw std::runtime_error("no function name at address");
  return to_rust_string(out);
}

// The function's comment at addr (repeatable or regular); throws when addr is not a function or
// that channel carries no comment.
rust::String func_cmt(uint64_t addr, bool repeatable) {
  ea_t ea = static_cast<ea_t>(addr);
  if (get_func_start(ea) == BADADDR)
    throw std::runtime_error("no function at address");
  qstring out;
  if (get_func_cmt_ea(&out, ea, repeatable) <= 0)
    throw std::runtime_error("no function comment");
  return to_rust_string(out);
}

// The function's addressing width in bits at addr: 16, 32, or 64, or 0 when addr is not a
// function. Returns the width (get_func_bits_ea), not the raw 0/1/2 bitness code, so the Rust
// side's width-based Bitness conversion applies uniformly across every bitness accessor.
int32_t func_bitness(uint64_t addr) {
  ea_t ea = static_cast<ea_t>(addr);
  return get_func_start(ea) != BADADDR ? static_cast<int32_t>(get_func_bits_ea(ea)) : 0;
}

// The entry chunk's scalars in one call, plus each string the GFI_* mask selects; throws when addr
// is not a function. An unselected string comes back empty rather than costing a build.
FunctionEntryInfo func_entry_info(uint64_t addr, int32_t fields) {
  func_entry_info_t entry;
  if (!get_func_entry_info(&entry, static_cast<ea_t>(addr), fields))
    throw std::runtime_error("no function at address");
  FunctionEntryInfo out;
  out.start = static_cast<uint64_t>(entry.start_ea);
  out.end = static_cast<uint64_t>(entry.end_ea);
  out.flags = entry.get_flags();
  out.frame_id = static_cast<uint64_t>(entry.get_frame_id());
  out.locals_size = static_cast<uint64_t>(entry.get_frsize());
  out.saved_regs_size = static_cast<uint32_t>(entry.get_frregs());
  out.purged_bytes = static_cast<uint64_t>(entry.get_argsize());
  out.frame_pointer_delta = static_cast<uint64_t>(entry.get_fpd());
  out.color = static_cast<uint32_t>(entry.get_color());
  out.name = rust::String::lossy(entry.get_name());
  out.cmt = rust::String::lossy(entry.get_cmt());
  out.cmt_rpt = rust::String::lossy(entry.get_cmt_rpt());
  return out;
}

} // namespace gen
