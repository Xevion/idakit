// Hand-written Custom bodies for the generated netnode domain (namespace idakit_gen): the irregular
// lifecycle and node-value functions the netnode matrix does not generate. A netnode is a value type
// over a single nodeidx_t id, so each body reconstructs `netnode n(node)` and drives its inline
// methods. rust::Str keys are NOT NUL-terminated, so they pass through std::string before reaching a
// `const char *` parameter. The combinatorial array-family bodies live in the generated
// gen_netnode_bodies.cc; the to_rust_string / to_rust_bytes helpers both call are inline in
// gen_netnode.h.

#include <pro.h>
#include <ida.hpp>

#include <netnode.hpp>

#include <stdexcept>
#include <string>

#include "gen_netnode.h"

namespace idakit_gen {

// Lifecycle.

uint64_t netnode_by_name(rust::Str name, bool create) {
  std::string s(name);
  netnode n(s.c_str(), s.size(), create);
  return (uint64_t)(nodeidx_t)n;
}

bool netnode_exists(uint64_t node) {
  netnode n((nodeidx_t)node);
  return exist(n);
}

bool netnode_exists_name(rust::Str name) {
  std::string s(name);
  return netnode::exist(s.c_str());
}

void netnode_kill(uint64_t node) {
  netnode n((nodeidx_t)node);
  n.kill();
}

rust::String netnode_get_name(uint64_t node) {
  netnode n((nodeidx_t)node);
  qstring out;
  if (n.get_name(&out) < 0)
    throw std::runtime_error("netnode is unnamed");
  return to_rust_string(out);
}

bool netnode_rename(uint64_t node, rust::Str name) {
  std::string s(name);
  netnode n((nodeidx_t)node);
  return n.rename(s.c_str(), s.size());
}

uint64_t netnode_first() {
  netnode n;
  return n.start() ? (uint64_t)(nodeidx_t)n : (uint64_t)BADNODE;
}

uint64_t netnode_last() {
  netnode n;
  return n.end() ? (uint64_t)(nodeidx_t)n : (uint64_t)BADNODE;
}

uint64_t netnode_next(uint64_t cur) {
  netnode n((nodeidx_t)cur);
  return n.next() ? (uint64_t)(nodeidx_t)n : (uint64_t)BADNODE;
}

uint64_t netnode_prev(uint64_t cur) {
  netnode n((nodeidx_t)cur);
  return n.prev() ? (uint64_t)(nodeidx_t)n : (uint64_t)BADNODE;
}

size_t netnode_copyto(uint64_t node, uint64_t count, uint64_t target, bool move_) {
  return ::netnode_copy((nodeidx_t)node, (nodeidx_t)count, (nodeidx_t)target, move_);
}

// Node value (vtag).

rust::Vec<uint8_t> netnode_value(uint64_t node) {
  netnode n((nodeidx_t)node);
  uint8_t buf[MAXSPECSIZE];
  ssize_t r = n.valobj(buf, sizeof(buf));
  if (r < 0)
    throw std::runtime_error("netnode has no value");
  return to_rust_bytes(buf, (size_t)r);
}

rust::String netnode_value_str(uint64_t node) {
  netnode n((nodeidx_t)node);
  qstring out;
  if (n.valstr(&out) < 0)
    throw std::runtime_error("netnode has no value");
  return to_rust_string(out);
}

bool netnode_set_value(uint64_t node, rust::Slice<const uint8_t> value) {
  netnode n((nodeidx_t)node);
  return n.set(value.data(), value.size());
}

bool netnode_del_value(uint64_t node) {
  netnode n((nodeidx_t)node);
  return n.delvalue();
}

} // namespace idakit_gen
