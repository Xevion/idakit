// Hand-written Custom bodies for the generated netnode domain (namespace gen): the irregular
// lifecycle and node-value functions the netnode matrix does not generate. A netnode is a value
// type over a single nodeidx_t id, so each body reconstructs the netnode object from its raw id
// and drives its inline methods. rust::Str keys are NOT NUL-terminated, so they pass through
// std::string before reaching a `const char *` parameter. The combinatorial array-family bodies
// live in the generated gen_netnode_bodies.cc; the to_rust_string / to_rust_bytes helpers both
// call are inline in the shared gen_helpers.h (pulled in by gen_netnode.h).

#include <ida.hpp>
#include <pro.h>

#include <netnode.hpp>

#include <stdexcept>
#include <string>

#include "gen_netnode.h"

namespace gen {

// Lifecycle.

uint64_t netnode_by_name(rust::Str name, bool create) {
  std::string s(name);
  netnode node(s.c_str(), s.size(), create);
  return static_cast<uint64_t>(static_cast<nodeidx_t>(node));
}

bool netnode_exists(uint64_t node) {
  netnode handle(static_cast<nodeidx_t>(node));
  return exist(handle);
}

bool netnode_exists_name(rust::Str name) {
  std::string s(name);
  return netnode::exist(s.c_str());
}

void netnode_kill(uint64_t node) {
  netnode handle(static_cast<nodeidx_t>(node));
  handle.kill();
}

rust::String netnode_get_name(uint64_t node) {
  netnode handle(static_cast<nodeidx_t>(node));
  qstring out;
  if (handle.get_name(&out) < 0)
    throw std::runtime_error("netnode is unnamed");
  return to_rust_string(out);
}

bool netnode_rename(uint64_t node, rust::Str name) {
  std::string s(name);
  netnode handle(static_cast<nodeidx_t>(node));
  return handle.rename(s.c_str(), s.size());
}

uint64_t netnode_first() {
  netnode node;
  return node.start() ? static_cast<uint64_t>(static_cast<nodeidx_t>(node))
                      : static_cast<uint64_t>(BADNODE);
}

uint64_t netnode_last() {
  netnode node;
  return node.end() ? static_cast<uint64_t>(static_cast<nodeidx_t>(node))
                    : static_cast<uint64_t>(BADNODE);
}

uint64_t netnode_next(uint64_t cur) {
  netnode node(static_cast<nodeidx_t>(cur));
  return node.next() ? static_cast<uint64_t>(static_cast<nodeidx_t>(node))
                     : static_cast<uint64_t>(BADNODE);
}

uint64_t netnode_prev(uint64_t cur) {
  netnode node(static_cast<nodeidx_t>(cur));
  return node.prev() ? static_cast<uint64_t>(static_cast<nodeidx_t>(node))
                     : static_cast<uint64_t>(BADNODE);
}

size_t netnode_copyto(uint64_t node, uint64_t count, uint64_t target, bool move_) {
  return ::netnode_copy(static_cast<nodeidx_t>(node), static_cast<nodeidx_t>(count),
                        static_cast<nodeidx_t>(target), move_);
}

// Node value (vtag).

rust::Vec<uint8_t> netnode_value(uint64_t node) {
  netnode handle(static_cast<nodeidx_t>(node));
  uint8_t buf[MAXSPECSIZE];
  ssize_t r = handle.valobj(buf, sizeof(buf));
  if (r < 0)
    throw std::runtime_error("netnode has no value");
  return to_rust_bytes(buf, static_cast<size_t>(r));
}

rust::String netnode_value_str(uint64_t node) {
  netnode handle(static_cast<nodeidx_t>(node));
  qstring out;
  if (handle.valstr(&out) < 0)
    throw std::runtime_error("netnode has no value");
  return to_rust_string(out);
}

bool netnode_set_value(uint64_t node, rust::Slice<const uint8_t> value) {
  netnode handle(static_cast<nodeidx_t>(node));
  return handle.set(value.data(), value.size());
}

bool netnode_del_value(uint64_t node) {
  netnode handle(static_cast<nodeidx_t>(node));
  return handle.delvalue();
}

} // namespace gen
