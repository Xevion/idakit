// Hand-written Custom bodies for the generated netnode domain (namespace gen): the irregular
// lifecycle and node-value functions the netnode array-family generator doesn't cover. A netnode
// is a value type over a single nodeidx_t id, so each body reconstructs it from the raw id and
// drives its inline methods. rust::Str keys are not NUL-terminated, so they route through
// std::string before reaching a `const char *` parameter. The combinatorial array-family bodies
// live in the generated gen_netnode_bodies.cc; to_rust_string/to_rust_bytes are shared helpers in
// gen_helpers.h, pulled in transitively through gen_netnode.h.

#include <ida.hpp>
#include <pro.h>

#include <netnode.hpp>

#include <stdexcept>
#include <string>

#include "gen_netnode.h"

namespace gen {

// Lifecycle.

// Resolves name to a netnode id, creating it first when create is set; otherwise the returned id
// is BADNODE if no netnode with that name exists yet. netnode converts to nodeidx_t via its own
// operator, then widens to the FFI's uint64_t.
uint64_t netnode_by_name(rust::Str name, bool create) {
  std::string s(name);
  netnode node(s.c_str(), s.size(), create);
  return static_cast<uint64_t>(static_cast<nodeidx_t>(node));
}

// Reports whether any data is attached to the netnode with this raw id.
bool netnode_exists(uint64_t node) {
  netnode handle(static_cast<nodeidx_t>(node));
  return exist(handle);
}

// Reports whether a netnode with this name has been created, without resolving its id first.
bool netnode_exists_name(rust::Str name) {
  std::string s(name);
  return netnode::exist(s.c_str());
}

// Deletes the netnode and all data attached to it.
void netnode_kill(uint64_t node) {
  netnode handle(static_cast<nodeidx_t>(node));
  handle.kill();
}

// The netnode's name; throws if the netnode is unnamed.
rust::String netnode_get_name(uint64_t node) {
  netnode handle(static_cast<nodeidx_t>(node));
  qstring out;
  if (handle.get_name(&out) < 0)
    throw std::runtime_error("netnode is unnamed");
  return to_rust_string(out);
}

// Renames the netnode; returns whether the new name was free to take.
bool netnode_rename(uint64_t node, rust::Str name) {
  std::string s(name);
  netnode handle(static_cast<nodeidx_t>(node));
  return handle.rename(s.c_str(), s.size());
}

// The lowest netnode id in the database, or BADNODE if there are none.
uint64_t netnode_first() {
  netnode node;
  return node.start() ? static_cast<uint64_t>(static_cast<nodeidx_t>(node))
                      : static_cast<uint64_t>(BADNODE);
}

// The highest netnode id in the database, or BADNODE if there are none.
uint64_t netnode_last() {
  netnode node;
  return node.end() ? static_cast<uint64_t>(static_cast<nodeidx_t>(node))
                    : static_cast<uint64_t>(BADNODE);
}

// The next netnode id after cur, or BADNODE if cur is the last one.
uint64_t netnode_next(uint64_t cur) {
  netnode node(static_cast<nodeidx_t>(cur));
  return node.next() ? static_cast<uint64_t>(static_cast<nodeidx_t>(node))
                     : static_cast<uint64_t>(BADNODE);
}

// The netnode id before cur, or BADNODE if cur is the first one.
uint64_t netnode_prev(uint64_t cur) {
  netnode node(static_cast<nodeidx_t>(cur));
  return node.prev() ? static_cast<uint64_t>(static_cast<nodeidx_t>(node))
                     : static_cast<uint64_t>(BADNODE);
}

// Copies (or, if move_, moves) count consecutive netnode ids starting at node onto target;
// returns the number of keys actually copied/moved, or BADNODE on failure.
size_t netnode_copyto(uint64_t node, uint64_t count, uint64_t target, bool move_) {
  return ::netnode_copy(static_cast<nodeidx_t>(node), static_cast<nodeidx_t>(count),
                        static_cast<nodeidx_t>(target), move_);
}

// Node value (vtag).

// The netnode's raw value blob, copied into an owned Vec<u8>; throws if it has none.
rust::Vec<uint8_t> netnode_value(uint64_t node) {
  netnode handle(static_cast<nodeidx_t>(node));
  uint8_t buf[MAXSPECSIZE];
  ssize_t r = handle.valobj(buf, sizeof(buf));
  if (r < 0)
    throw std::runtime_error("netnode has no value");
  return to_rust_bytes(buf, static_cast<size_t>(r));
}

// The netnode's value read back as a string; throws if it has none.
rust::String netnode_value_str(uint64_t node) {
  netnode handle(static_cast<nodeidx_t>(node));
  qstring out;
  if (handle.valstr(&out) < 0)
    throw std::runtime_error("netnode has no value");
  return to_rust_string(out);
}

// Sets the netnode's value blob; returns whether the write succeeded.
bool netnode_set_value(uint64_t node, rust::Slice<const uint8_t> value) {
  netnode handle(static_cast<nodeidx_t>(node));
  return handle.set(value.data(), value.size());
}

// Deletes the netnode's value; returns whether there was one to delete.
bool netnode_del_value(uint64_t node) {
  netnode handle(static_cast<nodeidx_t>(node));
  return handle.delvalue();
}

} // namespace gen
