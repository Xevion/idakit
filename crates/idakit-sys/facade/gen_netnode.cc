// Hand-written Custom bodies for the generated netnode domain (namespace idakit_gen). IDA's
// persistent key/value + blob store. A netnode is a value type over a single nodeidx_t id, so every
// body reconstructs `netnode n(node)` and drives its inline methods; the node id is the only handle.
// Tags arrive as uint32_t and narrow to uchar. rust::Str keys are NOT NUL-terminated, so they pass
// through std::string before reaching a `const char *` parameter.

#include <pro.h>
#include <ida.hpp>

#include <netnode.hpp>

#include <stdexcept>
#include <string>
#include <vector>

#include "gen_netnode.h"

namespace idakit_gen {

namespace {
// Copy a filled qstring / byte buffer out as the owning Rust type in one crossing.
rust::String to_rust_string(const qstring &s) { return rust::String(s.c_str(), s.length()); }

rust::Vec<uint8_t> to_rust_bytes(const uint8_t *data, size_t n) {
  rust::Vec<uint8_t> out;
  out.reserve(n);
  for (size_t i = 0; i < n; i++)
    out.push_back(data[i]);
  return out;
}
} // namespace

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

// Alt values (sparse uint64 array, tag atag; unset reads as 0).

uint64_t netnode_altval(uint64_t node, uint64_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.altval((nodeidx_t)idx, (uchar)tag);
}

bool netnode_altset(uint64_t node, uint64_t idx, uint64_t value, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.altset((nodeidx_t)idx, (nodeidx_t)value, (uchar)tag);
}

bool netnode_altdel(uint64_t node, uint64_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.altdel((nodeidx_t)idx, (uchar)tag);
}

uint64_t netnode_altfirst(uint64_t node, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.altfirst((uchar)tag);
}

uint64_t netnode_altnext(uint64_t node, uint64_t cur, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.altnext((nodeidx_t)cur, (uchar)tag);
}

uint64_t netnode_altlast(uint64_t node, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.altlast((uchar)tag);
}

uint64_t netnode_altprev(uint64_t node, uint64_t cur, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.altprev((nodeidx_t)cur, (uchar)tag);
}

// Sup values (arbitrary byte objects, tag stag).

rust::Vec<uint8_t> netnode_supval(uint64_t node, uint64_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  uint8_t buf[MAXSPECSIZE];
  ssize_t r = n.supval((nodeidx_t)idx, buf, sizeof(buf), (uchar)tag);
  if (r < 0)
    throw std::runtime_error("sup value is unset");
  return to_rust_bytes(buf, (size_t)r);
}

rust::String netnode_supstr(uint64_t node, uint64_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  qstring out;
  if (n.supstr(&out, (nodeidx_t)idx, (uchar)tag) < 0)
    throw std::runtime_error("sup value is unset");
  return to_rust_string(out);
}

bool netnode_supset(uint64_t node, uint64_t idx, rust::Slice<const uint8_t> value, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.supset((nodeidx_t)idx, value.data(), value.size(), (uchar)tag);
}

bool netnode_supdel(uint64_t node, uint64_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.supdel((nodeidx_t)idx, (uchar)tag);
}

uint64_t netnode_supfirst(uint64_t node, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.supfirst((uchar)tag);
}

uint64_t netnode_supnext(uint64_t node, uint64_t cur, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.supnext((nodeidx_t)cur, (uchar)tag);
}

uint64_t netnode_suplast(uint64_t node, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.suplast((uchar)tag);
}

uint64_t netnode_supprev(uint64_t node, uint64_t cur, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.supprev((nodeidx_t)cur, (uchar)tag);
}

uint64_t netnode_lower_bound(uint64_t node, uint64_t cur, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.lower_bound((nodeidx_t)cur, (uchar)tag);
}

// Hash values (string-keyed, tag htag; iteration returns the key).

rust::Vec<uint8_t> netnode_hashval(uint64_t node, rust::Str key, uint32_t tag) {
  std::string k(key);
  netnode n((nodeidx_t)node);
  uint8_t buf[MAXSPECSIZE];
  ssize_t r = n.hashval(k.c_str(), buf, sizeof(buf), (uchar)tag);
  if (r < 0)
    throw std::runtime_error("hash key is unset");
  return to_rust_bytes(buf, (size_t)r);
}

rust::String netnode_hashstr(uint64_t node, rust::Str key, uint32_t tag) {
  std::string k(key);
  netnode n((nodeidx_t)node);
  qstring out;
  if (n.hashstr(&out, k.c_str(), (uchar)tag) < 0)
    throw std::runtime_error("hash key is unset");
  return to_rust_string(out);
}

uint64_t netnode_hashval_long(uint64_t node, rust::Str key, uint32_t tag) {
  std::string k(key);
  netnode n((nodeidx_t)node);
  return (uint64_t)n.hashval_long(k.c_str(), (uchar)tag);
}

bool netnode_hashset(uint64_t node, rust::Str key, rust::Slice<const uint8_t> value, uint32_t tag) {
  std::string k(key);
  netnode n((nodeidx_t)node);
  return n.hashset(k.c_str(), value.data(), value.size(), (uchar)tag);
}

bool netnode_hashset_long(uint64_t node, rust::Str key, uint64_t value, uint32_t tag) {
  std::string k(key);
  netnode n((nodeidx_t)node);
  return n.hashset(k.c_str(), (nodeidx_t)value, (uchar)tag);
}

bool netnode_hashdel(uint64_t node, rust::Str key, uint32_t tag) {
  std::string k(key);
  netnode n((nodeidx_t)node);
  return n.hashdel(k.c_str(), (uchar)tag);
}

rust::String netnode_hashfirst(uint64_t node, uint32_t tag) {
  netnode n((nodeidx_t)node);
  qstring out;
  if (n.hashfirst(&out, (uchar)tag) < 0)
    throw std::runtime_error("hash is empty");
  return to_rust_string(out);
}

rust::String netnode_hashnext(uint64_t node, rust::Str key, uint32_t tag) {
  std::string k(key);
  netnode n((nodeidx_t)node);
  qstring out;
  if (n.hashnext(&out, k.c_str(), (uchar)tag) < 0)
    throw std::runtime_error("no next hash key");
  return to_rust_string(out);
}

rust::String netnode_hashlast(uint64_t node, uint32_t tag) {
  netnode n((nodeidx_t)node);
  qstring out;
  if (n.hashlast(&out, (uchar)tag) < 0)
    throw std::runtime_error("hash is empty");
  return to_rust_string(out);
}

rust::String netnode_hashprev(uint64_t node, rust::Str key, uint32_t tag) {
  std::string k(key);
  netnode n((nodeidx_t)node);
  qstring out;
  if (n.hashprev(&out, k.c_str(), (uchar)tag) < 0)
    throw std::runtime_error("no previous hash key");
  return to_rust_string(out);
}

// Char values (8-bit, sharing sup storage; unset reads as 0).

uint32_t netnode_charval(uint64_t node, uint64_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint32_t)n.charval((nodeidx_t)idx, (uchar)tag);
}

bool netnode_charset(uint64_t node, uint64_t idx, uint32_t value, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.charset((nodeidx_t)idx, (uchar)value, (uchar)tag);
}

bool netnode_chardel(uint64_t node, uint64_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.chardel((nodeidx_t)idx, (uchar)tag);
}

// Blobs (unlimited size, chained sup slots, any tag).

size_t netnode_blobsize(uint64_t node, uint64_t start, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.blobsize((nodeidx_t)start, (uchar)tag);
}

rust::Vec<uint8_t> netnode_getblob(uint64_t node, uint64_t start, uint32_t tag) {
  netnode n((nodeidx_t)node);
  bytevec_t blob;
  ssize_t r = n.getblob(&blob, (nodeidx_t)start, (uchar)tag);
  if (r < 0)
    throw std::runtime_error("blob does not exist");
  return to_rust_bytes(blob.begin(), blob.size());
}

bool netnode_setblob(uint64_t node, rust::Slice<const uint8_t> value, uint64_t start, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.setblob(value.data(), value.size(), (nodeidx_t)start, (uchar)tag);
}

int32_t netnode_delblob(uint64_t node, uint64_t start, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (int32_t)n.delblob((nodeidx_t)start, (uchar)tag);
}

// Address-keyed conveniences (the class methods fold in NETMAP_IDX).

uint64_t netnode_altval_ea(uint64_t node, uint64_t ea, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.altval_ea((ea_t)ea, (uchar)tag);
}

bool netnode_altset_ea(uint64_t node, uint64_t ea, uint64_t value, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.altset_ea((ea_t)ea, (nodeidx_t)value, (uchar)tag);
}

bool netnode_altdel_ea(uint64_t node, uint64_t ea, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.altdel_ea((ea_t)ea, (uchar)tag);
}

rust::Vec<uint8_t> netnode_supval_ea(uint64_t node, uint64_t ea, uint32_t tag) {
  netnode n((nodeidx_t)node);
  uint8_t buf[MAXSPECSIZE];
  ssize_t r = n.supval_ea((ea_t)ea, buf, sizeof(buf), (uchar)tag);
  if (r < 0)
    throw std::runtime_error("sup value is unset");
  return to_rust_bytes(buf, (size_t)r);
}

rust::String netnode_supstr_ea(uint64_t node, uint64_t ea, uint32_t tag) {
  netnode n((nodeidx_t)node);
  qstring out;
  if (n.supstr_ea(&out, (ea_t)ea, (uchar)tag) < 0)
    throw std::runtime_error("sup value is unset");
  return to_rust_string(out);
}

bool netnode_supset_ea(uint64_t node, uint64_t ea, rust::Slice<const uint8_t> value, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.supset_ea((ea_t)ea, value.data(), value.size(), (uchar)tag);
}

bool netnode_supdel_ea(uint64_t node, uint64_t ea, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.supdel_ea((ea_t)ea, (uchar)tag);
}

uint32_t netnode_charval_ea(uint64_t node, uint64_t ea, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint32_t)n.charval_ea((ea_t)ea, (uchar)tag);
}

bool netnode_charset_ea(uint64_t node, uint64_t ea, uint32_t value, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.charset_ea((ea_t)ea, (uchar)value, (uchar)tag);
}

bool netnode_chardel_ea(uint64_t node, uint64_t ea, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.chardel_ea((ea_t)ea, (uchar)tag);
}

size_t netnode_blobsize_ea(uint64_t node, uint64_t ea, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.blobsize_ea((ea_t)ea, (uchar)tag);
}

rust::Vec<uint8_t> netnode_getblob_ea(uint64_t node, uint64_t ea, uint32_t tag) {
  netnode n((nodeidx_t)node);
  bytevec_t blob;
  ssize_t r = n.getblob_ea(&blob, (ea_t)ea, (uchar)tag);
  if (r < 0)
    throw std::runtime_error("blob does not exist");
  return to_rust_bytes(blob.begin(), blob.size());
}

bool netnode_setblob_ea(uint64_t node, rust::Slice<const uint8_t> value, uint64_t ea, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.setblob_ea(value.data(), value.size(), (ea_t)ea, (uchar)tag);
}

// 8-bit-indexed sub-arrays (a separate index space; indices narrow to uchar).

uint64_t netnode_altval_idx8(uint64_t node, uint32_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.altval_idx8((uchar)idx, (uchar)tag);
}

bool netnode_altset_idx8(uint64_t node, uint32_t idx, uint64_t value, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.altset_idx8((uchar)idx, (nodeidx_t)value, (uchar)tag);
}

bool netnode_altdel_idx8(uint64_t node, uint32_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.altdel_idx8((uchar)idx, (uchar)tag);
}

uint64_t netnode_altfirst_idx8(uint64_t node, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.altfirst_idx8((uchar)tag);
}

uint64_t netnode_altnext_idx8(uint64_t node, uint32_t cur, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.altnext_idx8((uchar)cur, (uchar)tag);
}

uint64_t netnode_altlast_idx8(uint64_t node, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.altlast_idx8((uchar)tag);
}

uint64_t netnode_altprev_idx8(uint64_t node, uint32_t cur, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.altprev_idx8((uchar)cur, (uchar)tag);
}

rust::Vec<uint8_t> netnode_supval_idx8(uint64_t node, uint32_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  uint8_t buf[MAXSPECSIZE];
  ssize_t r = n.supval_idx8((uchar)idx, buf, sizeof(buf), (uchar)tag);
  if (r < 0)
    throw std::runtime_error("sup value is unset");
  return to_rust_bytes(buf, (size_t)r);
}

rust::String netnode_supstr_idx8(uint64_t node, uint32_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  qstring out;
  if (n.supstr_idx8(&out, (uchar)idx, (uchar)tag) < 0)
    throw std::runtime_error("sup value is unset");
  return to_rust_string(out);
}

bool netnode_supset_idx8(uint64_t node, uint32_t idx, rust::Slice<const uint8_t> value, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.supset_idx8((uchar)idx, value.data(), value.size(), (uchar)tag);
}

bool netnode_supdel_idx8(uint64_t node, uint32_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.supdel_idx8((uchar)idx, (uchar)tag);
}

uint64_t netnode_supfirst_idx8(uint64_t node, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.supfirst_idx8((uchar)tag);
}

uint64_t netnode_supnext_idx8(uint64_t node, uint32_t cur, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.supnext_idx8((uchar)cur, (uchar)tag);
}

uint64_t netnode_suplast_idx8(uint64_t node, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.suplast_idx8((uchar)tag);
}

uint64_t netnode_supprev_idx8(uint64_t node, uint32_t cur, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.supprev_idx8((uchar)cur, (uchar)tag);
}

uint64_t netnode_lower_bound_idx8(uint64_t node, uint32_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint64_t)n.lower_bound_idx8((uchar)idx, (uchar)tag);
}

uint32_t netnode_charval_idx8(uint64_t node, uint32_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (uint32_t)n.charval_idx8((uchar)idx, (uchar)tag);
}

bool netnode_charset_idx8(uint64_t node, uint32_t idx, uint32_t value, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.charset_idx8((uchar)idx, (uchar)value, (uchar)tag);
}

bool netnode_chardel_idx8(uint64_t node, uint32_t idx, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.chardel_idx8((uchar)idx, (uchar)tag);
}

// Array shifts (move elements at from..from+size to to..to+size).

size_t netnode_altshift(uint64_t node, uint64_t from, uint64_t to, uint64_t size, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.altshift((nodeidx_t)from, (nodeidx_t)to, (nodeidx_t)size, (uchar)tag);
}

size_t netnode_supshift(uint64_t node, uint64_t from, uint64_t to, uint64_t size, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.supshift((nodeidx_t)from, (nodeidx_t)to, (nodeidx_t)size, (uchar)tag);
}

size_t netnode_charshift(uint64_t node, uint64_t from, uint64_t to, uint64_t size, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.charshift((nodeidx_t)from, (nodeidx_t)to, (nodeidx_t)size, (uchar)tag);
}

size_t netnode_blobshift(uint64_t node, uint64_t from, uint64_t to, uint64_t size, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.blobshift((nodeidx_t)from, (nodeidx_t)to, (nodeidx_t)size, (uchar)tag);
}

// Ranged and bulk deletes.

int32_t netnode_supdel_range(uint64_t node, uint64_t idx1, uint64_t idx2, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return (int32_t)n.supdel_range((nodeidx_t)idx1, (nodeidx_t)idx2, (uchar)tag);
}

bool netnode_supdel_all(uint64_t node, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.supdel_all((uchar)tag);
}

bool netnode_altdel_all(uint64_t node, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.altdel_all((uchar)tag);
}

bool netnode_hashdel_all(uint64_t node, uint32_t tag) {
  netnode n((nodeidx_t)node);
  return n.hashdel_all((uchar)tag);
}

} // namespace idakit_gen
