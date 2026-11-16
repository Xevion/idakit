// Widening from the SDK's native scalars onto the 64-bit wire every bridge carries.
//
// Every value leaving the facade crosses as uint64_t, but ea_t (and nodeidx_t and sel_t, which
// share its width) is 32-bit without __EA64__. A plain cast zero-extends that build's all-ones
// sentinel (BADADDR, BADNODE, BADSEL) to 0x00000000FFFFFFFF, which Rust then accepts as a valid
// value. ea_wire keeps all-ones all-ones at any width, so the Rust niche stays true by
// construction. widen is the spelling for every other value, which carries no sentinel.
//
// A source scan (tests/wire.rs) rejects any other widening cast in the facade, so each crossing
// names which of the two it is.
#ifndef WIRE_H
#define WIRE_H

#include <cstdint>
#include <limits>
#include <type_traits>

#include <pro.h>

template <class T> constexpr uint64_t widen_sentinel(T value) {
  static_assert(std::is_unsigned_v<T> && sizeof(T) <= sizeof(uint64_t));
  return value == std::numeric_limits<T>::max() ? UINT64_MAX : uint64_t{value};
}

// Pinned on the 32-bit width now, though the build is __EA64__-only, so dual width inherits it.
static_assert(widen_sentinel<uint32_t>(UINT32_MAX) == UINT64_MAX);
static_assert(widen_sentinel<uint32_t>(0xFFFFFFFEU) == 0xFFFFFFFEULL);
static_assert(widen_sentinel<uint32_t>(0) == 0);
static_assert(widen_sentinel<uint64_t>(UINT64_MAX) == UINT64_MAX);

// An address-domain value (ea_t, nodeidx_t, sel_t) onto the wire.
constexpr uint64_t ea_wire(ea_t value) { return widen_sentinel(value); }

// Any other integer onto the wire: a size, count, flag word, or signed frame delta.
template <class T> constexpr uint64_t widen(T value) {
  static_assert(std::is_integral_v<T>);
  return static_cast<uint64_t>(value);
}

#endif // WIRE_H
