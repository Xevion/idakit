#pragma once

#include <cstddef>
#include <cstdint>

// The moveit CopyNew shim below runs cfuncptr_t's copy-ctor and destructor, so cfunc_t must be
// complete here (hexrays.hpp), not merely forward-declared.
#include <pro.h>

#include <ida.hpp>

#include <hexrays.hpp>

// Raw C-ABI shims backing moveit's construction traits over cfuncptr_t. moveit needs
// placement-construct / copy-construct / destruct / raw-storage hooks that take a pointer into
// caller-owned uninitialized storage. All operate on a cfuncptr_t laid out at the given address, a
// Rust-stack repr(C) mirror (the inline CfuncVal path).
extern "C" {

// Placement copy-construct: run cfuncptr_t's copy-ctor from *src into dst (intrusive refcnt++).
void cfuncptr_copy_ctor(void *dst, const void *src);

// Placement-construct a cfuncptr_t into dst from decompiling the function at ea. dst is ALWAYS
// initialized (a null qrefcnt on any failure), so a later destructor/copy is always sound.
// Returns 1 if a cfunc was obtained, 0 otherwise.
int cfuncptr_decompile_into(void *dst, std::uint64_t ea);

// Run cfuncptr_t's destructor in place (intrusive refcnt--/release at zero); the inline CfuncVal
// Drop.
void cfuncptr_dtor(void *p);

// Read the pointee cfunc_t's intrusive refcnt (or -1 if the qrefcnt is null); the refcount probe.
std::int32_t cfuncptr_refcnt_raw(const void *p);
// Whether the qrefcnt at p holds a null cfunc_t pointer.
int cfuncptr_is_null_raw(const void *p);

} // extern "C"
