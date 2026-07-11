#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

// CfuncPtr is the SDK's cfuncptr_t (typedef qrefcnt_t<cfunc_t>) exposed as a cxx opaque type.
// cxx's UniquePtr glue instantiates std::unique_ptr<cfuncptr_t> in its own generated TU, and
// the moveit MakeCppStorage/CopyNew shims below run cfuncptr_t's copy-ctor and destructor, so
// cfunc_t must be complete here (hexrays.hpp), not merely forward-declared.
#include <pro.h>

#include <ida.hpp>

#include <hexrays.hpp>

#include "rust/cxx.h"

namespace idakit_cxx {

// cxx bridge shims (Goal A: opaque cfuncptr_t owned by UniquePtr). cfunc_decompile heap-allocates
// a cfuncptr_t (one owned ref on the cfunc_t) and hands it to Rust as a unique_ptr, whose cxx
// deleter runs ~cfuncptr_t (release()) on drop -- retiring the raw new/delete dance. cfunc_refcnt
// reads the pointee's intrusive count for the refcount probe.
std::unique_ptr<::cfuncptr_t> cfunc_decompile(std::uint64_t ea);
std::int32_t cfunc_refcnt(const ::cfuncptr_t &cf);

} // namespace idakit_cxx

// Raw C-ABI shims backing moveit's construction traits over cfuncptr_t. moveit needs
// placement-construct / copy-construct / destruct / raw-storage hooks that cxx cannot express
// (they take a pointer into caller-owned uninitialized storage). All operate on a cfuncptr_t
// laid out at the given address; the pointer is either C++ heap space (the MakeCppStorage +
// UniquePtr composition path) or a Rust-stack repr(C) mirror (the inline CfuncVal path).
extern "C" {

// Allocate / free raw uninitialized storage the size of one cfuncptr_t (moveit MakeCppStorage).
// alloc uses operator new so the eventual `delete` in cxx's UniquePtr deleter (destructor +
// operator delete) is the matching free; free is for the not-yet-constructed case.
void *idakit_cfuncptr_alloc(void);
void idakit_cfuncptr_free(void *p);

// Placement copy-construct: run cfuncptr_t's copy-ctor from *src into dst (intrusive refcnt++).
void idakit_cfuncptr_copy_ctor(void *dst, const void *src);

// Placement-construct a cfuncptr_t into dst from decompiling the function at ea. dst is ALWAYS
// initialized (a null qrefcnt on any failure), so a later destructor/copy is always sound.
// Returns 1 if a cfunc was obtained, 0 otherwise.
int idakit_cfuncptr_decompile_into(void *dst, std::uint64_t ea);

// Run cfuncptr_t's destructor in place (intrusive refcnt--/release at zero); for the inline
// CfuncVal Drop. The UniquePtr composition path never calls this (cxx's deleter does the delete).
void idakit_cfuncptr_dtor(void *p);

// Read the pointee cfunc_t's intrusive refcnt (or -1 if the qrefcnt is null); the refcount probe.
std::int32_t idakit_cfuncptr_refcnt_raw(const void *p);
// Whether the qrefcnt at p holds a null cfunc_t pointer.
int idakit_cfuncptr_is_null_raw(const void *p);

} // extern "C"
