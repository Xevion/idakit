// Placement shims backing moveit's construction traits over the decompiler's intrusive-refcounted
// smart pointer cfuncptr_t (typedef qrefcnt_t<cfunc_t>), for the still-experimental inline CfuncVal
// value type. Plain facade TU, no cxx.
//
// qrefcnt_t is NOT std::shared_ptr, it holds a bare cfunc_t* whose copy-ctor increments an
// intrusive cfunc_t::refcnt and whose destructor calls release() (decrement, delete at zero). The
// shims placement-construct / copy-construct / destruct a cfuncptr_t at a caller-owned address (a
// repr(C) Rust mirror on the stack), which moveit drives to give the inline value type C++
// construction semantics.

#include <pro.h>

#include <ida.hpp>

#include <funcs.hpp> // get_func
#include <hexrays.hpp>
#include <loader.hpp> // load_plugin

#include <new>

#include "cfunc_shims.h"

namespace {

// The decompiler is a plugin; init it once (idempotent) before any decompile_func call.
bool ensure_hexrays() {
  if (init_hexrays_plugin())
    return true;
  load_plugin("hexx64");
  return init_hexrays_plugin();
}

// Decompile ea's function into a heap cfuncptr_t (one owned ref), or nullptr on any failure.
// NOT wrapped in the setjmp/longjmp guard: a decompiler fatal would abort here rather than trap
// (the production idakit_decompile guards; this spike path stays deliberately simple since callers
// only ever drive a known-decompilable function).
::cfuncptr_t *decompile_heap(std::uint64_t ea) {
  if (!ensure_hexrays())
    return nullptr;
  func_t *pfn = get_func((ea_t)ea);
  if (pfn == nullptr)
    return nullptr;
  hexrays_failure_t hf;
  ::cfuncptr_t cf = decompile_func(pfn, &hf, 0);
  if (cf == nullptr)
    return nullptr;
  // Copy-construct onto the heap (refcnt++); the local cf's dtor then decrements, leaving the
  // heap object holding exactly one ref.
  return new ::cfuncptr_t(cf);
}

} // namespace

// cfuncptr_t is a single cfunc_t* with no vtable, so it is pointer-sized; the Rust-side inline
// CfuncVal mirror relies on this.
static_assert(sizeof(::cfuncptr_t) == sizeof(void *), "cfuncptr_t is not pointer-sized");
static_assert(alignof(::cfuncptr_t) == alignof(void *), "cfuncptr_t alignment unexpected");

extern "C" {

void idakit_cfuncptr_copy_ctor(void *dst, const void *src) {
  new (dst)::cfuncptr_t(*reinterpret_cast<const ::cfuncptr_t *>(src));
}

int idakit_cfuncptr_decompile_into(void *dst, std::uint64_t ea) {
  ::cfuncptr_t *heap = decompile_heap(ea);
  if (heap == nullptr) {
    // Always initialize dst so a later dtor/copy is sound: an explicit null qrefcnt.
    new (dst)::cfuncptr_t((cfunc_t *)nullptr);
    return 0;
  }
  // Move the single ref into dst without a net refcount change: copy-construct (refcnt++) then
  // delete the heap holder (refcnt--).
  new (dst)::cfuncptr_t(*heap);
  delete heap;
  return 1;
}

void idakit_cfuncptr_dtor(void *p) { reinterpret_cast<::cfuncptr_t *>(p)->~qrefcnt_t(); }

std::int32_t idakit_cfuncptr_refcnt_raw(const void *p) {
  const cfunc_t *cf = *reinterpret_cast<const ::cfuncptr_t *>(p);
  return cf != nullptr ? (std::int32_t)cf->refcnt : -1;
}

int idakit_cfuncptr_is_null_raw(const void *p) {
  const cfunc_t *cf = *reinterpret_cast<const ::cfuncptr_t *>(p);
  return cf == nullptr ? 1 : 0;
}

} // extern "C"
