// Declarations for the cxx extern "Rust" opaque-visitor type walk (namespace bridge). cxx
// emits the shims that call type_walk_visit_ordinal / func_type_walk_visit and expects this
// header (named by the bridge's include!) to declare them; the generated glue and the
// hand-written driver in typewalk_bridge.cpp both include it.
#pragma once

#include <cstdint>

#include "rust/cxx.h"
#include "trycatch.h"

namespace bridge {

// The extern "Rust" opaque visitor, defined by the generated header (gen_visitors.h) with a member
// function per node kind. Forward-declared here so the driver signatures can name it by reference;
// typewalk_bridge.cpp includes the generated header for the full class and its methods.
struct TypeWalkVisitor;
// The generated bridge header defines FrameWalk (with its FrameVar Vec); forward-declared here so
// frame_type_walk_visit can name it by value. A declaration may return an incomplete type; the
// definition and call sites both see the full struct through the generated header.
struct FrameWalk;

// Walk the named type `name` into `visitor`; throws if no such named type exists.
uint32_t type_walk_visit_named(rust::Str name, TypeWalkVisitor &visitor);
// Walk the type at local type library ordinal `ordinal` into `visitor`; throws if the ordinal is
// unused.
uint32_t type_walk_visit_ordinal(uint32_t ordinal, TypeWalkVisitor &visitor);
// Walk the type of the function at `addr` into `visitor`; throws if the function has no type
// info.
uint32_t func_type_walk_visit(uint64_t addr, TypeWalkVisitor &visitor);
// Walk the stack frame of the function at `addr` into a FrameWalk, resolving each variable's type
// through `visitor`; throws if the function has no frame.
FrameWalk frame_type_walk_visit(uint64_t addr, TypeWalkVisitor &visitor);

} // namespace bridge
