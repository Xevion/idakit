// Declarations for the cxx-bridged import-table snapshot (namespace idakit_cxx). cxx emits the
// shim that calls imports_build and expects this header (named by the bridge's include!) to
// declare it; the generated glue and the hand-written body in import_cxx.cc both include it.
#pragma once

#include <cstddef>
#include <cstdint>

#include "rust/cxx.h"

namespace idakit_cxx {

// The cxx shared struct, defined by the generated header. Forward-declared here so the
// imports_build declaration can name it as a Vec element; import_cxx.cc includes the generated
// header for the full definition.
struct ImportRec;

rust::Vec<ImportRec> imports_build();

} // namespace idakit_cxx
