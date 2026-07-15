// Shared internal helpers for the type-write domain's split TUs (namespace idakit_gen): the
// captured-diagnostic reader, the scalar leaf builders, the recipe interpreter, and the named-type
// resolver. Each is called from two or more of type_apply.cpp/type_define.cpp/udt_edit.cpp/
// enum_edit.cpp/func_sig.cpp/tinfo_build.cpp, so they need external linkage here rather than the
// per-TU anonymous-namespace copies a single-file helper gets.
#pragma once

#include <cstddef>
#include <cstdint>

#include <pro.h>

#include <ida.hpp>

#include <typeinf.hpp> // tinfo_t

#include "gen_type_build.h" // TypeWriteResult/SigWriteResult fwd decl, rust::String via gen_helpers.h

namespace idakit_gen {

// The last guarded call's captured diagnostics (IDA's messages, caught off the msg channel by the
// HT_UI hook) as an owned string; empty when nothing was captured. This is the one genuinely
// untrusted byte source (arbitrary msg() text, not a sanitized database string), so it decodes
// leniently: the throwing rust::String ctor would std::terminate inside these by-value, non-Result
// bodies.
rust::String captured_reason();

// Map a scalar integer leaf (width in bytes, signedness) onto the SDK's sized int types. False for
// a width IDA has no integer type for.
bool build_int(tinfo_t &out, uint32_t bytes, bool is_signed);

// Map a float leaf (4 -> float, 8 -> double) onto BT_FLOAT. False for any other width.
bool build_float(tinfo_t &out, uint32_t bytes);

// Resolve `name` to a typedef ref (resolve=false keeps the name in the applied type rather than
// its expansion, so `Foo *` stays `Foo *`). With resolve=false this returns true even for a name
// absent from the local til, building a forward reference the caller must existence-check itself.
bool build_named(tinfo_t &out, const char *name);

// Run the postfix recipe in (buf, len) over a tinfo stack, leaving the single resulting type in
// `out`: a leaf op pushes a type, a transform pops one and pushes the wrapped result, and a
// well-formed recipe leaves exactly one. TYPE_OK with `out` set, else TYPE_ERR_INPUT
// (malformed buffer, unresolved named leaf, or unparseable embedded decl). Callers wrap it in
// guarded<> (parse_decl/get_named_type/create_func may emit or trap).
int build_recipe(const uint8_t *buf, size_t len, tinfo_t &out);

// Link `tif` to the named type in the local til for editing. Edits to the returned typeref save
// back to the til and propagate to every reference (ETF_NO_SAVE stays unset). False if no such
// type. Resolves ANY named type without checking it's a UDT vs enum: the kernel verb that follows
// (add_udm, get_edm, ...) already rejects a mismatched target.
bool load_named_type(const char *type_name, tinfo_t &tif);

} // namespace idakit_gen
