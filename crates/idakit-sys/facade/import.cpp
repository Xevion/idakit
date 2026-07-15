// Hand-written Custom body for the generated import domain (namespace idakit_gen). One walk of
// every module's enum_import_names collects the whole import table into an owned
// rust::Vec<ImportRec> returned by value in a single crossing. ImportRec is a cxx shared struct
// (name/module are rust::String), defined by the cxx-generated gen_bridge.h.

#include <ida.hpp>
#include <pro.h>

#include <nalt.hpp> // enum_import_names, get_import_module_qty, get_import_module_name

#include "gen_import.h"
// The cxx-generated header defines ImportRec (full definition needed to construct and push it) and
// instantiates rust::Vec<ImportRec>; gen_import.h only forward-declares ImportRec.
#include "gen_bridge.h"

namespace idakit_gen {

namespace {

struct collect_ctx_t {
  rust::Vec<ImportRec> *rows;
  const qstring *module;
};

int idaapi collect_import(ea_t ea, const char *name, uval_t ord, void *param) {
  collect_ctx_t *ctx = (collect_ctx_t *)param;
  ImportRec rec;
  rec.ea = (uint64_t)ea;
  rec.ord = (uint64_t)ord;
  if (name != nullptr)
    rec.name = to_rust_string(name);
  rec.module = to_rust_string(ctx->module->c_str(), ctx->module->length());
  ctx->rows->push_back(std::move(rec));
  return 1; // continue enumeration
}

} // namespace

rust::Vec<ImportRec> imports_build() {
  rust::Vec<ImportRec> rows;
  uint nmods = get_import_module_qty();
  for (uint m = 0; m < nmods; m++) {
    qstring module;
    get_import_module_name(&module, (int)m);
    collect_ctx_t ctx{&rows, &module};
    enum_import_names((int)m, collect_import, &ctx);
  }
  return rows;
}

} // namespace idakit_gen
