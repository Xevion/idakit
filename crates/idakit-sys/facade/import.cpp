// Hand-written Custom body for the generated import domain (namespace gen): one walk of every
// module's enum_import_names collects the whole import table into an owned rust::Vec<ImportRec>,
// returned by value in a single crossing. ImportRec is a cxx shared struct (name/module are
// rust::String) defined by the cxx-generated gen_bridge.h.

#include <ida.hpp>
#include <pro.h>

#include <nalt.hpp> // enum_import_names, get_import_module_qty, get_import_module_name

#include "gen_import.h"
// The cxx-generated header defines ImportRec (full definition needed to construct and push it) and
// instantiates rust::Vec<ImportRec>; gen_import.h only forward-declares ImportRec.
#include "gen_bridge.h"

namespace gen {

namespace {

struct collect_ctx_t {
  rust::Vec<ImportRec> *rows;
  const qstring *module;
};

// enum_import_names callback: appends one row for (addr, name, ord) to ctx->rows.
int idaapi collect_import(ea_t addr, const char *name, uval_t ord, void *param) {
  collect_ctx_t *ctx = reinterpret_cast<collect_ctx_t *>(param);
  ImportRec rec;
  rec.ea = static_cast<uint64_t>(addr);
  rec.ord = static_cast<uint64_t>(ord);
  if (name != nullptr)
    rec.name = to_rust_string(name);
  rec.module = to_rust_string(ctx->module->c_str(), ctx->module->length());
  ctx->rows->push_back(std::move(rec));
  return 1; // continue enumeration
}

} // namespace

// Every import across all modules, collected into one owned snapshot.
rust::Vec<ImportRec> imports_build() {
  rust::Vec<ImportRec> rows;
  uint nmods = get_import_module_qty();
  for (uint m = 0; m < nmods; m++) {
    qstring module;
    get_import_module_name(&module, static_cast<int>(m));
    collect_ctx_t ctx{&rows, &module};
    enum_import_names(static_cast<int>(m), collect_import, &ctx);
  }
  return rows;
}

} // namespace gen
