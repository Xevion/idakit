// cxx-bridged import-table snapshot (namespace idakit_cxx). One call walks every module's
// enum_import_names into an owned rust::Vec<ImportRec>, returned by value. This retires the raw
// facade's build-handle -> index-N-times -> free dance (idakit_imports_build/_qty/_item/_name/
// _module/_free): no handle, no per-field accessor, no free. ImportRec is a cxx shared struct
// whose name/module fields are rust::String, so the owned strings ride inside the snapshot.

#include <pro.h>

#include <ida.hpp>

#include <nalt.hpp> // enum_import_names, get_import_module_qty, get_import_module_name

#include "import_cxx.h"
// The generated header defines the ImportRec shared struct (full definition needed to
// construct and push it); import_cxx.h only forward-declares it.
#include "idakit-sys/src/bridge_import.rs.h"

namespace idakit_cxx {

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
    rec.name = rust::String(name);
  rec.module = rust::String(ctx->module->c_str(), ctx->module->length());
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

} // namespace idakit_cxx
