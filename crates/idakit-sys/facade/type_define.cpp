// Hand-written Custom bodies for the generated type-write domain (namespace gen): parse C
// declarations into the local til, delete/rename a named type, or reserve a forward-declared
// aggregate. Reports an int result code plus captured diagnostic through a TypeWriteResult shared
// struct, as the sibling type-write TUs do.

#include <string>

#include <pro.h>

#include <ida.hpp>

#include <kernwin.hpp> // msg (parse_decls error sink)
#include <typeinf.hpp> // tinfo_t, parse_decls, del_named_type, create_forward_decl

#include "gen_type_build.h"
#include "internal.h" // guarded<>
// The generated bridge header defines the shared structs (full definitions needed to construct them
// below); gen_type_build.h only forward-declares them.
#include "gen_bridge.h"
#include "type_write_common.h" // captured_reason, load_named_type

using namespace facade;

namespace gen {

TypeWriteResult define_type(rust::Str input) {
  try {
    TypeWriteResult out{};
    std::string inputs(input.data(), input.size());
    out.code = guarded<int>(TYPE_ERR_INPUT, true, [&]() -> int {
      return parse_decls(get_idati(), inputs.c_str(), msg, HTI_DCL);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult delete_type(rust::Str type_name) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    out.code = guarded<int>(static_cast<int>(TERR_SAVE_ERROR), true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      // NTF_TYPE selects the type namespace; without it del_named_type looks up a symbol name
      // instead and reports the type as not found.
      bool deleted = del_named_type(get_idati(), tn.c_str(), NTF_TYPE);
      return deleted ? TYPE_OK : static_cast<int>(TERR_SAVE_ERROR);
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult rename_type(rust::Str type_name, rust::Str new_name) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    std::string nn(new_name.data(), new_name.size());
    out.code = guarded<int>(static_cast<int>(TERR_SAVE_ERROR), true, [&]() -> int {
      tinfo_t tif;
      if (!load_named_type(tn.c_str(), tif))
        return TEDIT_NO_TYPE;
      return static_cast<int>(tif.rename_type(nn.c_str()));
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

TypeWriteResult forward_declare_type(rust::Str type_name, uint32_t decl_type) {
  try {
    TypeWriteResult out{};
    std::string tn(type_name.data(), type_name.size());
    out.code = guarded<int>(static_cast<int>(TERR_SAVE_ERROR), true, [&]() -> int {
      tinfo_t tif;
      return static_cast<int>(
          tif.create_forward_decl(get_idati(), static_cast<type_t>(decl_type), tn.c_str()));
    });
    out.reason = captured_reason();
    return out;
  } catch (...) {
    std::abort();
  }
}

} // namespace gen
