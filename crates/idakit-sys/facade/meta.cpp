// Hand-written Custom bodies for the generated meta domain (namespace gen). Database-wide
// metadata: bitness, image base, and four identity strings (processor, file-type text, input path,
// root filename). The string getters throw when the SDK reports no value (Err on the Rust side).

#include <ida.hpp>
#include <pro.h>

#include <loader.hpp>
#include <nalt.hpp>

#include <stdexcept>

#include "gen_meta.h"

namespace gen {

int32_t bitness() { return (int32_t)inf_get_app_bitness(); }

uint64_t image_base() { return (uint64_t)get_imagebase(); }

rust::String proc_name() {
  qstring out = inf_get_procname();
  if (out.length() == 0)
    throw std::runtime_error("no processor name");
  return to_rust_string(out);
}

rust::String file_type_name() {
  char buf[256];
  size_t n = get_file_type_name(buf, sizeof(buf));
  if (n == 0)
    throw std::runtime_error("no file type name");
  return to_rust_string(buf, n);
}

rust::String input_path() {
  // get_input_file_path goes through getinf_buf, whose count includes the trailing NUL.
  char buf[QMAXPATH];
  ssize_t n = get_input_file_path(buf, sizeof(buf));
  if (n <= 0)
    throw std::runtime_error("no input file path");
  return to_rust_string(buf, (size_t)(n - 1));
}

rust::String root_filename() {
  char buf[QMAXPATH];
  ssize_t n = get_root_filename(buf, sizeof(buf));
  if (n <= 0)
    throw std::runtime_error("no root filename");
  return to_rust_string(buf, (size_t)n);
}

} // namespace gen
