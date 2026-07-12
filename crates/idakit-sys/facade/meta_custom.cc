// Hand-written Custom bodies for the generated meta domain (namespace idakit_gen). Database-wide
// metadata: bitness, image base, and four identity strings (processor, file-type text, input path,
// root filename). The string getters throw when the SDK reports no value (Err on the Rust side).

#include <pro.h>
#include <ida.hpp>

#include <loader.hpp>
#include <nalt.hpp>

#include <stdexcept>

#include "gen_meta.h"

namespace idakit_gen {

int32_t bitness() { return (int32_t)inf_get_app_bitness(); }

uint64_t image_base() { return (uint64_t)get_imagebase(); }

rust::String proc_name() {
  qstring out = inf_get_procname();
  if (out.length() == 0)
    throw std::runtime_error("no processor name");
  return rust::String(out.c_str(), out.length());
}

rust::String file_type_name() {
  char buf[256];
  size_t n = get_file_type_name(buf, sizeof(buf));
  if (n == 0)
    throw std::runtime_error("no file type name");
  return rust::String(buf, n);
}

rust::String input_path() {
  // get_input_file_path goes through getinf_buf, whose count includes the trailing NUL.
  char buf[QMAXPATH];
  ssize_t n = get_input_file_path(buf, sizeof(buf));
  if (n <= 0)
    throw std::runtime_error("no input file path");
  return rust::String(buf, (size_t)(n - 1));
}

rust::String root_filename() {
  char buf[QMAXPATH];
  ssize_t n = get_root_filename(buf, sizeof(buf));
  if (n <= 0)
    throw std::runtime_error("no root filename");
  return rust::String(buf, (size_t)n);
}

} // namespace idakit_gen
