// Hand-written Custom bodies for the generated meta domain (namespace gen): database-wide
// metadata, bitness, image base, and four identity strings (processor, file-type text, input
// path, root filename). String getters throw std::runtime_error (a Rust Err) when the SDK
// reports no value.

#include <ida.hpp>
#include <pro.h>

#include <loader.hpp>
#include <nalt.hpp>

#include <stdexcept>

#include "gen_meta.h"

namespace gen {

// Address bitness of the database: 16, 32, or 64.
int32_t bitness() { return static_cast<int32_t>(inf_get_app_bitness()); }

// Base address the input file was loaded at.
uint64_t image_base() { return static_cast<uint64_t>(get_imagebase()); }

// Name of the processor module the database was analyzed with; throws when it is unset.
rust::String proc_name() {
  qstring out = inf_get_procname();
  if (out.length() == 0)
    throw std::runtime_error("no processor name");
  return to_rust_string(out);
}

// No SDK constant bounds a processor's file-type text; comfortably above any real name.
constexpr size_t FILE_TYPE_NAME_BUF_SIZE = 256;

// Human-readable file type (e.g. "Portable executable"); throws when the SDK reports none.
rust::String file_type_name() {
  char buf[FILE_TYPE_NAME_BUF_SIZE];
  size_t n = get_file_type_name(buf, sizeof(buf));
  if (n == 0)
    throw std::runtime_error("no file type name");
  return to_rust_string(buf, n);
}

// Full path to the original input file; throws when the database has none recorded.
rust::String input_path() {
  // get_input_file_path goes through getinf_buf, whose count includes the trailing NUL.
  char buf[QMAXPATH];
  ssize_t n = get_input_file_path(buf, sizeof(buf));
  if (n <= 0)
    throw std::runtime_error("no input file path");
  return to_rust_string(buf, static_cast<size_t>(n - 1));
}

// Base filename (no directory) of the input file; throws when the database has none recorded.
rust::String root_filename() {
  char buf[QMAXPATH];
  ssize_t n = get_root_filename(buf, sizeof(buf));
  if (n <= 0)
    throw std::runtime_error("no root filename");
  return to_rust_string(buf, static_cast<size_t>(n));
}

} // namespace gen
