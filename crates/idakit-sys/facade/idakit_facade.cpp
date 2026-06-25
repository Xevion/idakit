// idakit facade implementation. Includes the IDA SDK (C++) and exposes a clean C
// ABI. qstrings live and die here; callers get plain copied-out C strings.
//
// Include order mirrors the SDK's own idalib example (idacli.cpp): pro.h, ida.hpp,
// then the specific subsystem headers.

#include <pro.h>
#include <ida.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <bytes.hpp>    // get_bytes
#include <xref.hpp>     // xrefblk_t
#include <typeinf.hpp>  // tinfo_t, udt_type_data_t, print_type
#include <lines.hpp>   // tag_remove
#include <loader.hpp>  // load_plugin
#include <idp.hpp>     // HEXDSP / get_hexdsp
#include <hexrays.hpp>

#include "idakit_facade.h"
