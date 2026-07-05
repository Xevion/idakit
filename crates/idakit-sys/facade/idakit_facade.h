/* idakit facade: a clean C ABI over the C++ IDA SDK surface.
 * Opaque handles + free functions; strings copied out into caller buffers.
 * This header is what idakit-sys binds (hand-extern for now, bindgen later). */
#ifndef IDAKIT_FACADE_H
#define IDAKIT_FACADE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t idakit_ea_t; /* ea_t under __EA64__ */

/* Force headless (TVHEADLESS) then init_library; returns its rc (0 = ok). Wrapping keeps
 * the setenv ordered before init and the side effect on the C++ side. */
int idakit_init_library(void);

/* Set IDA's `batch` global: nonzero suppresses dialogs and auto-answers prompts (headless
 * default), zero restores interactive behavior (e.g. a GUI-plugin host). */
void idakit_set_batch(int on);

/* Fatal-exit trap. idakit_guarded_open returns this sentinel (instead of an
 * open_database rc) when the kernel tried to terminate the process mid-call; the
 * intercepted exit code is then available from idakit_last_exit_code(). */
#define IDAKIT_EXIT_TRAPPED (-0x7FFFFFFF)
int idakit_guarded_open(const char *file_path, int run_auto);
int idakit_guarded_auto_wait(void); /* 1 ok / 0 fail / IDAKIT_EXIT_TRAPPED */
int idakit_guarded_close(int save); /* 0 ok / IDAKIT_EXIT_TRAPPED */
int idakit_last_exit_code(void);
int idakit_was_trapped(void); /* 1 if the last guarded call trapped a fatal exit */
size_t idakit_last_output(char *buf, size_t cap); /* captured stdout+stderr; len, snprintf-style */

int idakit_reg_read_int(const char *name, int defval); /* read an int/bool registry value */
int idakit_accept_eula(void); /* record EULA acceptance; returns its value */

/* Fault-injection shim, compiled only under the `test-shims` feature. Runs the chosen fatal
 * inside the guarded<> wrapper so the trap tests can prove it is converted to
 * IDAKIT_EXIT_TRAPPED rather than terminating the process. */
#ifdef IDAKIT_TEST_SHIMS
#define IDAKIT_FATAL_EXIT 0
#define IDAKIT_FATAL_ABORT 1
#define IDAKIT_FATAL_INTERR 2
int idakit_test_fatal(int kind);
int idakit_get_batch(void); /* read back the `batch` global, to prove bring-up wired it */
#endif

size_t idakit_func_qty(void);
idakit_ea_t idakit_func_ea(size_t n); /* start_ea of nth func, or BADADDR */
int64_t idakit_func_name(idakit_ea_t ea, char *buf, size_t cap); /* name length, <0 on miss */
int idakit_func_chunk_qty(idakit_ea_t ea); /* # chunks (entry + tails), 0 if not a func */
int idakit_func_chunk(
    idakit_ea_t ea, int idx, idakit_ea_t *start,
    idakit_ea_t *end); /* 1 + fills [start,end) if chunk idx exists (entry chunk = idx 0) */

int idakit_seg_qty(void);
int64_t idakit_seg_name(int n, char *buf, size_t cap);
idakit_ea_t idakit_seg_start(int n);
idakit_ea_t idakit_seg_end(int n);

int64_t idakit_get_bytes(idakit_ea_t ea, void *buf, size_t size); /* bytes read, <0 on fail */

/* Byte/item classification and navigation (bytes.hpp). `flags` is IDA's per-address class
 * word; the Rust side masks it against MS_CLS for is_code/is_data. An item head is the first
 * address of a defined instruction or data item; next/prev_head return BADADDR when no head
 * lies within the given bound. */
uint64_t idakit_get_flags(idakit_ea_t ea);
idakit_ea_t idakit_get_item_head(idakit_ea_t ea); /* start of the item covering ea */
idakit_ea_t idakit_get_item_end(idakit_ea_t ea);  /* one-past-end of the item at ea */
idakit_ea_t idakit_get_next_head(idakit_ea_t ea,
                                 idakit_ea_t maxea); /* next head before maxea, or BADADDR */
idakit_ea_t idakit_get_prev_head(idakit_ea_t ea,
                                 idakit_ea_t minea); /* prev head at/after minea, or BADADDR */

/* Binary pattern search (bytes.hpp). binpat_compile parses an IDA-style pattern string
 * ("B8 ? ? ? ? 90", ? = wildcard byte) at radix `radix` into an opaque handle bound to
 * `ea`'s byte width; returns NULL on a parse error, with the reason written to errbuf.
 * bin_search scans [start,end) for a compiled pattern, returning the match address or
 * BADADDR when none is found (the headless NOBREAK/NOSHOW flags are always applied); `flags`
 * adds BIN_SEARCH_* semantics (case, bitmask). Release the handle with binpat_free.
 * min_ea/max_ea are the database's address bounds, the natural default search range. */
idakit_ea_t idakit_min_ea(void);
idakit_ea_t idakit_max_ea(void);
void *idakit_binpat_compile(idakit_ea_t ea, const char *pattern, int radix, char *errbuf,
                            size_t errcap);
void idakit_binpat_free(void *pat);
idakit_ea_t idakit_bin_search(idakit_ea_t start, idakit_ea_t end, const void *pat, int flags);

/* Database-wide metadata. String getters are snprintf-style (return the full length). */
int idakit_bitness(void);                             /* 16, 32, or 64 */
idakit_ea_t idakit_image_base(void);                  /* preferred load address */
int64_t idakit_proc_name(char *buf, size_t cap);      /* processor id, e.g. "metapc" */
int64_t idakit_file_type_name(char *buf, size_t cap); /* input file format, human text */
int64_t idakit_input_path(char *buf, size_t cap);     /* full path of the analyzed input */
int64_t idakit_root_filename(char *buf, size_t cap);  /* input's base file name */

/* Names (name.hpp). get_ea_name reads the name at an address; get_name_ea is the reverse
 * lookup (BADADDR if unknown); demangle_name turns a mangled symbol into readable form (<0
 * if the name is not mangled). The nlist enumerates every named address. String getters are
 * snprintf-style; <0 means "no such name". */
int64_t idakit_get_ea_name(idakit_ea_t ea, char *buf, size_t cap);
idakit_ea_t idakit_get_name_ea(const char *name);
int64_t idakit_demangle_name(const char *name, char *buf, size_t cap);
size_t idakit_nlist_size(void);
idakit_ea_t idakit_nlist_ea(size_t idx);
int64_t idakit_nlist_name(size_t idx, char *buf, size_t cap);

/* Cross-reference cursor (ordinary flow excluded). `is_to` selects xrefs TO ea (callers
 * of ea) vs FROM ea (what ea references). Open returns an opaque cursor; step it with
 * next (writes from/to/type/iscode, returns 1 until exhausted, then 0); release with
 * close. type is the cref_t/dref_t byte. */
void *idakit_xref_open(idakit_ea_t ea, uint8_t is_to);
uint8_t idakit_xref_next(void *cursor, idakit_ea_t *from, idakit_ea_t *to, uint8_t *type,
                         uint8_t *iscode);
void idakit_xref_close(void *cursor);

int64_t idakit_func_type(idakit_ea_t ea, char *buf, size_t cap); /* prototype text, <0 on miss */

size_t idakit_type_ordinal_count(void); /* # of local named types */
int64_t idakit_type_ordinal_name(uint32_t ordinal, char *buf, size_t cap);
void *idakit_type_open(const char *name); /* opaque tinfo, NULL if unknown */
void idakit_type_dispose(void *h);
int64_t idakit_type_size(void *h);                         /* byte size, <0 if unknown */
int64_t idakit_type_print(void *h, char *buf, size_t cap); /* full type decl text */
size_t idakit_type_nmembers(void *h);                      /* 0 if not a struct/union */
int idakit_type_member_info(void *h, size_t i, uint64_t *offset,
                            uint64_t *size); /* 1 if member i exists; offset/size in BYTES */
int64_t idakit_type_member_name(void *h, size_t i, char *buf,
                                size_t cap); /* name length, <0 if absent */
int64_t idakit_type_member_type(void *h, size_t i, char *buf,
                                size_t cap); /* type repr length, <0 if absent */

int idakit_hexrays_init(void); /* 1 = decompiler ready, 0 = unavailable */
void *idakit_decompile(idakit_ea_t ea, char *errbuf,
                       size_t cap); /* cfunc handle (owns a ref); NULL on fail, reason in errbuf */
void idakit_cfunc_dispose(void *cfunc);
int64_t idakit_cfunc_pseudocode(void *cfunc, char *buf, size_t cap); /* tag-stripped text length */
void idakit_cfunc_ctree_counts(void *cfunc, int *n_insn, int *n_expr, int *n_calls);

/* Streaming ctree extraction. The facade is a pure SDK walker: it reads a decompiled
 * function's ctree depth-first and, per node, calls one Rust callback in `vtbl` to mint
 * the corresponding owned node. Children are emitted before their parent (post-order),
 * so each callback receives its children as the `uint32_t` handles their own callbacks
 * returned; the facade just threads them through the recursion. The facade owns no node
 * storage and does no interning -- all identity, dedup, and meaning live on the Rust side.
 *
 * Handles are opaque to the facade. `0xFFFFFFFF` (IDAKIT_NONE) marks an absent optional
 * child. `ctx` is passed back to every callback untouched. */
#define IDAKIT_NONE 0xFFFFFFFFu

/* One struct/union member: `name` (UTF-8, `name_len` bytes, may be empty), `bit_offset`
 * from the aggregate start, member type `ty`, and `bitfield_width` (0 = not a bitfield). */
typedef struct {
  const char *name;
  size_t name_len;
  uint64_t bit_offset;
  uint32_t ty;
  uint32_t bitfield_width;
} idakit_member_t;

/* One enum constant: `name` and its integer `value`. */
typedef struct {
  const char *name;
  size_t name_len;
  uint64_t value;
} idakit_enum_const_t;

/* One switch case: its `values` (empty = default) and `body` statement handle. */
typedef struct {
  const uint64_t *values;
  size_t nvalues;
  uint32_t body;
} idakit_case_t;

/* The callbacks the facade invokes while walking. Every function returns the handle of
 * the node/type it minted (except the void ones). Scalar `kind` codes and `ctype` values
 * are interpreted on the Rust side. `ty` is the node's resolved type handle.
 *
 * Pointer lifetime: every `const char*`/byte span passed to a callback (names, string
 * literals, member/enum-constant names, comments, value arrays) points into a C++ stack
 * temporary owned by the walk -- a local `qstring`, `udt_type_data_t`, `enum_type_data_t`,
 * or `std::vector`. It is borrowed for that single callback invocation only and is
 * invalidated as soon as the callback returns; a callback that needs it longer must copy
 * it before returning. */
typedef struct idakit_emit_vtbl_t {
  /* expressions */
  uint32_t (*e_num)(void *ctx, idakit_ea_t ea, uint64_t value, uint32_t ty);
  uint32_t (*e_fnum)(void *ctx, idakit_ea_t ea, double value, uint32_t ty);
  uint32_t (*e_obj)(void *ctx, idakit_ea_t ea, idakit_ea_t target, const char *name,
                    size_t name_len, uint32_t ty);
  uint32_t (*e_var)(void *ctx, idakit_ea_t ea, uint32_t idx, uint32_t ty);
  uint32_t (*e_str)(void *ctx, idakit_ea_t ea, const char *s, size_t len, uint32_t ty);
  uint32_t (*e_helper)(void *ctx, idakit_ea_t ea, const char *s, size_t len, uint32_t ty);
  uint32_t (*e_call)(void *ctx, idakit_ea_t ea, uint32_t callee, const uint32_t *args, size_t nargs,
                     uint32_t ty);
  uint32_t (*e_memref)(void *ctx, idakit_ea_t ea, uint32_t obj, uint32_t offset, uint32_t ty);
  uint32_t (*e_memptr)(void *ctx, idakit_ea_t ea, uint32_t obj, uint32_t offset, uint32_t ty);
  uint32_t (*e_deref)(void *ctx, idakit_ea_t ea, uint32_t x, uint32_t size, uint32_t ty);
  /* generic operator node: binary/assign/unary/ternary/cast/index/sizeof/empty/type/insn.
   * `ctype` is the raw ctype_t; absent operands are IDAKIT_NONE. */
  uint32_t (*e_op)(void *ctx, idakit_ea_t ea, uint32_t ctype, uint32_t x, uint32_t y, uint32_t z,
                   uint32_t ty);

  /* statements */
  uint32_t (*s_block)(void *ctx, idakit_ea_t ea, const uint32_t *kids, size_t nkids);
  uint32_t (*s_expr)(void *ctx, idakit_ea_t ea, uint32_t expr);
  uint32_t (*s_if)(void *ctx, idakit_ea_t ea, uint32_t cond, uint32_t then_s, uint32_t else_s);
  uint32_t (*s_for)(void *ctx, idakit_ea_t ea, uint32_t init, uint32_t cond, uint32_t step,
                    uint32_t body);
  uint32_t (*s_while)(void *ctx, idakit_ea_t ea, uint32_t cond, uint32_t body);
  uint32_t (*s_do)(void *ctx, idakit_ea_t ea, uint32_t body, uint32_t cond);
  uint32_t (*s_switch)(void *ctx, idakit_ea_t ea, uint32_t expr, const idakit_case_t *cases,
                       size_t ncases);
  uint32_t (*s_break)(void *ctx, idakit_ea_t ea);
  uint32_t (*s_continue)(void *ctx, idakit_ea_t ea);
  uint32_t (*s_return)(void *ctx, idakit_ea_t ea, uint32_t expr /* or IDAKIT_NONE */);
  uint32_t (*s_goto)(void *ctx, idakit_ea_t ea, int32_t label);
  uint32_t (*s_asm)(void *ctx, idakit_ea_t ea, const uint64_t *addrs, size_t n);
  uint32_t (*s_try)(void *ctx, idakit_ea_t ea, uint32_t body, const uint32_t *catches, size_t n);
  uint32_t (*s_throw)(void *ctx, idakit_ea_t ea, uint32_t expr /* or IDAKIT_NONE */);
  uint32_t (*s_empty)(void *ctx, idakit_ea_t ea);

  /* types. kind: 0 unknown, 1 void, 2 bool, 3 int, 4 float. */
  uint32_t (*t_scalar)(void *ctx, uint32_t kind, uint32_t bytes, uint32_t is_signed, uint64_t size,
                       uint32_t has_size);
  uint32_t (*t_ptr)(void *ctx, uint32_t target, uint64_t size, uint32_t has_size);
  uint32_t (*t_array)(void *ctx, uint32_t elem, uint64_t nelems, uint64_t size, uint32_t has_size);
  uint32_t (*t_func)(void *ctx, uint32_t ret, const uint32_t *params, size_t n, uint32_t vararg);
  /* Reference a named aggregate/typedef; mints (or returns the existing) placeholder so a
   * recursive member can point back before the definition is filled. */
  uint32_t (*t_named_ref)(void *ctx, const char *name, size_t name_len);
  /* Mint an anonymous (un-deduped) placeholder for an unnamed struct/union/enum. */
  uint32_t (*t_anon)(void *ctx);
  /* Fill a placeholder `id` minted by t_named_ref/t_anon. */
  void (*t_fill_struct)(void *ctx, uint32_t id, uint32_t is_union, const idakit_member_t *members,
                        size_t n, uint64_t size, uint32_t has_size);
  void (*t_fill_enum)(void *ctx, uint32_t id, uint32_t underlying,
                      const idakit_enum_const_t *consts, size_t n, uint64_t size,
                      uint32_t has_size);
  void (*t_fill_typedef)(void *ctx, uint32_t id, uint32_t underlying);

  /* locals. Append one lvar; the call order is the lvar index that `e_var.idx` refers to. flags:
   * bit0 is_arg, bit1 is_result, bit2 is_byref. loc_kind: 0 other, 1 register, 2 stack. */
  void (*l_lvar)(void *ctx, const char *name, size_t name_len, uint32_t ty, uint32_t flags,
                 uint32_t width, const char *comment, size_t comment_len, uint32_t loc_kind,
                 int64_t loc_val);
} idakit_emit_vtbl_t;

/* Walk `cfunc`'s ctree, driving `vtbl` (with `ctx`) and writing the root statement handle
 * to `*root`. Returns 0 on success, non-zero if `cfunc` is NULL. */
int idakit_cfunc_walk_ctree(void *cfunc, const idakit_emit_vtbl_t *vtbl, void *ctx, uint32_t *root);

/* Instruction decode. One flat POD per instruction (no owned handle): the facade decodes
 * on the kernel thread, folds every raw operand type into a semantic kind, resolves
 * register names and control-flow facts, and copies it all into `*out`. Bounded to
 * IDAKIT_MAX_OPS operands, so a fixed struct beats a streaming vtable here. */
#define IDAKIT_MAX_OPS 8

/* idakit_op_t::kind -- semantic operand classification (raw optype is folded away). */
#define IDAKIT_OP_REG 0
#define IDAKIT_OP_MEM 1
#define IDAKIT_OP_IMM 2
#define IDAKIT_OP_NEAR 3
#define IDAKIT_OP_FAR 4

/* idakit_reg_t::num sentinel for an absent base/index register. */
#define IDAKIT_REG_NONE 0xFFFF

/* idakit_insn_t::flow bit flags. */
#define IDAKIT_FLOW_CALL 0x01
#define IDAKIT_FLOW_RET 0x02
#define IDAKIT_FLOW_JUMP 0x04
#define IDAKIT_FLOW_INDIRECT 0x08
#define IDAKIT_FLOW_STOPS 0x10

/* A register reference: number, idakit RegClass code, selected byte width, and IDA's
 * resolved name (NUL-terminated, empty if unresolved). num == IDAKIT_REG_NONE means the
 * slot is absent (a memory operand with no base/index). */
typedef struct {
  uint16_t num;
  uint8_t cls;
  uint8_t width;
  char name[16];
} idakit_reg_t;

/* One decoded operand. Which fields are meaningful depends on `kind`:
 *   REG  -> reg
 *   MEM  -> base, index, scale, disp, addr (target, BADADDR if none)
 *   IMM  -> value
 *   NEAR -> addr (target)
 *   FAR  -> value (offset), sel (selector)
 * `idx` is the original operand slot (feature bits are keyed by it). `access` bit0 =
 * read, bit1 = written. `dtype` is the raw op_dtype_t. */
typedef struct {
  uint8_t kind;
  uint8_t idx;
  uint8_t dtype;
  uint8_t access;
  uint8_t scale;
  idakit_reg_t reg;
  idakit_reg_t base;
  idakit_reg_t index;
  int64_t disp;
  uint64_t value;
  uint64_t addr;
  uint16_t sel;
} idakit_op_t;

/* One decoded instruction. `isa`: 0 = x86, 1 = x64. `target` is the direct branch/call
 * destination or BADADDR. `nops` counts the populated `ops` (trailing empty slots
 * dropped). On the error return -3, `err_optype`/`err_op` carry the offending raw type
 * and operand index. */
typedef struct {
  uint64_t ea;
  uint64_t target;
  uint16_t itype;
  uint8_t len;
  uint8_t isa;
  uint8_t nops;
  uint8_t flow;
  uint8_t err_optype;
  uint8_t err_op;
  char mnemonic[24];
  idakit_op_t ops[IDAKIT_MAX_OPS];
} idakit_insn_t;

/* Decode the instruction at `ea` into `*out`. Returns 0 on success, or negative:
 *   -1 no instruction decodes at `ea`
 *   -2 the database's processor has no wired decoder (only x86/x64 for now)
 *   -3 a supported processor produced an operand this decoder cannot model
 *      (should be unreachable for x86; err_optype/err_op say which). */
int idakit_decode_insn(idakit_ea_t ea, idakit_insn_t *out);

#ifdef __cplusplus
}
#endif

#endif /* IDAKIT_FACADE_H */
