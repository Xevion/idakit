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
idakit_ea_t idakit_func_end(idakit_ea_t ea); /* entry-chunk end_ea, or BADADDR if not a func */
uint64_t idakit_func_flags(idakit_ea_t ea);  /* func_t.flags (\ref FUNC_), 0 if not a func */

int idakit_seg_qty(void);
int64_t idakit_seg_name(int n, char *buf, size_t cap);
idakit_ea_t idakit_seg_start(int n);
idakit_ea_t idakit_seg_end(int n);
int idakit_seg_perm(int n);    /* SEGPERM_ bits (0 = no info) */
int idakit_seg_bitness(int n); /* addressing bits: 16, 32, or 64 (0 if no such segment) */
int64_t idakit_seg_class(int n, char *buf, size_t cap); /* class name length, -1 if none */

/* Exports / entry points (entry.hpp). Indexed [0, export_qty); each row is one entry point.
 * export_ea is its address (BADADDR for a pure forwarder), export_ordinal its ordinal (or,
 * for a name-only entry, its entry index); name/forwarder are snprintf-style (<0 = none, and
 * most exports have no forwarder). */
size_t idakit_export_qty(void);
idakit_ea_t idakit_export_ea(size_t idx);
uint64_t idakit_export_ordinal(size_t idx);
int64_t idakit_export_name(size_t idx, char *buf, size_t cap);
int64_t idakit_export_forwarder(size_t idx, char *buf, size_t cap);

/* Imports (nalt.hpp). Import addresses have no stable random-access index, so imports_build
 * walks every module's names into one owned snapshot handle (never NULL; empty if none),
 * released with imports_free. qty is its length; item n fills the thunk address and ordinal
 * (0 = imported by name); name/module copy snprintf-style (name is absent, -1, for an
 * import-by-ordinal). */
void *idakit_imports_build(void);
size_t idakit_imports_qty(const void *h);
int idakit_imports_item(const void *h, size_t n, idakit_ea_t *ea, uint64_t *ord);
int64_t idakit_imports_name(const void *h, size_t n, char *buf, size_t cap);
int64_t idakit_imports_module(const void *h, size_t n, char *buf, size_t cap);
void idakit_imports_free(void *h);

/* Strings (strlist.hpp + bytes.hpp). strlist_build (re)builds IDA's string list (an
 * O(database) scan); strlist_qty is its length and strlist_item fills the nth entry's address,
 * octet length, and STRTYPE code (1 ok / 0 out of range). strlit_contents decodes the string
 * at (ea, len, type) to UTF-8, snprintf-style (<0 = undecodable), replacing undecodable units
 * with U+FFFD. */
void idakit_strlist_build(void);
size_t idakit_strlist_qty(void);
int idakit_strlist_item(size_t n, idakit_ea_t *ea, int *length, int *type);
int64_t idakit_strlit_contents(idakit_ea_t ea, size_t len, int type, char *buf, size_t cap);

int64_t idakit_get_bytes(idakit_ea_t ea, void *buf, size_t size); /* bytes read, <0 on fail */

/* Typed value reads (bytes.hpp). Each reads a value in the database's byte order and returns 1
 * with *out filled, or 0 if any covered byte is uninitialized (unmapped or never assigned a
 * value). Widths are 1/2/4/8 bytes. */
int idakit_get_u8(idakit_ea_t ea, uint8_t *out);
int idakit_get_u16(idakit_ea_t ea, uint16_t *out);
int idakit_get_u32(idakit_ea_t ea, uint32_t *out);
int idakit_get_u64(idakit_ea_t ea, uint64_t *out);

/* Read the string literal at ea (bytes.hpp): auto-detect its length (get_max_strlit_length) for
 * STRTYPE code `strtype` (0 = 1-byte C string), then decode to UTF-8 snprintf-style, replacing
 * undecodable units with U+FFFD. Returns the decoded length, or -1 if ea holds no such string. */
int64_t idakit_get_strlit(idakit_ea_t ea, int strtype, char *buf, size_t cap);

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
/* Build a compiled pattern directly from raw bytes and a per-byte mask (no parsing): the
 * caller has already tokenized. `mask` is len bytes, applied bitwise (search with BITMASK);
 * 0xFF = full byte, 0x00 = wildcard, 0xF0/0x0F = a nibble. Pass mask == NULL for all bytes
 * defined. Never fails structurally, so there is no error channel. */
void *idakit_binpat_from_bytes(const uint8_t *bytes, const uint8_t *mask, size_t len);
void idakit_binpat_free(void *pat);
/* Compiled pattern shape: *total = byte length, *anchors = concrete (non-wildcard) bytes.
 * anchors == 0 means the pattern pins nothing to match on (empty, all wildcards, or IDA
 * silently dropped an unreadable token). */
void idakit_binpat_stats(const void *pat, size_t *total, size_t *anchors);
idakit_ea_t idakit_bin_search(idakit_ea_t start, idakit_ea_t end, const void *pat, int flags);

/* Comment read (bytes.hpp get_cmt): fills buf snprintf-style with the comment at ea, regular
 * (rptble 0) or repeatable (rptble 1); returns its length, or -1 if there is none. The write
 * half is the plain libida `set_cmt`. */
int64_t idakit_get_cmt(idakit_ea_t ea, uint8_t rptble, char *buf, size_t cap);

/* Patch `size` bytes at ea (bytes.hpp patch_bytes; originals are saved and recoverable via
 * IDA's get_original_*). Returns 0 without patching anything when any target byte is
 * unmapped -- so a bad address fails cleanly instead of patching a truncated prefix -- and 1
 * on success. */
int idakit_patch_bytes(idakit_ea_t ea, const void *buf, size_t size);

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

/* Disassembly-level control-flow graph (gdl.hpp qflow_chart_t). cfg_build constructs the
 * flow chart for the function containing `ea` -- including tail chunks -- with the given
 * FC_ flags, returning an opaque handle (NULL if no function is there); the block list is
 * fully materialized at build time. Blocks are indexed [0, nblocks); block() fills the
 * range and fc_block_type_t `kind`. The first nproper() blocks are the function's own; the
 * rest are external stubs for out-of-function jump/call targets, built as zero-length
 * [target, target) ranges. Edges are block indices: succ/pred(n, i) return the i-th
 * successor/predecessor of block n, or -1 if out of range. Release with cfg_free. */
void *idakit_cfg_build(idakit_ea_t ea, int flags);
int idakit_cfg_nblocks(const void *h);
int idakit_cfg_nproper(const void *h);
int idakit_cfg_block(const void *h, int n, idakit_ea_t *start, idakit_ea_t *end, int *kind);
int idakit_cfg_nsucc(const void *h, int n);
int idakit_cfg_succ(const void *h, int n, int i);
int idakit_cfg_npred(const void *h, int n);
int idakit_cfg_pred(const void *h, int n, int i);
void idakit_cfg_free(void *h);

/* The disassembly-level stack frame (frame.hpp) is exposed only through the structured
 * frame-type walk (idakit_frame_type_walk), which lives with the shared type vtbl below since it
 * drives that machinery. */

int idakit_hexrays_init(void); /* 1 = decompiler ready, 0 = unavailable */
void *idakit_decompile(idakit_ea_t ea, char *errbuf,
                       size_t cap); /* cfunc handle (owns a ref); NULL on fail, reason in errbuf */
void idakit_cfunc_dispose(void *cfunc);
int64_t idakit_cfunc_pseudocode(void *cfunc, char *buf, size_t cap); /* tag-stripped text length */
void idakit_cfunc_ctree_counts(void *cfunc, int *n_insn, int *n_expr, int *n_calls);
/* Diagnostic: per-op expression histograms (256 ints each), from the SDK visitor (v_hist,
 * ground truth) and a mirror of the extraction walker's recursion (w_hist). Their difference
 * names the op the walker mis-visits. */
void idakit_cfunc_ctree_expr_gap(void *cfunc, int *v_hist, int *w_hist);

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

/* The type-emit callbacks, shared by every walk that builds an interned type table: the
 * ctree walk and the bare-tinfo walks (frame/member). Each returns the handle of the type it
 * minted; children are emitted before their container. kind: 1 void, 2 bool, 3 int, 4 float
 * (int also carries enum-underlying and bitfield base). A non-structural type is emitted via
 * t_opaque, never t_scalar. `name`/member-name spans borrow a C++ stack temporary valid only
 * for that single call (see the lifetime note on idakit_emit_vtbl_t). */
typedef struct idakit_type_vtbl_t {
  uint32_t (*t_scalar)(void *ctx, uint32_t kind, uint32_t bytes, uint32_t is_signed, uint64_t size,
                       uint32_t has_size);
  uint32_t (*t_ptr)(void *ctx, uint32_t target, uint64_t size, uint32_t has_size);
  uint32_t (*t_array)(void *ctx, uint32_t elem, uint64_t nelems, uint64_t size, uint32_t has_size);
  uint32_t (*t_func)(void *ctx, uint32_t ret, const uint32_t *params, size_t n, uint32_t vararg);
  /* A named type IDA can name but not structurally describe here (a forward-declared or
   * incomplete aggregate, an unresolved reference): a bodyless leaf carrying just the name. */
  uint32_t (*t_opaque)(void *ctx, const char *name, size_t name_len);
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
} idakit_type_vtbl_t;

/* Structured frame-type walk. `types` drives the shared tinfo walker to mint each variable's
 * type on the consumer side (building one interned table); `f_var` then reports the variable,
 * with its fp-relative offset (var_18 sits at -0x18), byte size, and flags (bit0 = return
 * address, bit1 = saved registers; both clear = an ordinary variable/argument). */
typedef struct idakit_frame_vtbl_t {
  idakit_type_vtbl_t types;
  void (*f_var)(void *ctx, const char *name, size_t name_len, int64_t offset, uint64_t size,
                uint32_t flags, uint32_t ty);
} idakit_frame_vtbl_t;

/* Walk the frame of the function at `ea` in one pass, driving `v` (with `ctx`): each variable's
 * type is emitted through `v->types` and the variable reported via `v->f_var`, and the frame's
 * total byte size written to `*frame_size`. A named type shared by two variables is emitted
 * once. Returns 0 on success, non-zero (leaving `*frame_size` untouched) if there is no function
 * or no frame at `ea`. */
int idakit_frame_type_walk(idakit_ea_t ea, const idakit_frame_vtbl_t *v, void *ctx,
                           uint64_t *frame_size);

/* Structured walks of a standalone type, driving the shared type vtbl `v` (with `ctx`) to mint
 * the type into one interned table and writing its root handle to `*root`. type_walk resolves the
 * local named type `name`; func_type_walk the stored prototype of the function at `ea`. Each
 * returns 0 on success, non-zero (leaving `*root` untouched) if there is no such named type / the
 * function has no type info. */
int idakit_type_walk(const char *name, const idakit_type_vtbl_t *v, void *ctx, uint32_t *root);
int idakit_func_type_walk(idakit_ea_t ea, const idakit_type_vtbl_t *v, void *ctx, uint32_t *root);

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

  /* type-emit callbacks, shared with the bare-tinfo walks (see idakit_type_vtbl_t). */
  idakit_type_vtbl_t types;

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
