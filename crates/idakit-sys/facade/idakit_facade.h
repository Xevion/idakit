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

/* Fatal-exit trap. idakit_guarded_open returns this sentinel (instead of an
 * open_database rc) when the kernel tried to terminate the process mid-call; the
 * intercepted exit code is then available from idakit_last_exit_code(). */
#define IDAKIT_EXIT_TRAPPED (-0x7FFFFFFF)
int idakit_guarded_open(const char *file_path, int run_auto);
int idakit_guarded_auto_wait(void);               /* 1 ok / 0 fail / IDAKIT_EXIT_TRAPPED */
int idakit_guarded_close(int save);               /* 0 ok / IDAKIT_EXIT_TRAPPED */
int idakit_last_exit_code(void);
int idakit_was_trapped(void);                     /* 1 if the last guarded call trapped a fatal exit */
size_t idakit_last_output(char *buf, size_t cap); /* captured stdout+stderr; len, snprintf-style */

int idakit_reg_read_int(const char *name, int defval); /* read an int/bool registry value */
int idakit_accept_eula(void);                          /* record EULA acceptance; returns its value */

size_t      idakit_func_qty(void);
idakit_ea_t idakit_func_ea(size_t n);                              /* start_ea of nth func, or BADADDR */
int64_t     idakit_func_name(idakit_ea_t ea, char *buf, size_t cap); /* name length, <0 on miss */

int     idakit_seg_qty(void);
int64_t idakit_seg_name(int n, char *buf, size_t cap);
idakit_ea_t idakit_seg_start(int n);
idakit_ea_t idakit_seg_end(int n);

int64_t idakit_get_bytes(idakit_ea_t ea, void *buf, size_t size);  /* bytes read, <0 on fail */

/* Cross-reference cursor (ordinary flow excluded). `is_to` selects xrefs TO ea (callers
 * of ea) vs FROM ea (what ea references). Open returns an opaque cursor; step it with
 * next (writes from/to/type/iscode, returns 1 until exhausted, then 0); release with
 * close. type is the cref_t/dref_t byte. */
void   *idakit_xref_open(idakit_ea_t ea, uint8_t is_to);
uint8_t idakit_xref_next(void *cursor, idakit_ea_t *from, idakit_ea_t *to,
                         uint8_t *type, uint8_t *iscode);
void    idakit_xref_close(void *cursor);

int64_t idakit_func_type(idakit_ea_t ea, char *buf, size_t cap);   /* prototype text, <0 on miss */

size_t  idakit_type_ordinal_count(void);                           /* # of local named types */
int64_t idakit_type_ordinal_name(uint32_t ordinal, char *buf, size_t cap);
void   *idakit_type_open(const char *name);                        /* opaque tinfo, NULL if unknown */
void    idakit_type_dispose(void *h);
int64_t idakit_type_size(void *h);                                 /* byte size, <0 if unknown */
int64_t idakit_type_print(void *h, char *buf, size_t cap);         /* full type decl text */
size_t  idakit_type_nmembers(void *h);                             /* 0 if not a struct/union */
int     idakit_type_member_info(void *h, size_t i,
                                uint64_t *offset, uint64_t *size); /* 1 if member i exists; offset/size in BYTES */
int64_t idakit_type_member_name(void *h, size_t i, char *buf, size_t cap); /* name length, <0 if absent */
int64_t idakit_type_member_type(void *h, size_t i, char *buf, size_t cap); /* type repr length, <0 if absent */

int   idakit_hexrays_init(void);                       /* 1 = decompiler ready, 0 = unavailable */
void *idakit_decompile(idakit_ea_t ea, char *errbuf, size_t cap); /* cfunc handle (owns a ref); NULL on fail, reason in errbuf */
void  idakit_cfunc_dispose(void *cfunc);
int64_t idakit_cfunc_pseudocode(void *cfunc, char *buf, size_t cap); /* tag-stripped text length */
void  idakit_cfunc_ctree_counts(void *cfunc, int *n_insn, int *n_expr, int *n_calls);

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
typedef struct
{
  const char *name; size_t name_len;
  uint64_t    bit_offset;
  uint32_t    ty;
  uint32_t    bitfield_width;
} idakit_member_t;

/* One enum constant: `name` and its integer `value`. */
typedef struct { const char *name; size_t name_len; uint64_t value; } idakit_enum_const_t;

/* One switch case: its `values` (empty = default) and `body` statement handle. */
typedef struct { const uint64_t *values; size_t nvalues; uint32_t body; } idakit_case_t;

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
typedef struct idakit_emit_vtbl_t
{
  /* expressions */
  uint32_t (*e_num)   (void *ctx, idakit_ea_t ea, uint64_t value, uint32_t ty);
  uint32_t (*e_fnum)  (void *ctx, idakit_ea_t ea, double value, uint32_t ty);
  uint32_t (*e_obj)   (void *ctx, idakit_ea_t ea, idakit_ea_t target,
                       const char *name, size_t name_len, uint32_t ty);
  uint32_t (*e_var)   (void *ctx, idakit_ea_t ea, uint32_t idx, uint32_t ty);
  uint32_t (*e_str)   (void *ctx, idakit_ea_t ea, const char *s, size_t len, uint32_t ty);
  uint32_t (*e_helper)(void *ctx, idakit_ea_t ea, const char *s, size_t len, uint32_t ty);
  uint32_t (*e_call)  (void *ctx, idakit_ea_t ea, uint32_t callee,
                       const uint32_t *args, size_t nargs, uint32_t ty);
  uint32_t (*e_memref)(void *ctx, idakit_ea_t ea, uint32_t obj, uint32_t offset, uint32_t ty);
  uint32_t (*e_memptr)(void *ctx, idakit_ea_t ea, uint32_t obj, uint32_t offset, uint32_t ty);
  uint32_t (*e_deref) (void *ctx, idakit_ea_t ea, uint32_t x, uint32_t size, uint32_t ty);
  /* generic operator node: binary/assign/unary/ternary/cast/index/sizeof/empty/type/insn.
   * `ctype` is the raw ctype_t; absent operands are IDAKIT_NONE. */
  uint32_t (*e_op)    (void *ctx, idakit_ea_t ea, uint32_t ctype,
                       uint32_t x, uint32_t y, uint32_t z, uint32_t ty);

  /* statements */
  uint32_t (*s_block) (void *ctx, idakit_ea_t ea, const uint32_t *kids, size_t nkids);
  uint32_t (*s_expr)  (void *ctx, idakit_ea_t ea, uint32_t expr);
  uint32_t (*s_if)    (void *ctx, idakit_ea_t ea, uint32_t cond, uint32_t then_s, uint32_t else_s);
  uint32_t (*s_for)   (void *ctx, idakit_ea_t ea, uint32_t init, uint32_t cond,
                       uint32_t step, uint32_t body);
  uint32_t (*s_while) (void *ctx, idakit_ea_t ea, uint32_t cond, uint32_t body);
  uint32_t (*s_do)    (void *ctx, idakit_ea_t ea, uint32_t body, uint32_t cond);
  uint32_t (*s_switch)(void *ctx, idakit_ea_t ea, uint32_t expr,
                       const idakit_case_t *cases, size_t ncases);
  uint32_t (*s_break) (void *ctx, idakit_ea_t ea);
  uint32_t (*s_continue)(void *ctx, idakit_ea_t ea);
  uint32_t (*s_return)(void *ctx, idakit_ea_t ea, uint32_t expr /* or IDAKIT_NONE */);
  uint32_t (*s_goto)  (void *ctx, idakit_ea_t ea, int32_t label);
  uint32_t (*s_asm)   (void *ctx, idakit_ea_t ea, const uint64_t *addrs, size_t n);
  uint32_t (*s_try)   (void *ctx, idakit_ea_t ea, uint32_t body,
                       const uint32_t *catches, size_t n);
  uint32_t (*s_throw) (void *ctx, idakit_ea_t ea, uint32_t expr /* or IDAKIT_NONE */);
  uint32_t (*s_empty) (void *ctx, idakit_ea_t ea);

  /* types. kind: 0 unknown, 1 void, 2 bool, 3 int, 4 float. */
  uint32_t (*t_scalar)(void *ctx, uint32_t kind, uint32_t bytes, uint32_t is_signed,
                       uint64_t size, uint32_t has_size);
  uint32_t (*t_ptr)   (void *ctx, uint32_t target, uint64_t size, uint32_t has_size);
  uint32_t (*t_array) (void *ctx, uint32_t elem, uint64_t nelems, uint64_t size, uint32_t has_size);
  uint32_t (*t_func)  (void *ctx, uint32_t ret, const uint32_t *params, size_t n, uint32_t vararg);
  /* Reference a named aggregate/typedef; mints (or returns the existing) placeholder so a
   * recursive member can point back before the definition is filled. */
  uint32_t (*t_named_ref)(void *ctx, const char *name, size_t name_len);
  /* Mint an anonymous (un-deduped) placeholder for an unnamed struct/union/enum. */
  uint32_t (*t_anon)  (void *ctx);
  /* Fill a placeholder `id` minted by t_named_ref/t_anon. */
  void (*t_fill_struct)(void *ctx, uint32_t id, uint32_t is_union,
                        const idakit_member_t *members, size_t n, uint64_t size, uint32_t has_size);
  void (*t_fill_enum) (void *ctx, uint32_t id, uint32_t underlying,
                       const idakit_enum_const_t *consts, size_t n, uint64_t size, uint32_t has_size);
  void (*t_fill_typedef)(void *ctx, uint32_t id, uint32_t underlying);

  /* locals. Append one lvar; the call order is the lvar index that `e_var.idx` refers to. flags:
   * bit0 is_arg, bit1 is_result, bit2 is_byref. loc_kind: 0 other, 1 register, 2 stack. */
  void (*l_lvar)(void *ctx, const char *name, size_t name_len, uint32_t ty, uint32_t flags,
                 uint32_t width, const char *comment, size_t comment_len,
                 uint32_t loc_kind, int64_t loc_val);
} idakit_emit_vtbl_t;

/* Walk `cfunc`'s ctree, driving `vtbl` (with `ctx`) and writing the root statement handle
 * to `*root`. Returns 0 on success, non-zero if `cfunc` is NULL. */
int idakit_cfunc_walk_ctree(void *cfunc, const idakit_emit_vtbl_t *vtbl, void *ctx, uint32_t *root);

#ifdef __cplusplus
}
#endif

#endif /* IDAKIT_FACADE_H */
