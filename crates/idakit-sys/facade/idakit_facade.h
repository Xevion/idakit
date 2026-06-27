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

size_t      idakit_func_qty(void);
idakit_ea_t idakit_func_ea(size_t n);                              /* start_ea of nth func, or BADADDR */
int64_t     idakit_func_name(idakit_ea_t ea, char *buf, size_t cap); /* name length, <0 on miss */

int     idakit_seg_qty(void);
int64_t idakit_seg_name(int n, char *buf, size_t cap);
idakit_ea_t idakit_seg_start(int n);
idakit_ea_t idakit_seg_end(int n);

int64_t idakit_get_bytes(idakit_ea_t ea, void *buf, size_t size);  /* bytes read, <0 on fail */

/* Explicit xrefs TO ea (ordinary flow excluded). Returns the total count and fills the
 * parallel from/type/iscode arrays up to cap. type is the cref_t/dref_t byte. */
size_t idakit_xrefs_to(idakit_ea_t ea, idakit_ea_t *from, uint8_t *type,
                       uint8_t *iscode, size_t cap);

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

/* Flat ctree extraction. The records mirror idakit-sys's `#[repr(C)]` structs exactly
 * (the static_asserts in the .cpp and the size checks in lib.rs are the tripwire). Field
 * meaning depends on `tag` and is documented in idakit's ctree extract module: `tag` is a
 * `ctype_t` for nodes, references are indices within the matching section, and variadic
 * edges (call args, block bodies, switch cases, asm/case values, strings) point into the
 * side pools. `0xFFFFFFFF` in an optional slot means absent. */
typedef struct { uint64_t ea, aux; uint32_t ty, a, b, c, tag, flags; } idakit_expr_rec_t;
typedef struct { uint64_t ea, aux; uint32_t a, b, c, tag, flags; } idakit_stmt_rec_t;
typedef struct { uint64_t size, aux; uint32_t a, b, tag, bytes, is_signed, has_size; } idakit_type_rec_t;
typedef struct { uint32_t values_off, values_len, body, flags; } idakit_case_rec_t;

/* A view over the extraction's facade-owned arrays; valid until idakit_ctree_dispose. */
typedef struct
{
  const idakit_type_rec_t *types; size_t n_types;
  const idakit_expr_rec_t *exprs; size_t n_exprs;
  const idakit_stmt_rec_t *stmts; size_t n_stmts;
  const uint32_t          *nodes; size_t n_nodes; /* homogeneous index lists */
  const uint8_t           *bytes; size_t n_bytes; /* string bytes */
  const uint64_t          *longs; size_t n_longs; /* asm addrs, switch case values */
  const idakit_case_rec_t *cases; size_t n_cases;
  uint32_t root;                                  /* statement index of the root block */
} idakit_ctree_view_t;

/* Extract `cfunc`'s ctree into a fresh handle and fill `out` with views into it. Returns
 * the handle (owns the storage; release with idakit_ctree_dispose), or NULL if cfunc is
 * NULL. */
void *idakit_cfunc_extract_ctree(void *cfunc, idakit_ctree_view_t *out);
void  idakit_ctree_dispose(void *h);

#ifdef __cplusplus
}
#endif

#endif /* IDAKIT_FACADE_H */
