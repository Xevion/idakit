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
int     idakit_type_member(void *h, size_t i, char *namebuf, size_t namecap,
                           uint64_t *offset, uint64_t *size,       /* both in BYTES */
                           char *typebuf, size_t typecap);

int   idakit_hexrays_init(void);                       /* 1 = decompiler ready, 0 = unavailable */
void *idakit_decompile(idakit_ea_t ea);                /* opaque cfunc handle (owns a ref), NULL on fail */
void  idakit_cfunc_dispose(void *cfunc);
int64_t idakit_cfunc_pseudocode(void *cfunc, char *buf, size_t cap); /* tag-stripped text length */
void  idakit_cfunc_ctree_counts(void *cfunc, int *n_insn, int *n_expr, int *n_calls);

#ifdef __cplusplus
}
#endif

#endif /* IDAKIT_FACADE_H */
