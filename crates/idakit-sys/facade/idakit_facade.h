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

int   idakit_hexrays_init(void);                       /* 1 = decompiler ready, 0 = unavailable */
void *idakit_decompile(idakit_ea_t ea);                /* opaque cfunc handle (owns a ref), NULL on fail */
void  idakit_cfunc_dispose(void *cfunc);
int64_t idakit_cfunc_pseudocode(void *cfunc, char *buf, size_t cap); /* tag-stripped text length */
void  idakit_cfunc_ctree_counts(void *cfunc, int *n_insn, int *n_expr, int *n_calls);

#ifdef __cplusplus
}
#endif

#endif /* IDAKIT_FACADE_H */
