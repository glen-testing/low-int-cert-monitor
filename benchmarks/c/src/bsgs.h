// BSGS: baby table (hash set) + giant steps, layered on the fast field/point
// arithmetic (point_fast.h). Baby table covers j in [1, M-1]; giant steps
// cover i in [0, M-1] with stride M*G, so d = i*M (+/-) j covers [1, M*M-1].
#ifndef BSGS_H
#define BSGS_H
#include "point_fast.h"
#include "babytable.h"

typedef struct {
    uint64_t M;
    babytable_t table;
    affine_t *baby_affine;   // size M, index 0 unused
    affine_t neg_stride;     // -(M*G), affine
    const curve_params_t *cp;
} bsgs_ctx_t;

void bsgs_build(bsgs_ctx_t *ctx, const curve_params_t *cp, uint64_t max_d);
void bsgs_free(bsgs_ctx_t *ctx);

// Searches d in [1, max_d] (max_d <= the value passed to bsgs_build) with
// d*G == target. Returns 1 and sets *d_out on a hit, else 0.
int bsgs_search(bsgs_ctx_t *ctx, const affine_t *target, uint64_t *d_out);

#endif
