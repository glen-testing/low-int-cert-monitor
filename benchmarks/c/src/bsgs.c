#include "bsgs.h"
#include <math.h>
#include <stdlib.h>
#include <stdio.h>

void bsgs_build(bsgs_ctx_t *ctx, const curve_params_t *cp, uint64_t max_d) {
    ctx->cp = cp;
    uint64_t M = (uint64_t)ceil(sqrt((double)max_d)) + 1;
    ctx->M = M;

    affine_t g = {0};
    fe_copy_c(g.x, cp->gx, cp);
    fe_copy_c(g.y, cp->gy, cp);

    // Build j*G for j = 1 .. M-1 as Jacobian points, bootstrap-doubling once
    // to avoid the P==Q edge case on the very first mixed-add (j=1 -> j=2).
    jac_t *jpts = malloc(sizeof(jac_t) * M); // index 1..M-1 used
    jac_from_affine(&jpts[1], &g, cp);
    if (M > 2) point_double_jac(&jpts[2], &jpts[1], cp);
    for (uint64_t j = 3; j < M; j++) point_add_mixed(&jpts[j], &jpts[j - 1], &g, cp);

    ctx->baby_affine = malloc(sizeof(affine_t) * M);
    batch_normalize(&ctx->baby_affine[1], &jpts[1], (int)(M - 1), cp);
    free(jpts);

    bt_init(&ctx->table, (size_t)M);
    for (uint64_t j = 1; j < M; j++) bt_insert(&ctx->table, ctx->baby_affine[j].x, j, cp);

    // stride = M*G, we need -(M*G) for the giant-step subtraction loop.
    jac_t stride_jac;
    point_mul_u64(&stride_jac, M, cp);
    affine_t stride_affine;
    batch_normalize(&stride_affine, &stride_jac, 1, cp);
    affine_neg(&ctx->neg_stride, &stride_affine, cp);
}

void bsgs_free(bsgs_ctx_t *ctx) {
    bt_free(&ctx->table);
    free(ctx->baby_affine);
}

int bsgs_search(bsgs_ctx_t *ctx, const affine_t *target, uint64_t *d_out) {
    const curve_params_t *cp = ctx->cp;
    uint64_t M = ctx->M;

    jac_t *giant = malloc(sizeof(jac_t) * M);
    jac_from_affine(&giant[0], target, cp);
    for (uint64_t i = 1; i < M; i++) point_add_mixed(&giant[i], &giant[i - 1], &ctx->neg_stride, cp);

    for (uint64_t i = 0; i < M; i++) {
        if (jac_is_infinity(&giant[i], cp)) {
            uint64_t cand = i * M;
            if (cand >= 1) { *d_out = cand; free(giant); return 1; }
        }
    }

    affine_t *aff = malloc(sizeof(affine_t) * M);
    batch_normalize(aff, giant, (int)M, cp);
    free(giant);

    int found = 0;
    uint64_t result = 0;
    for (uint64_t i = 0; i < M && !found; i++) {
        if (fe_is_zero_c(aff[i].x, cp) && fe_is_zero_c(aff[i].y, cp)) continue; // infinity placeholder, handled above
        uint64_t j;
        if (!bt_lookup(&ctx->table, aff[i].x, &j, cp)) continue;
        int64_t cand;
        if (bn_cmp(aff[i].y, ctx->baby_affine[j].y, cp->n) == 0) {
            cand = (int64_t)(i * M + j);
        } else {
            fe_t neg_y; fe_neg(neg_y, ctx->baby_affine[j].y, cp);
            if (bn_cmp(aff[i].y, neg_y, cp->n) != 0) {
                fprintf(stderr, "FATAL: BSGS internal inconsistency (x matched but y is neither +/-)\n");
                abort();
            }
            cand = (int64_t)(i * M) - (int64_t)j;
        }
        if (cand >= 1) { result = (uint64_t)cand; found = 1; }
    }
    free(aff);
    if (found) { *d_out = result; return 1; }
    return 0;
}
