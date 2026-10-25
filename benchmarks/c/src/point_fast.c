#include "point_fast.h"
#include <string.h>
#include <stdlib.h>

void jac_from_affine(jac_t *R, const affine_t *P, const curve_params_t *cp) {
    fe_copy_c(R->X, P->x, cp);
    fe_copy_c(R->Y, P->y, cp);
    fe_zero_c(R->Z, cp);
    R->Z[0] = 1;
}

int jac_is_infinity(const jac_t *P, const curve_params_t *cp) { return fe_is_zero_c(P->Z, cp); }
void jac_set_infinity(jac_t *R, const curve_params_t *cp) {
    fe_zero_c(R->X, cp); fe_zero_c(R->Y, cp); fe_zero_c(R->Z, cp);
}

void affine_neg(affine_t *R, const affine_t *P, const curve_params_t *cp) {
    fe_copy_c(R->x, P->x, cp);
    fe_neg(R->y, P->y, cp);
}

// dbl-2001-b, a = -3.
void point_double_jac(jac_t *R, const jac_t *P, const curve_params_t *cp) {
    if (jac_is_infinity(P, cp)) { jac_set_infinity(R, cp); return; }
    fe_t delta, gamma, beta, alpha, t1, t2, t3;
    fe_sqr(delta, P->Z, cp);                       // delta = Z1^2
    fe_sqr(gamma, P->Y, cp);                        // gamma = Y1^2
    fe_mul(beta, P->X, gamma, cp);                  // beta = X1*gamma
    fe_sub(t1, P->X, delta, cp);                    // X1-delta
    fe_add(t2, P->X, delta, cp);                    // X1+delta
    fe_mul(t3, t1, t2, cp);                         // (X1-delta)(X1+delta)
    fe_add(alpha, t3, t3, cp); fe_add(alpha, alpha, t3, cp); // alpha = 3*t3

    fe_t alpha2, beta8, X3;
    fe_sqr(alpha2, alpha, cp);
    fe_add(beta8, beta, beta, cp);      // 2b
    fe_add(beta8, beta8, beta8, cp);    // 4b
    fe_add(beta8, beta8, beta8, cp);    // 8b
    fe_sub(X3, alpha2, beta8, cp);

    fe_t yz, yz2, z3;
    fe_add(yz, P->Y, P->Z, cp);
    fe_sqr(yz2, yz, cp);
    fe_sub(z3, yz2, gamma, cp);
    fe_sub(z3, z3, delta, cp);

    fe_t four_beta, diff, y3, gamma2, gamma2_8;
    fe_add(four_beta, beta, beta, cp); fe_add(four_beta, four_beta, four_beta, cp); // 4*beta
    fe_sub(diff, four_beta, X3, cp);
    fe_mul(y3, alpha, diff, cp);
    fe_sqr(gamma2, gamma, cp);
    fe_add(gamma2_8, gamma2, gamma2, cp); fe_add(gamma2_8, gamma2_8, gamma2_8, cp);
    fe_add(gamma2_8, gamma2_8, gamma2_8, cp); // 8*gamma^2
    fe_sub(y3, y3, gamma2_8, cp);

    fe_copy_c(R->X, X3, cp);
    fe_copy_c(R->Y, y3, cp);
    fe_copy_c(R->Z, z3, cp);
}

// madd-2007-bl (Z2=1), with explicit handling for P==+-Q.
void point_add_mixed(jac_t *R, const jac_t *P, const affine_t *Q, const curve_params_t *cp) {
    if (jac_is_infinity(P, cp)) { jac_from_affine(R, Q, cp); return; }

    fe_t Z1Z1, U2, S2, H, r;
    fe_sqr(Z1Z1, P->Z, cp);
    fe_mul(U2, Q->x, Z1Z1, cp);
    fe_t Z1Z1Z1;
    fe_mul(Z1Z1Z1, P->Z, Z1Z1, cp);
    fe_mul(S2, Q->y, Z1Z1Z1, cp);
    fe_sub(H, U2, P->X, cp);
    fe_t Sdiff;
    fe_sub(Sdiff, S2, P->Y, cp);
    fe_add(r, Sdiff, Sdiff, cp); // r = 2*(S2-Y1)

    if (fe_is_zero_c(H, cp)) {
        if (fe_is_zero_c(r, cp)) {
            // P == Q: double P (equivalently double Q lifted to Jacobian via P itself)
            point_double_jac(R, P, cp);
        } else {
            // P == -Q: result is point at infinity
            jac_set_infinity(R, cp);
        }
        return;
    }

    fe_t HH, I, J, V, X3, Y3, Z3;
    fe_sqr(HH, H, cp);
    fe_add(I, HH, HH, cp); fe_add(I, I, I, cp);       // I = 4*HH
    fe_mul(J, H, I, cp);
    fe_mul(V, P->X, I, cp);

    fe_t r2, twoV;
    fe_sqr(r2, r, cp);
    fe_add(twoV, V, V, cp);
    fe_sub(X3, r2, J, cp);
    fe_sub(X3, X3, twoV, cp);

    fe_t VminusX3, twoY1J;
    fe_sub(VminusX3, V, X3, cp);
    fe_mul(Y3, r, VminusX3, cp);
    fe_mul(twoY1J, P->Y, J, cp);
    fe_add(twoY1J, twoY1J, twoY1J, cp);
    fe_sub(Y3, Y3, twoY1J, cp);

    fe_mul(Z3, P->Z, H, cp);
    fe_add(Z3, Z3, Z3, cp);

    fe_copy_c(R->X, X3, cp);
    fe_copy_c(R->Y, Y3, cp);
    fe_copy_c(R->Z, Z3, cp);
}

void batch_normalize(affine_t *out, const jac_t *pts, int count, const curve_params_t *cp) {
    if (count <= 0) return;
    fe_t *prefix = malloc(sizeof(fe_t) * count);
    // prefix[i] = Z0*Z1*...*Zi  (treat Z==0 as "1" placeholder to keep the chain invertible;
    // those slots are never dereferenced meaningfully by the caller since jac_is_infinity
    // should be checked on the input before relying on the output for that index)
    fe_t cur;
    fe_zero_c(cur, cp); cur[0] = 1;
    for (int i = 0; i < count; i++) {
        const uint64_t *z = pts[i].Z;
        if (!fe_is_zero_c(z, cp)) fe_mul(cur, cur, z, cp);
        fe_copy_c(prefix[i], cur, cp);
    }
    fe_t inv_all;
    fe_inv(inv_all, cur, cp); // single inversion for the whole batch

    fe_t running_inv;
    fe_copy_c(running_inv, inv_all, cp);
    for (int i = count - 1; i >= 0; i--) {
        const uint64_t *z = pts[i].Z;
        if (fe_is_zero_c(z, cp)) {
            fe_zero_c(out[i].x, cp);
            fe_zero_c(out[i].y, cp);
            continue;
        }
        fe_t zinv;
        if (i == 0) {
            fe_copy_c(zinv, running_inv, cp);
        } else {
            fe_mul(zinv, running_inv, prefix[i - 1], cp);
        }
        // update running_inv for next (smaller) i: running_inv *= Z_i  (removes this Z from the chain)
        fe_t new_running;
        fe_mul(new_running, running_inv, z, cp);
        fe_copy_c(running_inv, new_running, cp);

        fe_t zinv2, zinv3;
        fe_sqr(zinv2, zinv, cp);
        fe_mul(zinv3, zinv2, zinv, cp);
        fe_mul(out[i].x, pts[i].X, zinv2, cp);
        fe_mul(out[i].y, pts[i].Y, zinv3, cp);
    }
    free(prefix);
}

void point_mul_u64(jac_t *R, uint64_t d, const curve_params_t *cp) {
    jac_set_infinity(R, cp);
    affine_t g = {0};
    fe_copy_c(g.x, cp->gx, cp);
    fe_copy_c(g.y, cp->gy, cp);
    jac_t base; jac_from_affine(&base, &g, cp);
    jac_t cur = base;
    int started = 0;
    for (int bit = 63; bit >= 0; bit--) {
        if (started) point_double_jac(R, R, cp);
        if ((d >> bit) & 1ULL) {
            if (!started) { *R = cur; started = 1; }
            else point_add_mixed(R, R, &g, cp);
        }
    }
    if (!started) jac_set_infinity(R, cp);
}
