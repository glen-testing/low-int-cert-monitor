#include "point_gmp.h"
#include "field_gmp.h"
#include <stdlib.h>

void jacg_init(jac_gmp_t *p) { mpz_init(p->X); mpz_init(p->Y); mpz_init(p->Z); }
void jacg_clear(jac_gmp_t *p) { mpz_clear(p->X); mpz_clear(p->Y); mpz_clear(p->Z); }
void affg_init(affine_gmp_t *p) { mpz_init(p->x); mpz_init(p->y); p->inf = 0; }
void affg_clear(affine_gmp_t *p) { mpz_clear(p->x); mpz_clear(p->y); }

void jacg_from_affine(jac_gmp_t *R, const affine_gmp_t *P, const curve_params_t *cp) {
    (void)cp;
    mpz_set(R->X, P->x);
    mpz_set(R->Y, P->y);
    mpz_set_ui(R->Z, 1);
}
int jacg_is_infinity(const jac_gmp_t *P) { return mpz_sgn(P->Z) == 0; }
void jacg_set_infinity(jac_gmp_t *R, const curve_params_t *cp) { (void)cp; mpz_set_ui(R->X, 0); mpz_set_ui(R->Y, 0); mpz_set_ui(R->Z, 0); }

void point_double_jacg(jac_gmp_t *R, const jac_gmp_t *P, const curve_params_t *cp) {
    if (jacg_is_infinity(P)) { jacg_set_infinity(R, cp); return; }
    mpz_t delta, gamma, beta, alpha, t1, t2, t3;
    mpz_init(delta); mpz_init(gamma); mpz_init(beta); mpz_init(alpha);
    mpz_init(t1); mpz_init(t2); mpz_init(t3);

    feg_sqr(delta, P->Z, cp);
    feg_sqr(gamma, P->Y, cp);
    feg_mul(beta, P->X, gamma, cp);
    feg_sub(t1, P->X, delta, cp);
    feg_add(t2, P->X, delta, cp);
    feg_mul(t3, t1, t2, cp);
    feg_add(alpha, t3, t3, cp); feg_add(alpha, alpha, t3, cp);

    mpz_t alpha2, beta8, X3;
    mpz_init(alpha2); mpz_init(beta8); mpz_init(X3);
    feg_sqr(alpha2, alpha, cp);
    feg_add(beta8, beta, beta, cp); feg_add(beta8, beta8, beta8, cp); feg_add(beta8, beta8, beta8, cp);
    feg_sub(X3, alpha2, beta8, cp);

    mpz_t yz, yz2, z3;
    mpz_init(yz); mpz_init(yz2); mpz_init(z3);
    feg_add(yz, P->Y, P->Z, cp);
    feg_sqr(yz2, yz, cp);
    feg_sub(z3, yz2, gamma, cp);
    feg_sub(z3, z3, delta, cp);

    mpz_t four_beta, diff, y3, gamma2, gamma2_8;
    mpz_init(four_beta); mpz_init(diff); mpz_init(y3); mpz_init(gamma2); mpz_init(gamma2_8);
    feg_add(four_beta, beta, beta, cp); feg_add(four_beta, four_beta, four_beta, cp);
    feg_sub(diff, four_beta, X3, cp);
    feg_mul(y3, alpha, diff, cp);
    feg_sqr(gamma2, gamma, cp);
    feg_add(gamma2_8, gamma2, gamma2, cp); feg_add(gamma2_8, gamma2_8, gamma2_8, cp); feg_add(gamma2_8, gamma2_8, gamma2_8, cp);
    feg_sub(y3, y3, gamma2_8, cp);

    mpz_set(R->X, X3); mpz_set(R->Y, y3); mpz_set(R->Z, z3);

    mpz_clear(delta); mpz_clear(gamma); mpz_clear(beta); mpz_clear(alpha);
    mpz_clear(t1); mpz_clear(t2); mpz_clear(t3);
    mpz_clear(alpha2); mpz_clear(beta8); mpz_clear(X3);
    mpz_clear(yz); mpz_clear(yz2); mpz_clear(z3);
    mpz_clear(four_beta); mpz_clear(diff); mpz_clear(y3); mpz_clear(gamma2); mpz_clear(gamma2_8);
}

void point_add_mixed_g(jac_gmp_t *R, const jac_gmp_t *P, const affine_gmp_t *Q, const curve_params_t *cp) {
    if (jacg_is_infinity(P)) { jacg_from_affine(R, Q, cp); return; }

    mpz_t Z1Z1, U2, S2, H, r, Z1Z1Z1, Sdiff;
    mpz_init(Z1Z1); mpz_init(U2); mpz_init(S2); mpz_init(H); mpz_init(r); mpz_init(Z1Z1Z1); mpz_init(Sdiff);

    feg_sqr(Z1Z1, P->Z, cp);
    feg_mul(U2, Q->x, Z1Z1, cp);
    feg_mul(Z1Z1Z1, P->Z, Z1Z1, cp);
    feg_mul(S2, Q->y, Z1Z1Z1, cp);
    feg_sub(H, U2, P->X, cp);
    feg_sub(Sdiff, S2, P->Y, cp);
    feg_add(r, Sdiff, Sdiff, cp);

    if (mpz_sgn(H) == 0) {
        if (mpz_sgn(r) == 0) point_double_jacg(R, P, cp);
        else jacg_set_infinity(R, cp);
        mpz_clear(Z1Z1); mpz_clear(U2); mpz_clear(S2); mpz_clear(H); mpz_clear(r); mpz_clear(Z1Z1Z1); mpz_clear(Sdiff);
        return;
    }

    mpz_t HH, I, J, V, X3, Y3, Z3, r2, twoV, VminusX3, twoY1J;
    mpz_init(HH); mpz_init(I); mpz_init(J); mpz_init(V); mpz_init(X3); mpz_init(Y3); mpz_init(Z3);
    mpz_init(r2); mpz_init(twoV); mpz_init(VminusX3); mpz_init(twoY1J);

    feg_sqr(HH, H, cp);
    feg_add(I, HH, HH, cp); feg_add(I, I, I, cp);
    feg_mul(J, H, I, cp);
    feg_mul(V, P->X, I, cp);
    feg_sqr(r2, r, cp);
    feg_add(twoV, V, V, cp);
    feg_sub(X3, r2, J, cp);
    feg_sub(X3, X3, twoV, cp);
    feg_sub(VminusX3, V, X3, cp);
    feg_mul(Y3, r, VminusX3, cp);
    feg_mul(twoY1J, P->Y, J, cp); feg_add(twoY1J, twoY1J, twoY1J, cp);
    feg_sub(Y3, Y3, twoY1J, cp);
    feg_mul(Z3, P->Z, H, cp); feg_add(Z3, Z3, Z3, cp);

    mpz_set(R->X, X3); mpz_set(R->Y, Y3); mpz_set(R->Z, Z3);

    mpz_clear(Z1Z1); mpz_clear(U2); mpz_clear(S2); mpz_clear(H); mpz_clear(r); mpz_clear(Z1Z1Z1); mpz_clear(Sdiff);
    mpz_clear(HH); mpz_clear(I); mpz_clear(J); mpz_clear(V); mpz_clear(X3); mpz_clear(Y3); mpz_clear(Z3);
    mpz_clear(r2); mpz_clear(twoV); mpz_clear(VminusX3); mpz_clear(twoY1J);
}

void batch_normalize_g(affine_gmp_t *out, const jac_gmp_t *pts, int count, const curve_params_t *cp) {
    if (count <= 0) return;
    mpz_t *prefix = malloc(sizeof(mpz_t) * count);
    for (int i = 0; i < count; i++) mpz_init(prefix[i]);
    mpz_t cur; mpz_init_set_ui(cur, 1);
    for (int i = 0; i < count; i++) {
        if (mpz_sgn(pts[i].Z) != 0) feg_mul(cur, cur, pts[i].Z, cp);
        mpz_set(prefix[i], cur);
    }
    mpz_t inv_all, running_inv;
    mpz_init(inv_all); mpz_init(running_inv);
    feg_inv(inv_all, cur, cp);
    mpz_set(running_inv, inv_all);

    mpz_t zinv, zinv2, zinv3, newrun;
    mpz_init(zinv); mpz_init(zinv2); mpz_init(zinv3); mpz_init(newrun);
    for (int i = count - 1; i >= 0; i--) {
        if (mpz_sgn(pts[i].Z) == 0) { mpz_set_ui(out[i].x, 0); mpz_set_ui(out[i].y, 0); continue; }
        if (i == 0) mpz_set(zinv, running_inv);
        else feg_mul(zinv, running_inv, prefix[i - 1], cp);
        feg_mul(newrun, running_inv, pts[i].Z, cp);
        mpz_set(running_inv, newrun);

        feg_sqr(zinv2, zinv, cp);
        feg_mul(zinv3, zinv2, zinv, cp);
        feg_mul(out[i].x, pts[i].X, zinv2, cp);
        feg_mul(out[i].y, pts[i].Y, zinv3, cp);
    }
    mpz_clear(zinv); mpz_clear(zinv2); mpz_clear(zinv3); mpz_clear(newrun);
    mpz_clear(inv_all); mpz_clear(running_inv);
    mpz_clear(cur);
    for (int i = 0; i < count; i++) mpz_clear(prefix[i]);
    free(prefix);
}

// ---- baseline: plain affine + per-step modular inverse ----
void affine_double_g(affine_gmp_t *R, const affine_gmp_t *P, const curve_params_t *cp) {
    mpz_t x1sq, num, den, deninv, lambda, x3, y3;
    mpz_init(x1sq); mpz_init(num); mpz_init(den); mpz_init(deninv); mpz_init(lambda); mpz_init(x3); mpz_init(y3);
    feg_sqr(x1sq, P->x, cp);
    feg_add(num, x1sq, x1sq, cp); feg_add(num, num, x1sq, cp); // 3*x1^2
    mpz_t three; mpz_init_set_ui(three, 3);
    feg_sub(num, num, three, cp); // 3*x1^2 - 3  (a = -3)
    feg_add(den, P->y, P->y, cp); // 2*y1
    feg_inv(deninv, den, cp);     // per-step modular inverse
    feg_mul(lambda, num, deninv, cp);
    feg_sqr(x3, lambda, cp);
    feg_sub(x3, x3, P->x, cp); feg_sub(x3, x3, P->x, cp);
    feg_sub(y3, P->x, x3, cp);
    feg_mul(y3, lambda, y3, cp);
    feg_sub(y3, y3, P->y, cp);
    mpz_set(R->x, x3); mpz_set(R->y, y3); R->inf = 0;
    mpz_clear(x1sq); mpz_clear(num); mpz_clear(den); mpz_clear(deninv); mpz_clear(lambda); mpz_clear(x3); mpz_clear(y3);
    mpz_clear(three);
}

void affine_add_g(affine_gmp_t *R, const affine_gmp_t *P, const affine_gmp_t *Q, const curve_params_t *cp) {
    if (P->inf) { mpz_set(R->x, Q->x); mpz_set(R->y, Q->y); R->inf = Q->inf; return; }
    if (Q->inf) { mpz_set(R->x, P->x); mpz_set(R->y, P->y); R->inf = P->inf; return; }
    if (mpz_cmp(P->x, Q->x) == 0) {
        mpz_t ysum; mpz_init(ysum);
        feg_add(ysum, P->y, Q->y, cp);
        if (mpz_sgn(ysum) == 0) { R->inf = 1; mpz_set_ui(R->x, 0); mpz_set_ui(R->y, 0); mpz_clear(ysum); return; }
        mpz_clear(ysum);
        affine_double_g(R, P, cp);
        return;
    }
    mpz_t num, den, deninv, lambda, x3, y3;
    mpz_init(num); mpz_init(den); mpz_init(deninv); mpz_init(lambda); mpz_init(x3); mpz_init(y3);
    feg_sub(num, Q->y, P->y, cp);
    feg_sub(den, Q->x, P->x, cp);
    feg_inv(deninv, den, cp); // per-step modular inverse -- this is the baseline's defining cost
    feg_mul(lambda, num, deninv, cp);
    feg_sqr(x3, lambda, cp);
    feg_sub(x3, x3, P->x, cp);
    feg_sub(x3, x3, Q->x, cp);
    feg_sub(y3, P->x, x3, cp);
    feg_mul(y3, lambda, y3, cp);
    feg_sub(y3, y3, P->y, cp);
    mpz_set(R->x, x3); mpz_set(R->y, y3); R->inf = 0;
    mpz_clear(num); mpz_clear(den); mpz_clear(deninv); mpz_clear(lambda); mpz_clear(x3); mpz_clear(y3);
}
