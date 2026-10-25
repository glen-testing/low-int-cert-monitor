#include "field_fast.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

void fe_copy_c(fe_t r, const fe_t a, const curve_params_t *cp) { bn_copy(r, a, cp->n); }
void fe_zero_c(fe_t r, const curve_params_t *cp) { bn_zero(r, cp->n); }
int  fe_is_zero_c(const fe_t a, const curve_params_t *cp) { return bn_is_zero(a, cp->n); }
int  fe_cmp_c(const fe_t a, const fe_t b, const curve_params_t *cp) { return bn_cmp(a, b, cp->n); }

void fe_add(fe_t r, const fe_t a, const fe_t b, const curve_params_t *cp) {
    int n = cp->n;
    uint64_t s[BN_MAXLIMBS], p_ext[BN_MAXLIMBS];
    s[n] = bn_add_n(s, a, b, n);
    bn_copy(p_ext, cp->p, n); p_ext[n] = 0;
    if (bn_cmp(s, p_ext, n + 1) >= 0) bn_sub_n(s, s, p_ext, n + 1);
    bn_copy(r, s, n);
}

void fe_sub(fe_t r, const fe_t a, const fe_t b, const curve_params_t *cp) {
    int n = cp->n;
    if (bn_cmp(a, b, n) >= 0) {
        bn_sub_n(r, a, b, n);
    } else {
        uint64_t tmp[BN_MAXLIMBS], bext[BN_MAXLIMBS], res[BN_MAXLIMBS];
        tmp[n] = bn_add_n(tmp, a, cp->p, n); // a + p, fits in n+1 limbs
        bn_copy(bext, b, n); bext[n] = 0;
        bn_sub_n(res, tmp, bext, n + 1);
        bn_copy(r, res, n);
    }
}

void fe_neg(fe_t r, const fe_t a, const curve_params_t *cp) {
    if (fe_is_zero_c(a, cp)) { fe_zero_c(r, cp); return; }
    bn_sub_n(r, cp->p, a, cp->n);
}

// ---- Barrett reduction (P-256 / P-384): x (2n limbs) -> r (n limbs) mod p ----
static void barrett_reduce(fe_t r, const uint64_t *x, const curve_params_t *cp) {
    int n = cp->n;
    const uint64_t *q1 = &x[n - 1];               // length n+1
    uint64_t q2[BN_MAXLIMBS];
    bn_mul(q2, q1, n + 1, cp->mu, n + 1);           // length 2n+2
    const uint64_t *q3 = &q2[n + 1];                // length n+1
    uint64_t prod[BN_MAXLIMBS];
    bn_mul(prod, q3, n + 1, cp->p, n);               // length 2n+1
    uint64_t rr[BN_MAXLIMBS];
    bn_sub_n(rr, x, prod, n + 1);                    // low n+1 limbs; wraparound == "+b^(n+1)" per HAC 14.42
    uint64_t p_ext[BN_MAXLIMBS];
    bn_copy(p_ext, cp->p, n); p_ext[n] = 0;
    int guard = 0;
    while (bn_cmp(rr, p_ext, n + 1) >= 0) {
        bn_sub_n(rr, rr, p_ext, n + 1);
        if (++guard > 8) { fprintf(stderr, "FATAL: barrett_reduce did not converge (curve %s)\n", cp->name); abort(); }
    }
    bn_copy(r, rr, n);
}

// ---- Mersenne reduction (P-521): p = 2^521 - 1 ----
static void mersenne521_reduce(fe_t r, const uint64_t *x /*18 limbs*/, const curve_params_t *cp) {
    uint64_t val[BN_MAXLIMBS];
    bn_zero(val, BN_MAXLIMBS);
    memcpy(val, x, 18 * sizeof(uint64_t));

    for (int round = 0; round < 2; round++) {
        uint64_t H[BN_MAXLIMBS], L[9];
        bn_zero(H, BN_MAXLIMBS);
        // H_pre = val[8 .. 23]  (len 16), then >>9 bits -> H
        bn_shr_bits(H, &val[8], 16, 9);
        for (int i = 0; i < 8; i++) L[i] = val[i];
        L[8] = val[8] & 0x1FFULL;
        uint64_t Lw[BN_MAXLIMBS]; bn_zero(Lw, BN_MAXLIMBS);
        memcpy(Lw, L, 9 * sizeof(uint64_t));
        bn_add_n(val, Lw, H, BN_MAXLIMBS - 1); // headroom limb stays 0 (values are small by construction)
    }
    // final cleanup: val now <= ~p+small; subtract p (9 limbs, rest 0) while >=
    uint64_t p_ext[BN_MAXLIMBS]; bn_zero(p_ext, BN_MAXLIMBS);
    bn_copy(p_ext, cp->p, 9);
    int guard = 0;
    while (bn_cmp(val, p_ext, BN_MAXLIMBS) >= 0) {
        bn_sub_n(val, val, p_ext, BN_MAXLIMBS);
        if (++guard > 8) { fprintf(stderr, "FATAL: mersenne521_reduce did not converge\n"); abort(); }
    }
    bn_copy(r, val, 9);
}

void fe_mul(fe_t r, const fe_t a, const fe_t b, const curve_params_t *cp) {
    int n = cp->n;
    uint64_t x[BN_MAXLIMBS];
    bn_mul(x, a, n, b, n); // length 2n
    if (cp->is_mersenne) mersenne521_reduce(r, x, cp);
    else barrett_reduce(r, x, cp);
}

void fe_inv(fe_t r, const fe_t a, const curve_params_t *cp) {
    mpz_t A, P, R;
    mpz_init(A); mpz_init(R);
    mpz_import(A, cp->n, -1, sizeof(uint64_t), 0, 0, a);
    mpz_init_set(P, cp->P);
    if (mpz_sgn(A) == 0) { fe_zero_c(r, cp); mpz_clear(A); mpz_clear(P); mpz_clear(R); return; }
    if (mpz_invert(R, A, P) == 0) { fprintf(stderr, "FATAL: fe_inv: not invertible\n"); abort(); }
    bn_zero(r, cp->n);
    size_t count = 0;
    mpz_export(r, &count, -1, sizeof(uint64_t), 0, 0, R);
    mpz_clear(A); mpz_clear(P); mpz_clear(R);
}

// ---- validation against GMP ----
static void limbs_to_mpz(mpz_t out, const uint64_t *a, int n) { mpz_import(out, n, -1, sizeof(uint64_t), 0, 0, a); }

int field_fast_selftest(const curve_params_t *cp, int trials) {
    mpz_t A, B, Rm, Rref, tmp;
    mpz_init(A); mpz_init(B); mpz_init(Rm); mpz_init(Rref); mpz_init(tmp);
    gmp_randstate_t st; gmp_randinit_mt(st);
    gmp_randseed_ui(st, 0xC0FFEEu ^ (unsigned)cp->n);

    for (int t = 0; t < trials; t++) {
        mpz_urandomm(A, st, cp->P);
        mpz_urandomm(B, st, cp->P);
        fe_t a, b, r;
        bn_zero(a, cp->n); bn_zero(b, cp->n);
        size_t cnt;
        mpz_export(a, &cnt, -1, sizeof(uint64_t), 0, 0, A);
        mpz_export(b, &cnt, -1, sizeof(uint64_t), 0, 0, B);

        // mul
        fe_mul(r, a, b, cp);
        limbs_to_mpz(Rm, r, cp->n);
        mpz_mul(tmp, A, B); mpz_mod(Rref, tmp, cp->P);
        if (mpz_cmp(Rm, Rref) != 0) {
            fprintf(stderr, "MISMATCH fe_mul curve=%s trial=%d\n", cp->name, t);
            gmp_fprintf(stderr, "A=%Zx\nB=%Zx\ngot=%Zx\nwant=%Zx\n", A, B, Rm, Rref);
            return 0;
        }
        // add
        fe_add(r, a, b, cp);
        limbs_to_mpz(Rm, r, cp->n);
        mpz_add(tmp, A, B); mpz_mod(Rref, tmp, cp->P);
        if (mpz_cmp(Rm, Rref) != 0) { fprintf(stderr, "MISMATCH fe_add curve=%s trial=%d\n", cp->name, t); return 0; }
        // sub
        fe_sub(r, a, b, cp);
        limbs_to_mpz(Rm, r, cp->n);
        mpz_sub(tmp, A, B); mpz_mod(Rref, tmp, cp->P);
        if (mpz_cmp(Rm, Rref) != 0) { fprintf(stderr, "MISMATCH fe_sub curve=%s trial=%d\n", cp->name, t); return 0; }
        // inv (only every 50th trial - GMP invert cost)
        if (t % 50 == 0 && mpz_sgn(A) != 0) {
            fe_inv(r, a, cp);
            limbs_to_mpz(Rm, r, cp->n);
            mpz_invert(Rref, A, cp->P);
            if (mpz_cmp(Rm, Rref) != 0) { fprintf(stderr, "MISMATCH fe_inv curve=%s trial=%d\n", cp->name, t); return 0; }
        }
    }
    gmp_randclear(st);
    mpz_clear(A); mpz_clear(B); mpz_clear(Rm); mpz_clear(Rref); mpz_clear(tmp);
    return 1;
}
