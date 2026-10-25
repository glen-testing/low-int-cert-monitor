// Generic GMP mpz_t field arithmetic mod p -- the "generic/GMP path" comparison
// point against the hand-rolled fast field (field_fast.h). mpz_mod here goes
// through GMP's general-purpose division, not a curve-specialized reduction.
#ifndef FIELD_GMP_H
#define FIELD_GMP_H
#include <gmp.h>
#include "curves.h"

static inline void feg_add(mpz_t r, const mpz_t a, const mpz_t b, const curve_params_t *cp) {
    mpz_add(r, a, b);
    if (mpz_cmp(r, cp->P) >= 0) mpz_sub(r, r, cp->P);
}
static inline void feg_sub(mpz_t r, const mpz_t a, const mpz_t b, const curve_params_t *cp) {
    mpz_sub(r, a, b);
    if (mpz_sgn(r) < 0) mpz_add(r, r, cp->P);
}
static inline void feg_mul(mpz_t r, const mpz_t a, const mpz_t b, const curve_params_t *cp) {
    mpz_mul(r, a, b);
    mpz_mod(r, r, cp->P);
}
static inline void feg_sqr(mpz_t r, const mpz_t a, const curve_params_t *cp) { feg_mul(r, a, a, cp); }
static inline void feg_neg(mpz_t r, const mpz_t a, const curve_params_t *cp) {
    if (mpz_sgn(a) == 0) { mpz_set_ui(r, 0); return; }
    mpz_sub(r, cp->P, a);
}
static inline void feg_inv(mpz_t r, const mpz_t a, const curve_params_t *cp) { mpz_invert(r, a, cp->P); }

#endif
