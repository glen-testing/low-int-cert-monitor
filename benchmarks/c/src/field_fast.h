// Hand-rolled field arithmetic mod p, specialized per curve:
//  - P-256 / P-384 (generalized-Mersenne / Solinas primes): Barrett reduction
//    with a precomputed per-curve constant 'mu' (hand-rolled multiply/shift/sub,
//    no GMP calls at runtime).
//  - P-521 (p = 2^521-1, true Mersenne prime): direct shift-and-add fold,
//    no multiply needed in the reduction at all.
// fe_inv (needed only once per Montgomery batch) is the one exception that
// shells out to GMP mpz_invert, since it is called O(1) times per block of
// points and its own speed is irrelevant to the ns/add metric.
#ifndef FIELD_FAST_H
#define FIELD_FAST_H
#include "bn.h"
#include "curves.h"

typedef uint64_t fe_t[BN_MAXLIMBS];

void fe_copy_c(fe_t r, const fe_t a, const curve_params_t *cp);
void fe_zero_c(fe_t r, const curve_params_t *cp);
int  fe_is_zero_c(const fe_t a, const curve_params_t *cp);
int  fe_cmp_c(const fe_t a, const fe_t b, const curve_params_t *cp);

void fe_add(fe_t r, const fe_t a, const fe_t b, const curve_params_t *cp);
void fe_sub(fe_t r, const fe_t a, const fe_t b, const curve_params_t *cp);
void fe_neg(fe_t r, const fe_t a, const curve_params_t *cp);
void fe_mul(fe_t r, const fe_t a, const fe_t b, const curve_params_t *cp);
static inline void fe_sqr(fe_t r, const fe_t a, const curve_params_t *cp) { fe_mul(r, a, a, cp); }
void fe_inv(fe_t r, const fe_t a, const curve_params_t *cp); // rare path, uses GMP internally

// Cross-check the hand-rolled field ops against GMP for `trials` random values.
// Returns 1 if all match, 0 on first mismatch (prints details to stderr).
int field_fast_selftest(const curve_params_t *cp, int trials);

#endif
