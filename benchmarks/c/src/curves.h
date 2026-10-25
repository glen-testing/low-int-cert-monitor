// Curve parameter tables for P-256, P-384, P-521 (NIST primes, a = -3).
// GMP is used only here, at startup, to parse hex constants and derive the
// Barrett constant 'mu' -- never in the hot-path field arithmetic.
#ifndef CURVES_H
#define CURVES_H
#include <stdint.h>
#include <gmp.h>
#include "bn.h"

typedef enum { CURVE_P256 = 0, CURVE_P384 = 1, CURVE_P521 = 2, CURVE_COUNT = 3 } curve_id_t;

typedef struct {
    const char *name;
    int bits;          // 256, 384, 521
    int n;              // limb count for field elements (4, 6, 9)
    uint64_t p[BN_MAXLIMBS];
    uint64_t b[BN_MAXLIMBS];
    uint64_t gx[BN_MAXLIMBS];
    uint64_t gy[BN_MAXLIMBS];
    uint64_t mu[BN_MAXLIMBS];   // Barrett mu, n+1 limbs valid (P256/P384 only)
    int is_mersenne;            // 1 for P521 (p = 2^521 - 1)

    // GMP forms, kept for the gmp-backed variant and for cross-validation.
    mpz_t P, B, GX, GY, ORDER;
} curve_params_t;

extern curve_params_t g_curves[CURVE_COUNT];

void curves_init(void);
curve_id_t curve_by_name(const char *name); // "P-256" etc, returns -1-based error via int cast guard
int curve_name_to_id(const char *name, curve_id_t *out);

#endif
