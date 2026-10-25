// Jacobian point arithmetic over GMP mpz_t (generic field path), and plain
// affine arithmetic with a per-step modular inverse (the spec's baseline #1).
#ifndef POINT_GMP_H
#define POINT_GMP_H
#include <gmp.h>
#include "curves.h"

typedef struct { mpz_t X, Y, Z; } jac_gmp_t;
typedef struct { mpz_t x, y; int inf; } affine_gmp_t;

void jacg_init(jac_gmp_t *p);
void jacg_clear(jac_gmp_t *p);
void affg_init(affine_gmp_t *p);
void affg_clear(affine_gmp_t *p);

void jacg_from_affine(jac_gmp_t *R, const affine_gmp_t *P, const curve_params_t *cp);
int  jacg_is_infinity(const jac_gmp_t *P);
void jacg_set_infinity(jac_gmp_t *R, const curve_params_t *cp);

void point_double_jacg(jac_gmp_t *R, const jac_gmp_t *P, const curve_params_t *cp);
void point_add_mixed_g(jac_gmp_t *R, const jac_gmp_t *P, const affine_gmp_t *Q, const curve_params_t *cp);
void batch_normalize_g(affine_gmp_t *out, const jac_gmp_t *pts, int count, const curve_params_t *cp);

// Plain affine point addition with a per-step modular inverse (baseline #1).
void affine_add_g(affine_gmp_t *R, const affine_gmp_t *P, const affine_gmp_t *Q, const curve_params_t *cp);
void affine_double_g(affine_gmp_t *R, const affine_gmp_t *P, const curve_params_t *cp);

#endif
