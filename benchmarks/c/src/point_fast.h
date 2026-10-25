// Jacobian point arithmetic over the hand-rolled fast field (field_fast.h).
// Curve: y^2 = x^3 - 3x + b  (a = -3 fixed, per spec).
#ifndef POINT_FAST_H
#define POINT_FAST_H
#include "field_fast.h"

typedef struct { fe_t X, Y, Z; } jac_t;       // Z==0 (all-zero limbs) means point at infinity
typedef struct { fe_t x, y; } affine_t;

void jac_from_affine(jac_t *R, const affine_t *P, const curve_params_t *cp);
int  jac_is_infinity(const jac_t *P, const curve_params_t *cp);
void jac_set_infinity(jac_t *R, const curve_params_t *cp);

// R = 2*P
void point_double_jac(jac_t *R, const jac_t *P, const curve_params_t *cp);

// R = P + Q, Q affine (mixed addition, inversion-free). Handles P==+-Q correctly
// (falls back to doubling, or produces the point at infinity).
void point_add_mixed(jac_t *R, const jac_t *P, const affine_t *Q, const curve_params_t *cp);

// Negate an affine point: (x,y) -> (x,-y)
void affine_neg(affine_t *R, const affine_t *P, const curve_params_t *cp);

// Montgomery's trick: normalize `count` Jacobian points to affine in one inverse.
// Points with Z==0 (infinity) are left as x=y=0 in the output (caller must check
// jac_is_infinity on the *input* array beforehand if it needs to distinguish them).
void batch_normalize(affine_t *out, const jac_t *pts, int count, const curve_params_t *cp);

// scalar multiply via double-and-add, d in [0, 2^64). For validation only (not hot path).
void point_mul_u64(jac_t *R, uint64_t d, const curve_params_t *cp);

#endif
