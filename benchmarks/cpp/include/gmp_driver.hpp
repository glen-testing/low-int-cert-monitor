// GMP-backed drivers: variant 1 (affine + per-step modular inverse, the
// slow baseline mirroring the Python reference) and variant 2 (Jacobian
// mixed-add + batched normalization, GMP field -- isolates the
// coordinate-system win from the field-arithmetic win).
#pragma once
#include "common.hpp"
#include "field_gmp.hpp"
#include "point.hpp"
#include <gmp.h>

// variant 1: affine point addition with a fresh modular inverse every step.
template <size_t N>
double bench_add_affine_gmp(const CurveParams<N> &c, const mpz_t *pmod, long long iters) {
    mpz_t gx, gy;
    mpz_inits(gx, gy, nullptr);
    limbs_to_mpz<N>(gx, c.Gx);
    limbs_to_mpz<N>(gy, c.Gy);
    FieldG Gx = FieldG::from_mpz(pmod, gx), Gy = FieldG::from_mpz(pmod, gy);
    FieldG x1 = Gx, y1 = Gy; // start at G, add G repeatedly like the fast benches

    auto t0 = Clock::now();
    for (long long i = 0; i < iters; i++) {
        FieldG dx = Gx - x1;
        FieldG dy = Gy - y1;
        FieldG lambda = dy * dx.inv(); // per-step modular inverse (the slow part)
        FieldG x3 = lambda * lambda - x1 - Gx;
        FieldG y3 = lambda * (x1 - x3) - y1;
        x1 = x3;
        y1 = y3;
    }
    auto t1 = Clock::now();
    mpz_clears(gx, gy, nullptr);
    volatile unsigned long sink = mpz_get_ui(x1.v);
    (void)sink;
    return elapsed_ns(t0, t1) / (double)iters;
}

// variant 2: Jacobian mixed-add, inversion-free, GMP field backend.
template <size_t N>
double bench_add_jac_gmp(const CurveParams<N> &c, const mpz_t *pmod, long long iters) {
    mpz_t gx, gy;
    mpz_inits(gx, gy, nullptr);
    limbs_to_mpz<N>(gx, c.Gx);
    limbs_to_mpz<N>(gy, c.Gy);
    FieldG Gx = FieldG::from_mpz(pmod, gx), Gy = FieldG::from_mpz(pmod, gy);
    JacPoint<FieldG> P = jac_from_affine<FieldG>(Gx, Gy);

    auto t0 = Clock::now();
    for (long long i = 0; i < iters; i++) P = mixed_add<FieldG>(P, Gx, Gy);
    auto t1 = Clock::now();
    mpz_clears(gx, gy, nullptr);
    volatile unsigned long sink = mpz_get_ui(P.X.v);
    (void)sink;
    return elapsed_ns(t0, t1) / (double)iters;
}
