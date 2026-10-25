// Cross-check the hand-rolled field arithmetic (both backends) against GMP
// on random inputs. Required by the correctness gate before either backend
// is trusted for a null verdict.
#pragma once
#include "bigint.hpp"
#include "curve_params.hpp"
#include "field.hpp"
#include <gmp.h>
#include <random>

template <size_t N>
inline Limbs<N> random_below_p(const CurveParams<N> &c, std::mt19937_64 &rng) {
    Limbs<N> r;
    for (auto &x : r) x = rng();
    mpz_t rm, pm;
    mpz_inits(rm, pm, nullptr);
    limbs_to_mpz<N>(rm, r);
    limbs_to_mpz<N>(pm, c.p);
    mpz_mod(rm, rm, pm);
    Limbs<N> out;
    mpz_to_limbs<N>(out, rm);
    mpz_clears(rm, pm, nullptr);
    return out;
}

template <size_t N, Backend B>
inline bool validate_field(const CurveParams<N> &c, int trials, std::mt19937_64 &rng, std::string &err) {
    using F = Field<N, B>;
    mpz_t pm, am, bm, rm, gotm;
    mpz_inits(pm, am, bm, rm, gotm, nullptr);
    limbs_to_mpz<N>(pm, c.p);
    bool ok = true;
    for (int t = 0; t < trials && ok; t++) {
        Limbs<N> a = random_below_p<N>(c, rng);
        Limbs<N> b = random_below_p<N>(c, rng);
        F fa = F::from_plain(c, a), fb = F::from_plain(c, b);
        limbs_to_mpz<N>(am, a);
        limbs_to_mpz<N>(bm, b);

        F fsum = fa + fb;
        mpz_add(rm, am, bm);
        mpz_mod(rm, rm, pm);
        limbs_to_mpz<N>(gotm, fsum.to_plain());
        if (mpz_cmp(rm, gotm) != 0) { err = "add mismatch"; ok = false; break; }

        F fdiff = fa - fb;
        mpz_sub(rm, am, bm);
        mpz_mod(rm, rm, pm);
        if (mpz_sgn(rm) < 0) mpz_add(rm, rm, pm);
        limbs_to_mpz<N>(gotm, fdiff.to_plain());
        if (mpz_cmp(rm, gotm) != 0) { err = "sub mismatch"; ok = false; break; }

        F fprod = fa * fb;
        mpz_mul(rm, am, bm);
        mpz_mod(rm, rm, pm);
        limbs_to_mpz<N>(gotm, fprod.to_plain());
        if (mpz_cmp(rm, gotm) != 0) { err = "mul mismatch"; ok = false; break; }
    }
    if (ok) {
        Limbs<N> a = random_below_p<N>(c, rng);
        if (is_zero_n<N>(a)) a[0] = 1;
        F fa = F::from_plain(c, a);
        F finv = fa.inv();
        F one = fa * finv;
        mpz_set_ui(gotm, 1);
        limbs_to_mpz<N>(rm, one.to_plain());
        if (mpz_cmp(rm, gotm) != 0) { err = "inv mismatch"; ok = false; }
    }
    mpz_clears(pm, am, bm, rm, gotm, nullptr);
    return ok;
}
