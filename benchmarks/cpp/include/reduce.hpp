// Two interchangeable modular-reduction backends, both built on the generic
// bigint.hpp primitives:
//   redc<N>        - generic Montgomery reduction (CIOS-style, separated form)
//   fold_reduce<N> - Solinas-style shift/fold reduction using each curve's
//                    2^bitlen === K (mod p) identity (K = signed sum of
//                    powers of two, see curve_params.cpp). No multiplications
//                    at all -- only shifts/adds/subtracts.
//
// fold_reduce correctness argument (why no bias/sign handling is needed):
// each round splits cur = lo + hi*2^bitlen (exact, both >=0) and replaces
// 2^bitlen by K = Kpos - Kneg (Kpos,Kneg sums of the positive/negative fold
// terms). Since K > 0 and hi >= 0, hi*Kpos >= hi*Kneg always, and lo>=0 adds
// extra margin, so pos_sum = lo + hi*Kpos >= neg_sum = hi*Kneg unconditionally
// -- the subtraction never underflows. Validated against GMP in selftest.
#pragma once
#include "bigint.hpp"
#include "curve_params.hpp"

// HAC Algorithm 14.32 bound: the running accumulator A satisfies A < 2*p*R,
// which needs a 2N+1-limb buffer (not 2N) -- the extra top limb is always 0
// or 1. A fixed 2N-limb buffer silently truncates that carry on big inputs;
// caught by GMP cross-validation (see validate.hpp), fixed here.
template <size_t N>
FINLINE void redc(Limbs<N> &out, const Limbs<2 * N> &Tin, const CurveParams<N> &c) {
    Limbs<2 * N + 1> T{};
    for (size_t i = 0; i < 2 * N; i++) T[i] = Tin[i];
    for (size_t i = 0; i < N; i++) {
        uint64_t m = T[i] * c.n0inv;
        unsigned __int128 carry = 0;
        for (size_t j = 0; j < N; j++) {
            unsigned __int128 cur = (unsigned __int128)m * c.p[j] + T[i + j] + carry;
            T[i + j] = (uint64_t)cur;
            carry = cur >> 64;
        }
        size_t k = i + N;
        while (carry && k < 2 * N + 1) {
            unsigned __int128 cur = (unsigned __int128)T[k] + carry;
            T[k] = (uint64_t)cur;
            carry = cur >> 64;
            k++;
        }
    }
    Limbs<N> r;
    for (size_t i = 0; i < N; i++) r[i] = T[N + i];
    if (T[2 * N]) addto_n<N>(r, c.one_mont); // fold the (0 or 1) overflow limb back in: + (R mod p)
    for (int i = 0; i < 8 && cmp_n<N>(r, c.p) >= 0; i++) {
        Limbs<N> t;
        sub_n<N>(t, r, c.p);
        r = t;
    }
    out = r;
}

template <size_t N>
FINLINE void fold_reduce(Limbs<N> &out, const Limbs<2 * N> &Twide, const CurveParams<N> &c) {
    Limbs<2 * N> cur = Twide;
    for (int round = 0; round < 24; round++) {
        Limbs<2 * N> hi{};
        shr_bits<2 * N, 2 * N>(hi, cur, c.bitlen);
        if (is_zero_n<2 * N>(hi)) break;
        Limbs<2 * N> lo = cur;
        mask_bits<2 * N>(lo, c.bitlen);
        Limbs<2 * N> pos = lo;
        Limbs<2 * N> neg{};
        for (const auto &t : c.fold) {
            Limbs<2 * N> shifted{};
            shl_bits<2 * N, 2 * N>(shifted, hi, t.shift);
            if (t.sign > 0) addto_n<2 * N>(pos, shifted);
            else addto_n<2 * N>(neg, shifted);
        }
        Limbs<2 * N> diff;
        sub_n<2 * N>(diff, pos, neg); // provably non-negative, see header comment
        cur = diff;
    }
    Limbs<N> r;
    for (size_t i = 0; i < N; i++) r[i] = cur[i];
    for (int i = 0; i < 32 && cmp_n<N>(r, c.p) >= 0; i++) {
        Limbs<N> t;
        sub_n<N>(t, r, c.p);
        r = t;
    }
    out = r;
}
