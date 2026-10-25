// Curve parameter sets for P-256, P-384, P-521 (short Weierstrass, a = -3).
// Limb counts are compile-time (template) constants; the actual constant
// *values* (p, b, G, n, Montgomery helpers) are parsed once at process
// startup from the hex literals in common/spec.md -- true constexpr
// evaluation of multi-limb modular constants (R^2 mod p, n0inv) is not
// attempted; they are computed once via plain runtime code (negligible
// one-time cost), same as OpenSSL/GMP do for their Montgomery contexts.
#pragma once
#include "bigint.hpp"
#include <vector>

enum class CurveId { P256, P384, P521 };

struct FoldTerm {
    unsigned shift;
    int sign; // +1 or -1
};

template <size_t LIMBS_>
struct CurveParams {
    static constexpr size_t LIMBS = LIMBS_;
    unsigned bitlen;              // bit length of p (256, 384, 521)
    Limbs<LIMBS> p, b, Gx, Gy, n; // field modulus, curve b, generator, order
    std::vector<FoldTerm> fold;   // terms s.t. 2^bitlen === K (mod p), K = sum sign*2^shift
    // Montgomery context (generic REDC path)
    uint64_t n0inv;        // -p^{-1} mod 2^64
    Limbs<LIMBS> r2modp;   // R^2 mod p, R = 2^(64*LIMBS)
    Limbs<LIMBS> one_mont; // R mod p (Montgomery representation of 1)
    Limbs<LIMBS> bias;     // large multiple of p added before fold-subtracts, to avoid underflow
    CurveId id;
    const char *name;
};

using P256Params = CurveParams<4>;
using P384Params = CurveParams<6>;
using P521Params = CurveParams<9>;

// -p^{-1} mod 2^64 via Newton's iteration (x_{k+1} = x_k*(2 - p*x_k)), converges
// in 6 doublings of precision for 64-bit odd p[0].
inline uint64_t compute_n0inv(uint64_t p0) {
    uint64_t x = p0; // for odd p0, p0*p0 === 1 (mod 8): correct to 3 bits already
    for (int i = 0; i < 6; i++) x = x * (2 - p0 * x); // doubles correct bits each step
    return (uint64_t)0 - x; // n0inv = -p^{-1} mod 2^64 (unsigned wraparound negation)
}

template <size_t N>
inline void init_montgomery(CurveParams<N> &c) {
    c.n0inv = compute_n0inv(c.p[0]);
    mpz_t p, r2, one, t;
    mpz_inits(p, r2, one, t, nullptr);
    limbs_to_mpz<N>(p, c.p);
    // R = 2^(64*N); R^2 mod p
    mpz_ui_pow_ui(t, 2, 64 * N);
    mpz_powm_ui(r2, t, 2, p);
    mpz_to_limbs<N>(c.r2modp, r2);
    mpz_mod(one, t, p); // R mod p
    mpz_to_limbs<N>(c.one_mont, one);
    mpz_clears(p, r2, one, t, nullptr);
}

template <size_t N>
inline void init_bias(CurveParams<N> &c, unsigned multiple) {
    // bias = multiple * p, computed by repeated doubling + add (one-time cost)
    Limbs<N> acc{};
    Limbs<N> base = c.p;
    unsigned m = multiple;
    while (m) {
        if (m & 1) addto_n<N>(acc, base);
        Limbs<N> doubled;
        add_n<N>(doubled, base, base);
        base = doubled;
        m >>= 1;
    }
    c.bias = acc;
}

P256Params make_p256();
P384Params make_p384();
P521Params make_p521();
