#pragma once
#include "curve_params.hpp"

inline const P256Params &g_p256() {
    static P256Params c = make_p256();
    return c;
}
inline const P384Params &g_p384() {
    static P384Params c = make_p384();
    return c;
}
inline const P521Params &g_p521() {
    static P521Params c = make_p521();
    return c;
}

// GMP mpz modulus, shared per curve, for the GMP-backed field (FieldG).
#include <gmp.h>
inline const mpz_t *g_p256_mpz() {
    static bool init = false;
    static mpz_t p;
    if (!init) {
        mpz_init(p);
        limbs_to_mpz<4>(p, g_p256().p);
        init = true;
    }
    return &p;
}
inline const mpz_t *g_p384_mpz() {
    static bool init = false;
    static mpz_t p;
    if (!init) {
        mpz_init(p);
        limbs_to_mpz<6>(p, g_p384().p);
        init = true;
    }
    return &p;
}
inline const mpz_t *g_p521_mpz() {
    static bool init = false;
    static mpz_t p;
    if (!init) {
        mpz_init(p);
        limbs_to_mpz<9>(p, g_p521().p);
        init = true;
    }
    return &p;
}
