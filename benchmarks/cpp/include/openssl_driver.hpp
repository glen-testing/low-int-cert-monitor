// Optional reference datapoint: OpenSSL's own EC_POINT_add, same
// point += generator microbenchmark shape as the other drivers.
#pragma once
#include "common.hpp"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

inline int nid_for_curve(CurveId id) {
    switch (id) {
        case CurveId::P256: return NID_X9_62_prime256v1;
        case CurveId::P384: return NID_secp384r1;
        case CurveId::P521: return NID_secp521r1;
    }
    return 0;
}

inline double bench_add_openssl(CurveId id, long long iters) {
    int nid = nid_for_curve(id);
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(nid);
    BN_CTX *ctx = BN_CTX_new();
    const EC_POINT *gen = EC_GROUP_get0_generator(grp);
    EC_POINT *P = EC_POINT_dup(gen, grp);

    auto t0 = Clock::now();
    for (long long i = 0; i < iters; i++) EC_POINT_add(grp, P, P, gen, ctx);
    auto t1 = Clock::now();

    BIGNUM *x = BN_new();
    EC_POINT_get_affine_coordinates(grp, P, x, nullptr, ctx);
    volatile unsigned long sink = BN_get_word(x);
    (void)sink;
    BN_free(x);
    EC_POINT_free(P);
    BN_CTX_free(ctx);
    EC_GROUP_free(grp);
    return elapsed_ns(t0, t1) / (double)iters;
}
