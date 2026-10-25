// Fast-field drivers: point-add microbenchmark and the BSGS sweep, both
// built on Field<N,Backend> + Jacobian mixed-add + Montgomery-trick batch
// normalization.
#pragma once
#include "baby_table.hpp"
#include "common.hpp"
#include "field.hpp"
#include "point.hpp"
#include <cmath>
#include <vector>

template <size_t N, Backend B>
double bench_add_fast(const CurveParams<N> &c, long long iters) {
    using F = Field<N, B>;
    F Gx = F::from_plain(c, c.Gx), Gy = F::from_plain(c, c.Gy);
    JacPoint<F> P = jac_from_affine<F>(Gx, Gy);
    auto t0 = Clock::now();
    for (long long i = 0; i < iters; i++) P = mixed_add<F>(P, Gx, Gy);
    auto t1 = Clock::now();
    volatile uint64_t sink = P.X.v[0] ^ P.Z.v[0] ^ (uint64_t)P.inf;
    (void)sink;
    return elapsed_ns(t0, t1) / (double)iters;
}

struct BsgsStats {
    long long total_adds = 0;
    double seconds = 0.0;
    long long m_b = 0, i_max = 0;
};

// targets_for_curve: subset of TargetRec already filtered to this curve.
// d_out[i] = -1 if no d<=maxN found, else the discovered d.
template <size_t N, Backend B>
BsgsStats run_bsgs_fast(const CurveParams<N> &c, const std::vector<TargetRec> &targets_for_curve,
                         long long maxN, std::vector<long long> &d_out) {
    using F = Field<N, B>;
    BsgsStats stats;
    F Gx = F::from_plain(c, c.Gx), Gy = F::from_plain(c, c.Gy);
    long long m_b = (long long)std::ceil(std::sqrt((double)maxN));
    if (m_b < 1) m_b = 1;
    long long i_max = (maxN + m_b - 1) / m_b;
    if (i_max < 1) i_max = 1;
    stats.m_b = m_b;
    stats.i_max = i_max;

    auto t0 = Clock::now();
    long long adds = 0;

    std::vector<JacPoint<F>> baby_jac;
    baby_jac.reserve((size_t)m_b);
    JacPoint<F> P = jac_from_affine<F>(Gx, Gy);
    baby_jac.push_back(P);
    for (long long j = 2; j <= m_b; j++) {
        P = mixed_add<F>(P, Gx, Gy);
        baby_jac.push_back(P);
        adds++;
    }
    std::vector<F> baby_x, baby_y;
    batch_normalize<F>(baby_jac, baby_x, baby_y);

    BabyTable<N> table;
    table.init((size_t)m_b);
    for (long long j = 1; j <= m_b; j++) table.insert(baby_x[j - 1].to_plain(), baby_y[j - 1].to_plain(), j);

    F stride_x = baby_x[(size_t)m_b - 1];
    F stride_y = baby_y[(size_t)m_b - 1];
    F neg_stride_y = F::zero(c) - stride_y;

    d_out.assign(targets_for_curve.size(), -1);
    for (size_t ti = 0; ti < targets_for_curve.size(); ti++) {
        Limbs<N> tx = hex_to_limbs<N>(targets_for_curve[ti].x_hex);
        Limbs<N> ty = hex_to_limbs<N>(targets_for_curve[ti].y_hex);
        F Qx = F::from_plain(c, tx), Qy = F::from_plain(c, ty);

        std::vector<JacPoint<F>> Rs;
        Rs.reserve((size_t)i_max);
        JacPoint<F> R = jac_from_affine<F>(Qx, Qy);
        Rs.push_back(R);
        for (long long i = 1; i < i_max; i++) {
            R = mixed_add<F>(R, stride_x, neg_stride_y);
            Rs.push_back(R);
            adds++;
        }
        std::vector<F> rx, ry;
        batch_normalize<F>(Rs, rx, ry);

        for (long long i = 0; i < (long long)Rs.size(); i++) {
            Limbs<N> xp = rx[(size_t)i].to_plain();
            long long j;
            Limbs<N> baby_y_plain;
            if (!table.find(xp, baby_y_plain, j)) continue;
            Limbs<N> yp_actual = ry[(size_t)i].to_plain();
            if (cmp_n<N>(yp_actual, baby_y_plain) == 0) {
                long long d1 = i * m_b + j;
                if (d1 >= 1 && d1 <= maxN) {
                    d_out[ti] = d1;
                    break;
                }
            }
            Limbs<N> negy;
            sub_n<N>(negy, c.p, baby_y_plain);
            if (cmp_n<N>(yp_actual, negy) == 0) {
                long long d2 = i * m_b - j;
                if (d2 >= 1 && d2 <= maxN) {
                    d_out[ti] = d2;
                    break;
                }
            }
        }
    }
    auto t1 = Clock::now();
    stats.total_adds = adds;
    stats.seconds = elapsed_ns(t0, t1) / 1e9;
    return stats;
}
