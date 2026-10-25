// Jacobian point arithmetic templated on a Field type F (duck-typed: needs
// operator+,-,*, is_zero(), equals(), and ::zero(cp)/::one(cp)).
// Only mixed addition (Jacobian += affine) is needed on the hot path -- the
// BSGS sweep here only ever adds/subtracts the fixed points G and the giant
// stride, so point doubling never triggers except in the (never-hit for
// d in [1,1e8], prime-order G) degenerate equal-point case, which is still
// implemented below for defensive correctness.
#pragma once
#include <vector>

template <typename F>
struct JacPoint {
    F X, Y, Z;
    bool inf = false;
};

template <typename F>
JacPoint<F> jac_from_affine(const F &x, const F &y) {
    JacPoint<F> p{x, y, F::one_like(x), false};
    return p;
}

template <typename F>
JacPoint<F> jac_infinity(const F &zero) {
    JacPoint<F> p{zero, zero, zero, true};
    return p;
}

// a = -3 Jacobian doubling ("dbl-2007-bl"); defensive path, not hot.
template <typename F>
JacPoint<F> jac_double(const JacPoint<F> &P) {
    if (P.inf || P.Y.is_zero()) return jac_infinity<F>(P.X - P.X);
    F delta = P.Z * P.Z;
    F gamma = P.Y * P.Y;
    F beta = P.X * gamma;
    F xm = P.X - delta, xp = P.X + delta;
    F alpha = xm * xp;
    alpha = alpha + alpha + alpha; // 3*
    F X3 = alpha * alpha;
    F beta8 = beta + beta;
    beta8 = beta8 + beta8;
    beta8 = beta8 + beta8;
    X3 = X3 - beta8;
    F ypz = P.Y + P.Z;
    F Z3 = ypz * ypz - gamma - delta;
    F beta4 = beta + beta;
    beta4 = beta4 + beta4;
    F Y3 = alpha * (beta4 - X3);
    F gamma2 = gamma * gamma;
    F gamma8 = gamma2 + gamma2;
    gamma8 = gamma8 + gamma8;
    gamma8 = gamma8 + gamma8;
    Y3 = Y3 - gamma8;
    return JacPoint<F>{X3, Y3, Z3, false};
}

// "add-2007-bl" mixed addition: Jacobian P += affine (x2, y2).
template <typename F>
FINLINE JacPoint<F> mixed_add(const JacPoint<F> &P, const F &x2, const F &y2) {
    if (P.inf) return jac_from_affine<F>(x2, y2);
    F Z1Z1 = P.Z * P.Z;
    F U2 = x2 * Z1Z1;
    F S2 = (y2 * P.Z) * Z1Z1;
    F H = U2 - P.X;
    if (H.is_zero()) {
        F r0 = S2 - P.Y;
        if (r0.is_zero()) return jac_double<F>(P);
        return jac_infinity<F>(P.X - P.X);
    }
    F HH = H * H;
    F I = (HH + HH) + (HH + HH); // 4*HH
    F J = H * I;
    F r = (S2 - P.Y) + (S2 - P.Y); // 2*(S2-Y1)
    F V = P.X * I;
    F X3 = r * r - J - V - V;
    F twoY1J = (P.Y * J) + (P.Y * J);
    F Y3 = r * (V - X3) - twoY1J;
    F Z3 = (P.Z * H) + (P.Z * H);
    return JacPoint<F>{X3, Y3, Z3, false};
}

// Montgomery's trick: normalize a whole block of Jacobian points to affine
// using exactly one field inversion for the entire block.
template <typename F>
void batch_normalize(const std::vector<JacPoint<F>> &pts, std::vector<F> &outx, std::vector<F> &outy) {
    size_t n = pts.size();
    outx.resize(n);
    outy.resize(n);
    if (n == 0) return;
    std::vector<F> prefix(n);
    prefix[0] = pts[0].Z;
    for (size_t i = 1; i < n; i++) prefix[i] = prefix[i - 1] * pts[i].Z;
    F u = prefix[n - 1].inv();
    for (size_t idx = n; idx-- > 0;) {
        F zinv = (idx == 0) ? u : u * prefix[idx - 1];
        u = u * pts[idx].Z;
        F zinv2 = zinv * zinv;
        F zinv3 = zinv2 * zinv;
        outx[idx] = pts[idx].X * zinv2;
        outy[idx] = pts[idx].Y * zinv3;
    }
}
