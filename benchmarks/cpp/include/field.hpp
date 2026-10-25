// Field<N, Backend>: a field element mod p for an N-limb curve.
// Backend::FOLD   -> plain representation, multiply via fold_reduce (Solinas-style).
// Backend::MONT   -> Montgomery representation (v = x*R mod p), multiply via redc.
// add/sub are representation-agnostic (Montgomery domain is additive-homomorphic).
#pragma once
#include "bigint.hpp"
#include "curve_params.hpp"
#include "reduce.hpp"

enum class Backend { FOLD, MONT };

template <size_t N, Backend B>
struct Field {
    using C = CurveParams<N>;
    const C *c = nullptr;
    Limbs<N> v{};

    static Field from_plain(const C &cp, const Limbs<N> &x) {
        Field f;
        f.c = &cp;
        if constexpr (B == Backend::FOLD) {
            f.v = x;
        } else {
            Limbs<2 * N> t;
            mul_schoolbook<N>(t, x, cp.r2modp);
            redc<N>(f.v, t, cp);
        }
        return f;
    }

    Limbs<N> to_plain() const {
        if constexpr (B == Backend::FOLD) {
            return v;
        } else {
            Limbs<2 * N> t{};
            for (size_t i = 0; i < N; i++) t[i] = v[i];
            Limbs<N> r;
            redc<N>(r, t, *c);
            return r;
        }
    }

    static Field one_like(const Field &ref) { return one(*ref.c); }
    static Field zero_like(const Field &ref) { return zero(*ref.c); }

    static Field zero(const C &cp) {
        Field f;
        f.c = &cp;
        f.v.fill(0);
        return f;
    }
    static Field one(const C &cp) {
        Field f;
        f.c = &cp;
        if constexpr (B == Backend::FOLD) {
            f.v.fill(0);
            f.v[0] = 1;
        } else {
            f.v = cp.one_mont;
        }
        return f;
    }

    FINLINE Field operator+(const Field &o) const {
        Field r;
        r.c = c;
        Limbs<N> t;
        uint64_t carry = add_n<N>(t, v, o.v);
        if (carry || cmp_n<N>(t, c->p) >= 0) {
            Limbs<N> t2;
            sub_n<N>(t2, t, c->p);
            t = t2;
        }
        r.v = t;
        return r;
    }

    FINLINE Field operator-(const Field &o) const {
        Field r;
        r.c = c;
        Limbs<N> t;
        uint64_t borrow = sub_n<N>(t, v, o.v);
        if (borrow) {
            Limbs<N> t2;
            addto_n<N>(t, c->p);
            t2 = t;
            t = t2;
        }
        r.v = t;
        return r;
    }

    FINLINE Field operator*(const Field &o) const {
        Limbs<2 * N> t;
        mul_schoolbook<N>(t, v, o.v);
        Field r;
        r.c = c;
        if constexpr (B == Backend::FOLD) fold_reduce<N>(r.v, t, *c);
        else redc<N>(r.v, t, *c);
        return r;
    }

    bool is_zero() const { return is_zero_n<N>(v); }
    bool equals(const Field &o) const { return cmp_n<N>(v, o.v) == 0; }

    // x^(p-2) mod p via right-to-left square-and-multiply (slow path; only
    // used for the rare per-block Montgomery-trick inversion, never per-add).
    Field inv() const {
        Limbs<N> two{};
        two[0] = 2;
        Limbs<N> e;
        sub_n<N>(e, c->p, two);
        Field result = Field::one(*c);
        Field base = *this;
        for (size_t i = 0; i < N * 64; i++) {
            if ((e[i / 64] >> (i % 64)) & 1ULL) result = result * base;
            base = base * base;
        }
        return result;
    }
};
