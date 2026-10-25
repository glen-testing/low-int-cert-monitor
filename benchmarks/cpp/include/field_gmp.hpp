// Simple GMP mpz-backed field element -- the "baseline; GMP ok" backend
// used by variant 1 (affine + per-step inverse) and variant 2 (Jacobian +
// batched normalization, isolating the coordinate-system win from the
// field-arithmetic win).
#pragma once
#include <gmp.h>
#include <memory>

struct FieldG {
    const mpz_t *p = nullptr; // pointer to shared curve modulus
    mpz_t v;

    FieldG() { mpz_init(v); }
    FieldG(const FieldG &o) : p(o.p) {
        mpz_init(v);
        mpz_set(v, o.v);
    }
    FieldG &operator=(const FieldG &o) {
        p = o.p;
        mpz_set(v, o.v);
        return *this;
    }
    ~FieldG() { mpz_clear(v); }

    static FieldG from_mpz(const mpz_t *modulus, const mpz_t x) {
        FieldG f;
        f.p = modulus;
        mpz_mod(f.v, x, *modulus);
        return f;
    }
    static FieldG zero(const mpz_t *modulus) {
        FieldG f;
        f.p = modulus;
        mpz_set_ui(f.v, 0);
        return f;
    }
    static FieldG one_like(const FieldG &ref) { return one(ref.p); }
    static FieldG zero_like(const FieldG &ref) { return zero(ref.p); }

    static FieldG one(const mpz_t *modulus) {
        FieldG f;
        f.p = modulus;
        mpz_set_ui(f.v, 1);
        return f;
    }

    FieldG operator+(const FieldG &o) const {
        FieldG r;
        r.p = p;
        mpz_add(r.v, v, o.v);
        if (mpz_cmp(r.v, *p) >= 0) mpz_sub(r.v, r.v, *p);
        return r;
    }
    FieldG operator-(const FieldG &o) const {
        FieldG r;
        r.p = p;
        mpz_sub(r.v, v, o.v);
        if (mpz_sgn(r.v) < 0) mpz_add(r.v, r.v, *p);
        return r;
    }
    FieldG operator*(const FieldG &o) const {
        FieldG r;
        r.p = p;
        mpz_mul(r.v, v, o.v);
        mpz_mod(r.v, r.v, *p);
        return r;
    }
    FieldG inv() const {
        FieldG r;
        r.p = p;
        mpz_invert(r.v, v, *p);
        return r;
    }
    bool is_zero() const { return mpz_sgn(v) == 0; }
    bool equals(const FieldG &o) const { return mpz_cmp(v, o.v) == 0; }
};
