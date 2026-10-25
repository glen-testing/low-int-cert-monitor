// Minimal hand-rolled fixed-radix-2^64 bignum primitives.
// Variable-length (n passed at runtime), unsigned __int128 for 64x64->128.
// No GMP calls here - this is the "hand-rolled" layer used by field_fast.c.
#ifndef BN_H
#define BN_H
#include <stdint.h>
#include <string.h>

#define BN_MAXLIMBS 24   // covers up to 1536 bits (P-521 double-width product needs 17-18, plus Barrett headroom)

typedef unsigned __int128 u128;

static inline void bn_zero(uint64_t *r, int n) { memset(r, 0, n * sizeof(uint64_t)); }
static inline void bn_copy(uint64_t *r, const uint64_t *a, int n) { memcpy(r, a, n * sizeof(uint64_t)); }

// returns 1 if a<b, 0 if a==b, -1... actually return -1/0/1 like memcmp semantics on magnitude
static inline int bn_cmp(const uint64_t *a, const uint64_t *b, int n) {
    for (int i = n - 1; i >= 0; i--) {
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

static inline int bn_is_zero(const uint64_t *a, int n) {
    for (int i = 0; i < n; i++) if (a[i]) return 0;
    return 1;
}

// r = a + b (n limbs each), returns carry out (0/1)
static inline uint64_t bn_add_n(uint64_t *r, const uint64_t *a, const uint64_t *b, int n) {
    u128 carry = 0;
    for (int i = 0; i < n; i++) {
        u128 t = (u128)a[i] + b[i] + carry;
        r[i] = (uint64_t)t;
        carry = t >> 64;
    }
    return (uint64_t)carry;
}

// r = a + w (single limb add into n-limb a), returns carry out
static inline uint64_t bn_add_1(uint64_t *r, const uint64_t *a, int n, uint64_t w) {
    u128 carry = w;
    for (int i = 0; i < n; i++) {
        u128 t = (u128)a[i] + carry;
        r[i] = (uint64_t)t;
        carry = t >> 64;
    }
    return (uint64_t)carry;
}

// r = a - b (n limbs each), returns borrow out (1 if a<b)
static inline uint64_t bn_sub_n(uint64_t *r, const uint64_t *a, const uint64_t *b, int n) {
    u128 borrow = 0;
    for (int i = 0; i < n; i++) {
        u128 t = (u128)a[i] - b[i] - borrow;
        r[i] = (uint64_t)t;
        borrow = (t >> 64) & 1; // 1 if underflowed
    }
    return (uint64_t)borrow;
}

// Schoolbook multiply: r[na+nb] = a[na] * b[nb]. r must not alias a or b.
static inline void bn_mul(uint64_t *r, const uint64_t *a, int na, const uint64_t *b, int nb) {
    for (int i = 0; i < na + nb; i++) r[i] = 0;
    for (int i = 0; i < na; i++) {
        if (a[i] == 0) continue;
        u128 carry = 0;
        for (int j = 0; j < nb; j++) {
            u128 t = (u128)a[i] * (u128)b[j] + r[i + j] + carry;
            r[i + j] = (uint64_t)t;
            carry = t >> 64;
        }
        int k = i + nb;
        while (carry) {
            u128 t = (u128)r[k] + carry;
            r[k] = (uint64_t)t;
            carry = t >> 64;
            k++;
        }
    }
}

// shift right within an n-limb array by `bits` (0<=bits<64), in place capable (r may == a)
static inline void bn_shr_bits(uint64_t *r, const uint64_t *a, int n, int bits) {
    if (bits == 0) { if (r != a) bn_copy(r, a, n); return; }
    for (int i = 0; i < n; i++) {
        uint64_t lo = a[i] >> bits;
        uint64_t hi = (i + 1 < n) ? (a[i + 1] << (64 - bits)) : 0;
        r[i] = lo | hi;
    }
}

// shift left within an array, output must have n+1 limbs capacity (top limb = overflow)
static inline void bn_shl_bits(uint64_t *r, const uint64_t *a, int n, int bits) {
    if (bits == 0) { bn_copy(r, a, n); r[n] = 0; return; }
    uint64_t carry = 0;
    for (int i = 0; i < n; i++) {
        uint64_t v = a[i];
        r[i] = (v << bits) | carry;
        carry = v >> (64 - bits);
    }
    r[n] = carry;
}

#endif
