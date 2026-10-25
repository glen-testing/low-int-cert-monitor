// Generic fixed-width multi-precision unsigned integer primitives.
// Templated on limb count N (64-bit limbs, little-endian: limb[0] is LSW).
// These are the shared building blocks for both the generic Montgomery
// reduction path and the Solinas-style shift/fold reduction path.
#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <gmp.h>
#include <string>

#define FINLINE __attribute__((always_inline)) inline

template <size_t N>
using Limbs = std::array<uint64_t, N>;

template <size_t N>
FINLINE void zero_n(Limbs<N> &a) {
    a.fill(0);
}

template <size_t N>
FINLINE bool is_zero_n(const Limbs<N> &a) {
    for (size_t i = 0; i < N; i++) if (a[i]) return false;
    return true;
}

// returns -1,0,1
template <size_t N>
FINLINE int cmp_n(const Limbs<N> &a, const Limbs<N> &b) {
    for (size_t i = N; i-- > 0;) {
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

// r = a + b, returns carry out. Uses unsigned __int128 for the carry chain
// (not __builtin_addcll: that builtin is unavailable on this aarch64 GCC).
template <size_t N>
FINLINE uint64_t add_n(Limbs<N> &r, const Limbs<N> &a, const Limbs<N> &b) {
    unsigned __int128 carry = 0;
    for (size_t i = 0; i < N; i++) {
        unsigned __int128 s = (unsigned __int128)a[i] + b[i] + carry;
        r[i] = (uint64_t)s;
        carry = s >> 64;
    }
    return (uint64_t)carry;
}

// r += b, returns carry out
template <size_t N>
FINLINE uint64_t addto_n(Limbs<N> &r, const Limbs<N> &b) {
    unsigned __int128 carry = 0;
    for (size_t i = 0; i < N; i++) {
        unsigned __int128 s = (unsigned __int128)r[i] + b[i] + carry;
        r[i] = (uint64_t)s;
        carry = s >> 64;
    }
    return (uint64_t)carry;
}

// r = a - b, returns borrow (0 or 1)
template <size_t N>
FINLINE uint64_t sub_n(Limbs<N> &r, const Limbs<N> &a, const Limbs<N> &b) {
    __int128 borrow = 0;
    for (size_t i = 0; i < N; i++) {
        __int128 d = (__int128)a[i] - (__int128)b[i] - borrow;
        if (d < 0) {
            d += ((__int128)1 << 64);
            borrow = 1;
        } else {
            borrow = 0;
        }
        r[i] = (uint64_t)d;
    }
    return (uint64_t)borrow;
}

// Conditionally subtract modulus m from r if r >= m. Returns nothing; in place.
template <size_t N>
FINLINE void cond_sub_mod(Limbs<N> &r, const Limbs<N> &m) {
    if (cmp_n<N>(r, m) >= 0) {
        Limbs<N> t;
        sub_n<N>(t, r, m);
        r = t;
    }
}

// Shift `src` (Ns limbs) left by `bits` and write the low Nd limbs of the
// result into dst (zero-padded or truncated as needed). bits may exceed a
// single limb width.
template <size_t Nd, size_t Ns>
FINLINE void shl_bits(Limbs<Nd> &dst, const Limbs<Ns> &src, unsigned bits) {
    dst.fill(0);
    unsigned limb_shift = bits / 64;
    unsigned bit_shift = bits % 64;
    for (size_t i = 0; i < Ns; i++) {
        size_t di = i + limb_shift;
        if (di >= Nd) break;
        uint64_t lo = (bit_shift == 0) ? src[i] : (src[i] << bit_shift);
        dst[di] |= lo;
        if (bit_shift != 0 && di + 1 < Nd) {
            uint64_t hi = src[i] >> (64 - bit_shift);
            dst[di + 1] |= hi;
        }
    }
}

// Shift `src` (Ns limbs) right by `bits`, result truncated/zero-padded to Nd limbs.
template <size_t Nd, size_t Ns>
FINLINE void shr_bits(Limbs<Nd> &dst, const Limbs<Ns> &src, unsigned bits) {
    dst.fill(0);
    unsigned limb_shift = bits / 64;
    unsigned bit_shift = bits % 64;
    for (size_t i = 0; i < Ns; i++) {
        if (i < limb_shift) continue;
        size_t di = i - limb_shift;
        if (di >= Nd) continue;
        uint64_t lo = (bit_shift == 0) ? src[i] : (src[i] >> bit_shift);
        dst[di] |= lo;
    }
    if (bit_shift != 0) {
        for (size_t i = 0; i < Ns; i++) {
            if (i < limb_shift + 1) continue;
            size_t di = i - limb_shift - 1;
            if (di >= Nd) continue;
            dst[di] |= (src[i] << (64 - bit_shift));
        }
    }
}

// Mask off all bits >= `bits` (keep only the low `bits` bits).
template <size_t N>
FINLINE void mask_bits(Limbs<N> &a, unsigned bits) {
    unsigned full_limbs = bits / 64;
    unsigned rem = bits % 64;
    for (size_t i = full_limbs + (rem ? 1 : 0); i < N; i++) a[i] = 0;
    if (rem && full_limbs < N) {
        uint64_t m = (rem == 64) ? ~0ULL : ((1ULL << rem) - 1);
        a[full_limbs] &= m;
    }
}

// Schoolbook multiply: out (2N limbs) = a * b, using unsigned __int128.
template <size_t N>
FINLINE void mul_schoolbook(Limbs<2 * N> &out, const Limbs<N> &a, const Limbs<N> &b) {
    out.fill(0);
    for (size_t i = 0; i < N; i++) {
        unsigned __int128 carry = 0;
        for (size_t j = 0; j < N; j++) {
            unsigned __int128 cur = (unsigned __int128)a[i] * b[j] + out[i + j] + carry;
            out[i + j] = (uint64_t)cur;
            carry = cur >> 64;
        }
        // propagate remaining carry
        size_t k = i + N;
        while (carry) {
            unsigned __int128 cur = (unsigned __int128)out[k] + carry;
            out[k] = (uint64_t)cur;
            carry = cur >> 64;
            k++;
        }
    }
}

// ---- GMP interop (I/O boundary only; not on the hot path) ----
template <size_t N>
inline void limbs_to_mpz(mpz_t out, const Limbs<N> &a) {
    mpz_import(out, N, -1, sizeof(uint64_t), 0, 0, a.data());
}

template <size_t N>
inline void mpz_to_limbs(Limbs<N> &out, const mpz_t in) {
    out.fill(0);
    mpz_export(out.data(), nullptr, -1, sizeof(uint64_t), 0, 0, in);
}

template <size_t N>
inline Limbs<N> hex_to_limbs(const std::string &hex) {
    mpz_t z;
    mpz_init(z);
    mpz_set_str(z, hex.c_str(), 16);
    Limbs<N> r{};
    mpz_to_limbs<N>(r, z);
    mpz_clear(z);
    return r;
}

template <size_t N>
inline std::string limbs_to_hex(const Limbs<N> &a) {
    mpz_t z;
    mpz_init(z);
    limbs_to_mpz<N>(z, a);
    char *s = mpz_get_str(nullptr, 16, z);
    std::string r(s);
    free(s);
    mpz_clear(z);
    return r;
}
