// Open-addressing (linear probing) hash set for the BSGS baby-step table,
// keyed by plain-representation x-coordinate limbs.
#pragma once
#include "bigint.hpp"
#include <vector>

template <size_t N>
struct BabyTable {
    size_t mask = 0;
    std::vector<uint8_t> occ;
    std::vector<Limbs<N>> xs, ys;
    std::vector<long long> js;

    void init(size_t m_b) {
        size_t cap = 1;
        while (cap < m_b * 2 + 1) cap <<= 1;
        mask = cap - 1;
        occ.assign(cap, 0);
        xs.resize(cap);
        ys.resize(cap);
        js.assign(cap, 0);
    }

    static uint64_t hash_limbs(const Limbs<N> &x) {
        uint64_t h = 1469598103934665603ULL;
        for (auto v : x) {
            h ^= v;
            h *= 1099511628211ULL;
        }
        return h;
    }

    void insert(const Limbs<N> &x, const Limbs<N> &y, long long j) {
        size_t idx = hash_limbs(x) & mask;
        while (occ[idx]) idx = (idx + 1) & mask;
        occ[idx] = 1;
        xs[idx] = x;
        ys[idx] = y;
        js[idx] = j;
    }

    bool find(const Limbs<N> &x, Limbs<N> &y_out, long long &j_out) const {
        size_t idx = hash_limbs(x) & mask;
        while (occ[idx]) {
            if (cmp_n<N>(xs[idx], x) == 0) {
                y_out = ys[idx];
                j_out = js[idx];
                return true;
            }
            idx = (idx + 1) & mask;
        }
        return false;
    }
};
