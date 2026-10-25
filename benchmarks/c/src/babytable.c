#include "babytable.h"
#include <stdlib.h>
#include <string.h>

static size_t next_pow2(size_t v) { size_t p = 1; while (p < v) p <<= 1; return p; }

static uint64_t mix64(uint64_t x) {
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static uint64_t fe_hash(const fe_t x, int n) {
    uint64_t h = 0x9E3779B97F4A7C15ULL;
    for (int i = 0; i < n; i++) h = mix64(h ^ x[i]);
    return h;
}

void bt_init(babytable_t *t, size_t min_capacity) {
    t->cap = next_pow2(min_capacity * 2 + 16); // load factor <= ~0.5
    t->keys = calloc(t->cap, sizeof(fe_t));
    t->vals = calloc(t->cap, sizeof(uint64_t));
}

void bt_free(babytable_t *t) {
    free(t->keys); free(t->vals);
    t->keys = NULL; t->vals = NULL; t->cap = 0;
}

void bt_insert(babytable_t *t, const fe_t x, uint64_t j, const curve_params_t *cp) {
    uint64_t h = fe_hash(x, cp->n) & (t->cap - 1);
    while (t->vals[h] != 0) h = (h + 1) & (t->cap - 1);
    bn_copy(t->keys[h], x, cp->n);
    t->vals[h] = j;
}

int bt_lookup(const babytable_t *t, const fe_t x, uint64_t *j_out, const curve_params_t *cp) {
    uint64_t h = fe_hash(x, cp->n) & (t->cap - 1);
    while (t->vals[h] != 0) {
        if (bn_cmp(t->keys[h], x, cp->n) == 0) { *j_out = t->vals[h]; return 1; }
        h = (h + 1) & (t->cap - 1);
    }
    return 0;
}
