// Open-addressing hash set for the BSGS baby table: key = affine x-coordinate
// (fe_t), value = baby-step index j (uint64_t, j>=1; 0 is the "empty" sentinel
// so insertion order never needs a separate "used" bitmap).
#ifndef BABYTABLE_H
#define BABYTABLE_H
#include "field_fast.h"

typedef struct {
    fe_t *keys;
    uint64_t *vals; // 0 == empty slot
    size_t cap;     // power of two
} babytable_t;

void bt_init(babytable_t *t, size_t min_capacity);
void bt_free(babytable_t *t);
void bt_insert(babytable_t *t, const fe_t x, uint64_t j, const curve_params_t *cp);
// Returns 1 and sets *j_out if found, else 0.
int bt_lookup(const babytable_t *t, const fe_t x, uint64_t *j_out, const curve_params_t *cp);

#endif
