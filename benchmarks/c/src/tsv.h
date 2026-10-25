#ifndef TSV_H
#define TSV_H
#include "field_fast.h"

typedef struct {
    curve_id_t curve;
    fe_t x, y;
    uint64_t d; // only meaningful when loaded from answers.tsv; 0 otherwise
} key_entry_t;

// Loads a TSV file ("curve<TAB>x_hex<TAB>y_hex[<TAB>d]"), skipping blank/'#' lines.
// has_d: 1 for answers.tsv (reads the 4th column), 0 for targets.tsv.
// Returns malloc'd array in *out (caller frees) and sets *count. Returns 1 on success.
int load_tsv(const char *path, key_entry_t **out, int *count, int has_d);

#endif
