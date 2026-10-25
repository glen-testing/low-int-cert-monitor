#include "tsv.h"
#include "curves.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

static void hex_to_fe(fe_t out, const char *hex, const curve_params_t *cp) {
    mpz_t v;
    mpz_init_set_str(v, hex, 16);
    bn_zero(out, cp->n);
    size_t count = 0;
    mpz_export(out, &count, -1, sizeof(uint64_t), 0, 0, v);
    mpz_clear(v);
}

int load_tsv(const char *path, key_entry_t **out, int *count, int has_d) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 0; }

    size_t cap = 1024, n = 0;
    key_entry_t *arr = malloc(cap * sizeof(key_entry_t));
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;

        char curve_name[32] = {0}, xhex[300] = {0}, yhex[300] = {0};
        unsigned long long dval = 0;
        int nf;
        if (has_d) nf = sscanf(line, "%31[^\t]\t%299[^\t]\t%299[^\t]\t%llu", curve_name, xhex, yhex, &dval);
        else nf = sscanf(line, "%31[^\t]\t%299[^\t]\t%299[^\t\n]", curve_name, xhex, yhex);
        if (nf < 3) continue;

        curve_id_t cid;
        if (!curve_name_to_id(curve_name, &cid)) {
            fprintf(stderr, "unknown curve '%s' in %s, skipping line\n", curve_name, path);
            continue;
        }
        if (n == cap) { cap *= 2; arr = realloc(arr, cap * sizeof(key_entry_t)); }
        arr[n].curve = cid;
        hex_to_fe(arr[n].x, xhex, &g_curves[cid]);
        hex_to_fe(arr[n].y, yhex, &g_curves[cid]);
        arr[n].d = has_d ? (uint64_t)dval : 0;
        n++;
    }
    fclose(f);
    *out = arr;
    *count = (int)n;
    return 1;
}
