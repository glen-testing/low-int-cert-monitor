#include "openssl_ref.h"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <gmp.h>

static int nid_for(curve_id_t cid) {
    switch (cid) {
        case CURVE_P256: return NID_X9_62_prime256v1;
        case CURVE_P384: return NID_secp384r1;
        case CURVE_P521: return NID_secp521r1;
        default: return 0;
    }
}

double openssl_bench_add_ns(curve_id_t cid, long iterations) {
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(nid_for(cid));
    const EC_POINT *gen = EC_GROUP_get0_generator(grp);
    EC_POINT *acc = EC_POINT_dup(gen, grp);
    BN_CTX *bctx = BN_CTX_new();
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (long i = 0; i < iterations; i++) EC_POINT_add(grp, acc, acc, gen, bctx);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ns = (double)(t1.tv_sec - t0.tv_sec) * 1e9 + (double)(t1.tv_nsec - t0.tv_nsec);
    EC_POINT_free(acc); BN_CTX_free(bctx); EC_GROUP_free(grp);
    return ns / (double)iterations;
}

static void shell_quote(char *out, size_t outsz, const char *in) {
    size_t o = 0;
    out[o++] = '\'';
    for (; *in && o + 6 < outsz; in++) {
        if (*in == '\'') { memcpy(out + o, "'\\''", 4); o += 4; }
        else out[o++] = *in;
    }
    out[o++] = '\'';
    out[o] = '\0';
}

int cert_extract_pubkey(const char *path, curve_id_t *cid, fe_t x, fe_t y) {
    char qpath[2048];
    shell_quote(qpath, sizeof(qpath), path);
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
        "openssl x509 -in %s -noout -pubkey 2>/dev/null | openssl pkey -pubin -noout -text 2>/dev/null", qpath);
    FILE *fp = popen(cmd, "r");
    if (!fp) return 0;

    char line[512];
    char curve_name[64] = {0};
    char hexbuf[4096] = {0};
    size_t hexlen = 0;
    int in_pub = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "NIST CURVE:")) {
            char *p = strstr(line, "NIST CURVE:") + strlen("NIST CURVE:");
            while (*p == ' ') p++;
            size_t l = strcspn(p, "\r\n");
            if (l >= sizeof(curve_name)) l = sizeof(curve_name) - 1;
            memcpy(curve_name, p, l); curve_name[l] = 0;
            continue;
        }
        if (strstr(line, "pub:")) { in_pub = 1; continue; }
        if (in_pub) {
            // stop at the next field (no leading whitespace+hex:hex pattern)
            int is_hexline = 1;
            for (char *q = line; *q && *q != '\n'; q++) {
                if (!( (*q==' ')||(*q=='\t')||(*q==':')||isxdigit((unsigned char)*q) )) { is_hexline = 0; break; }
            }
            if (!is_hexline) { in_pub = 0; continue; }
            for (char *q = line; *q; q++) {
                if (isxdigit((unsigned char)*q) && hexlen + 2 < sizeof(hexbuf)) hexbuf[hexlen++] = *q;
            }
        }
    }
    pclose(fp);

    if (!curve_name[0] || hexlen < 4) return 0;
    if (!curve_name_to_id(curve_name, cid)) return 0;

    // hexbuf should be "04" + X + Y (uncompressed point)
    if (hexbuf[0] != '0' || hexbuf[1] != '4') return 0;
    const curve_params_t *cp = &g_curves[*cid];
    size_t coord_hexlen = ((size_t)(cp->bits + 7) / 8) * 2;
    if (hexlen < 2 + 2 * coord_hexlen) return 0;

    mpz_t vx, vy;
    char xs[300], ys[300];
    memcpy(xs, hexbuf + 2, coord_hexlen); xs[coord_hexlen] = 0;
    memcpy(ys, hexbuf + 2 + coord_hexlen, coord_hexlen); ys[coord_hexlen] = 0;
    mpz_init_set_str(vx, xs, 16);
    mpz_init_set_str(vy, ys, 16);
    bn_zero(x, cp->n); bn_zero(y, cp->n);
    size_t cnt = 0;
    mpz_export(x, &cnt, -1, sizeof(uint64_t), 0, 0, vx);
    mpz_export(y, &cnt, -1, sizeof(uint64_t), 0, 0, vy);
    mpz_clear(vx); mpz_clear(vy);
    return 1;
}
