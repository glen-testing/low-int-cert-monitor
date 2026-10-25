#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <inttypes.h>
#include <gmp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

#include "curves.h"
#include "field_fast.h"
#include "point_fast.h"
#include "point_gmp.h"
#include "field_gmp.h"
#include "bsgs.h"
#include "tsv.h"
#include "openssl_ref.h"

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static int nid_for(curve_id_t cid) {
    switch (cid) {
        case CURVE_P256: return NID_X9_62_prime256v1;
        case CURVE_P384: return NID_secp384r1;
        case CURVE_P521: return NID_secp521r1;
        default: return 0;
    }
}

// ---------------------------------------------------------------------------
// ns/add microbenchmarks per variant
// ---------------------------------------------------------------------------
static double bench_jac_fast(const curve_params_t *cp, long iters) {
    affine_t g = {0};
    fe_copy_c(g.x, cp->gx, cp); fe_copy_c(g.y, cp->gy, cp);
    jac_t acc; jac_from_affine(&acc, &g, cp);
    point_double_jac(&acc, &acc, cp); // bootstrap past the P==Q edge case
    double t0 = now_ns();
    for (long i = 0; i < iters; i++) point_add_mixed(&acc, &acc, &g, cp);
    double t1 = now_ns();
    return (t1 - t0) / (double)iters;
}

static double bench_jac_gmp(const curve_params_t *cp, long iters) {
    affine_gmp_t g; affg_init(&g);
    mpz_set(g.x, cp->GX); mpz_set(g.y, cp->GY);
    jac_gmp_t acc; jacg_init(&acc);
    jacg_from_affine(&acc, &g, cp);
    point_double_jacg(&acc, &acc, cp);
    double t0 = now_ns();
    for (long i = 0; i < iters; i++) point_add_mixed_g(&acc, &acc, &g, cp);
    double t1 = now_ns();
    jacg_clear(&acc); affg_clear(&g);
    return (t1 - t0) / (double)iters;
}

static double bench_affine_gmp(const curve_params_t *cp, long iters) {
    affine_gmp_t g; affg_init(&g);
    mpz_set(g.x, cp->GX); mpz_set(g.y, cp->GY);
    affine_gmp_t acc; affg_init(&acc);
    affine_double_g(&acc, &g, cp); // bootstrap
    double t0 = now_ns();
    for (long i = 0; i < iters; i++) affine_add_g(&acc, &acc, &g, cp);
    double t1 = now_ns();
    affg_clear(&acc); affg_clear(&g);
    return (t1 - t0) / (double)iters;
}

static void print_bench_line(const curve_params_t *cp, const char *variant, long iters,
                              double ns_per_add, uint64_t max_d) {
    double full_job_s = ns_per_add * (double)max_d / 1e9;
    fprintf(stderr, "curve=%-6s variant=%-11s adds=%-9ld ns/add=%10.2f  extrapolated(d<=%" PRIu64 ")=%.2fs\n",
            cp->name, variant, iters, ns_per_add, max_d, full_job_s);
}

// ---------------------------------------------------------------------------
// validation: fast field vs GMP, fast point-mul vs OpenSSL
// ---------------------------------------------------------------------------
static int validate_against_openssl(const curve_params_t *cp, int trials) {
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(nid_for((curve_id_t)(cp - g_curves)));
    EC_POINT *r = EC_POINT_new(grp);
    BN_CTX *bctx = BN_CTX_new();
    BIGNUM *bd = BN_new();
    BIGNUM *bx = BN_new(), *by = BN_new();
    srand(1234567u + cp->n);
    int ok = 1;
    for (int t = 0; t < trials && ok; t++) {
        uint64_t d = ((uint64_t)rand() << 32) ^ (uint64_t)rand();
        if (d == 0) d = 1;
        jac_t R; point_mul_u64(&R, d, cp);
        affine_t A; batch_normalize(&A, &R, 1, cp);

        BN_set_word(bd, 0); // build d as BIGNUM via repeated shifts (portable, no 64-bit BN_set_word guarantee issues)
        for (int b = 63; b >= 0; b--) { BN_lshift1(bd, bd); if ((d >> b) & 1) BN_add_word(bd, 1); }
        EC_POINT_mul(grp, r, bd, NULL, NULL, bctx);
        EC_POINT_get_affine_coordinates(grp, r, bx, by, bctx);

        unsigned char xb[200], yb[200];
        int xl = BN_bn2bin(bx, xb), yl = BN_bn2bin(by, yb);
        fe_t ex, ey; fe_zero_c(ex, cp); fe_zero_c(ey, cp);
        for (int i = 0; i < xl; i++) ((unsigned char*)ex)[i] = xb[xl - 1 - i]; // little-endian limb bytes
        for (int i = 0; i < yl; i++) ((unsigned char*)ey)[i] = yb[yl - 1 - i];
        if (bn_cmp(A.x, ex, cp->n) != 0 || bn_cmp(A.y, ey, cp->n) != 0) {
            fprintf(stderr, "MISMATCH vs OpenSSL: curve=%s d=%" PRIu64 "\n", cp->name, d);
            ok = 0;
        }
    }
    BN_free(bd); BN_free(bx); BN_free(by);
    EC_POINT_free(r); BN_CTX_free(bctx); EC_GROUP_free(grp);
    return ok;
}

// ---------------------------------------------------------------------------
// bench subcommand
// ---------------------------------------------------------------------------
static int cmd_bench(int argc, char **argv) {
    uint64_t max_d = 100000000ULL;
    long adds = 3000000;
    char method[32] = "linear";
    char variant[32] = "jac-fast";
    char curve_filter[16] = "all";
    char targets_path[1024] = "";

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--max") && i + 1 < argc) max_d = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--adds") && i + 1 < argc) adds = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--method") && i + 1 < argc) snprintf(method, sizeof(method), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--variant") && i + 1 < argc) snprintf(variant, sizeof(variant), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--curve") && i + 1 < argc) snprintf(curve_filter, sizeof(curve_filter), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--targets") && i + 1 < argc) snprintf(targets_path, sizeof(targets_path), "%s", argv[++i]);
    }

    curves_init();

    if (!strcmp(method, "linear")) {
        for (int c = 0; c < CURVE_COUNT; c++) {
            if (strcmp(curve_filter, "all") && strcmp(curve_filter, g_curves[c].name)) continue;
            const curve_params_t *cp = &g_curves[c];
            double ns;
            if (!strcmp(variant, "jac-fast")) ns = bench_jac_fast(cp, adds);
            else if (!strcmp(variant, "jac-gmp")) ns = bench_jac_gmp(cp, adds);
            else if (!strcmp(variant, "affine-gmp")) ns = bench_affine_gmp(cp, adds);
            else if (!strcmp(variant, "openssl")) ns = openssl_bench_add_ns((curve_id_t)c, adds);
            else { fprintf(stderr, "unknown variant %s\n", variant); return 2; }
            print_bench_line(cp, variant, adds, ns, max_d);
        }
        return 0;
    }

    if (!strcmp(method, "bsgs")) {
        if (!targets_path[0]) { fprintf(stderr, "bsgs method requires --targets\n"); return 2; }
        key_entry_t *entries; int n;
        if (!load_tsv(targets_path, &entries, &n, 0)) return 2;
        for (int c = 0; c < CURVE_COUNT; c++) {
            if (strcmp(curve_filter, "all") && strcmp(curve_filter, g_curves[c].name)) continue;
            const curve_params_t *cp = &g_curves[c];
            int cnt = 0;
            for (int i = 0; i < n; i++) if (entries[i].curve == c) cnt++;
            if (!cnt) continue;

            bsgs_ctx_t ctx;
            double tb0 = now_ns();
            bsgs_build(&ctx, cp, max_d);
            double tb1 = now_ns();

            int hits = 0;
            double ts0 = now_ns();
            for (int i = 0; i < n; i++) {
                if (entries[i].curve != c) continue;
                affine_t t; fe_copy_c(t.x, entries[i].x, cp); fe_copy_c(t.y, entries[i].y, cp);
                uint64_t d;
                if (bsgs_search(&ctx, &t, &d)) {
                    hits++;
                    mpz_t X, Y; mpz_init(X); mpz_init(Y);
                    mpz_import(X, cp->n, -1, sizeof(uint64_t), 0, 0, t.x);
                    mpz_import(Y, cp->n, -1, sizeof(uint64_t), 0, 0, t.y);
                    gmp_printf("HIT curve=%s d=%" PRIu64 " x=%Zx\n", cp->name, d, X);
                    mpz_clear(X); mpz_clear(Y);
                }
            }
            double ts1 = now_ns();
            double build_s = (tb1 - tb0) / 1e9, search_s = (ts1 - ts0) / 1e9;
            double giant_adds = (double)ctx.M * (double)cnt;
            double ns_per_add = (ts1 - ts0) / giant_adds;
            fprintf(stderr, "curve=%-6s bsgs M=%" PRIu64 " targets=%d hits=%d build=%.3fs search=%.3fs ns/add(giant-step)=%.1f\n",
                    cp->name, ctx.M, cnt, hits, build_s, search_s, ns_per_add);
            bsgs_free(&ctx);
        }
        free(entries);
        return 0;
    }

    fprintf(stderr, "unknown method %s\n", method);
    return 2;
}

// ---------------------------------------------------------------------------
// selftest subcommand
// ---------------------------------------------------------------------------
static int cmd_selftest(int argc, char **argv) {
    char targets_path[1024] = "", answers_path[1024] = "";
    uint64_t max_d = 100000000ULL;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--targets") && i + 1 < argc) snprintf(targets_path, sizeof(targets_path), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--answers") && i + 1 < argc) snprintf(answers_path, sizeof(answers_path), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--max") && i + 1 < argc) max_d = strtoull(argv[++i], NULL, 10);
    }
    if (!targets_path[0] || !answers_path[0]) { fprintf(stderr, "selftest requires --targets and --answers\n"); return 2; }

    curves_init();
    int all_ok = 1;

    fprintf(stderr, "== validating hand-rolled fast field vs GMP ==\n");
    for (int c = 0; c < CURVE_COUNT; c++) {
        int ok = field_fast_selftest(&g_curves[c], 2000);
        fprintf(stderr, "  %-6s field_fast_selftest: %s\n", g_curves[c].name, ok ? "PASS" : "FAIL");
        all_ok &= ok;
    }

    fprintf(stderr, "== validating fast point arithmetic vs OpenSSL EC_POINT_mul ==\n");
    for (int c = 0; c < CURVE_COUNT; c++) {
        int ok = validate_against_openssl(&g_curves[c], 40);
        fprintf(stderr, "  %-6s validate_against_openssl: %s\n", g_curves[c].name, ok ? "PASS" : "FAIL");
        all_ok &= ok;
    }

    if (!all_ok) {
        fprintf(stderr, "ABORT: field/point validation failed, refusing to trust BSGS results.\n");
        return 1;
    }

    key_entry_t *targets, *answers;
    int n_targets, n_answers;
    if (!load_tsv(targets_path, &targets, &n_targets, 0)) return 2;
    if (!load_tsv(answers_path, &answers, &n_answers, 1)) return 2;

    fprintf(stderr, "== BSGS sweep: %d targets, max=%" PRIu64 " ==\n", n_targets, max_d);
    int total_hits = 0, correct_controls = 0, false_positives = 0, missed_controls = 0;
    for (int c = 0; c < CURVE_COUNT; c++) {
        const curve_params_t *cp = &g_curves[c];
        int cnt = 0;
        for (int i = 0; i < n_targets; i++) if (targets[i].curve == c) cnt++;
        if (!cnt) continue;
        bsgs_ctx_t ctx;
        double t0 = now_ns();
        bsgs_build(&ctx, cp, max_d);
        for (int i = 0; i < n_targets; i++) {
            if (targets[i].curve != c) continue;
            affine_t t; fe_copy_c(t.x, targets[i].x, cp); fe_copy_c(t.y, targets[i].y, cp);
            uint64_t d;
            int found = bsgs_search(&ctx, &t, &d);

            // is this target one of the known answers?
            int is_answer = 0; uint64_t expected_d = 0;
            for (int a = 0; a < n_answers; a++) {
                if (answers[a].curve == c && bn_cmp(answers[a].x, targets[i].x, cp->n) == 0 &&
                    bn_cmp(answers[a].y, targets[i].y, cp->n) == 0) { is_answer = 1; expected_d = answers[a].d; break; }
            }
            if (found) {
                total_hits++;
                if (is_answer && d == expected_d) correct_controls++;
                else if (is_answer) { fprintf(stderr, "  WRONG d for a control key: curve=%s got d=%" PRIu64 " want=%" PRIu64 "\n", cp->name, d, expected_d); false_positives++; }
                else { fprintf(stderr, "  FALSE POSITIVE on a live key: curve=%s d=%" PRIu64 "\n", cp->name, d); false_positives++; }
            } else if (is_answer) {
                fprintf(stderr, "  MISSED control key: curve=%s expected d=%" PRIu64 "\n", cp->name, expected_d);
                missed_controls++;
            }
        }
        double t1 = now_ns();
        fprintf(stderr, "  %-6s %d targets swept in %.3fs (M=%" PRIu64 ")\n", cp->name, cnt, (t1 - t0) / 1e9, ctx.M);
        bsgs_free(&ctx);
    }

    fprintf(stderr, "== result: hits=%d correct_controls=%d/%d false_positives=%d missed_controls=%d ==\n",
            total_hits, correct_controls, n_answers, false_positives, missed_controls);

    free(targets); free(answers);
    int pass = (correct_controls == n_answers) && (false_positives == 0) && (missed_controls == 0);
    fprintf(stderr, pass ? "SELFTEST PASS\n" : "SELFTEST FAIL\n");
    return pass ? 0 : 1;
}

// ---------------------------------------------------------------------------
// cert subcommand
// ---------------------------------------------------------------------------
static int cmd_cert(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s cert <file.pem|der> [--max N]\n", argv[0]); return 2; }
    const char *path = argv[2];
    uint64_t max_d = 100000000ULL;
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--max") && i + 1 < argc) max_d = strtoull(argv[++i], NULL, 10);
    }
    curves_init();
    curve_id_t cid;
    fe_t x, y;
    if (!cert_extract_pubkey(path, &cid, x, y)) {
        fprintf(stderr, "could not extract an EC public key from %s (only P-256/P-384/P-521 supported)\n", path);
        return 2;
    }
    const curve_params_t *cp = &g_curves[cid];
    fprintf(stderr, "curve=%s sweeping d<=%" PRIu64 "...\n", cp->name, max_d);
    bsgs_ctx_t ctx;
    bsgs_build(&ctx, cp, max_d);
    affine_t t; fe_copy_c(t.x, x, cp); fe_copy_c(t.y, y, cp);
    uint64_t d;
    if (bsgs_search(&ctx, &t, &d)) {
        printf("WEAK KEY: curve=%s d=%" PRIu64 "  (Q = d*G -- this certificate's private key is a trivially small integer)\n", cp->name, d);
        bsgs_free(&ctx);
        return 1;
    } else {
        printf("clean: curve=%s, no small-d relationship found for d<=%" PRIu64 "\n", cp->name, max_d);
        bsgs_free(&ctx);
        return 0;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <bench|selftest|cert> ...\n", argv[0]);
        return 2;
    }
    if (!strcmp(argv[1], "bench")) return cmd_bench(argc, argv);
    if (!strcmp(argv[1], "selftest")) return cmd_selftest(argc, argv);
    if (!strcmp(argv[1], "cert")) return cmd_cert(argc, argv);
    fprintf(stderr, "unknown subcommand %s\n", argv[1]);
    return 2;
}
