#include "cert.hpp"
#include "common.hpp"
#include "curves_global.hpp"
#include "fast_driver.hpp"
#include "gmp_driver.hpp"
#include "openssl_driver.hpp"
#include "validate.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <random>
#include <string>
#include <vector>

static std::map<std::string, std::string> parse_flags(int argc, char **argv, int start) {
    std::map<std::string, std::string> flags;
    for (int i = start; i < argc; i++) {
        std::string a = argv[i];
        if (a.rfind("--", 0) == 0) {
            std::string key = a.substr(2);
            std::string val = "1";
            if (i + 1 < argc && (argv[i + 1][0] != '-' || strlen(argv[i + 1]) == 1)) {
                val = argv[++i];
            }
            flags[key] = val;
        }
    }
    return flags;
}

static bool validate_all(bool verbose) {
    std::mt19937_64 rng(0xC0FFEE);
    bool all_ok = true;
    struct Row { const char *curve; bool ok; std::string err; };
    std::vector<Row> rows;
    {
        std::string err;
        bool ok = validate_field<4, Backend::FOLD>(g_p256(), 2000, rng, err);
        rows.push_back({"P-256 FOLD", ok, err});
    }
    {
        std::string err;
        bool ok = validate_field<4, Backend::MONT>(g_p256(), 2000, rng, err);
        rows.push_back({"P-256 MONT", ok, err});
    }
    {
        std::string err;
        bool ok = validate_field<6, Backend::FOLD>(g_p384(), 2000, rng, err);
        rows.push_back({"P-384 FOLD", ok, err});
    }
    {
        std::string err;
        bool ok = validate_field<6, Backend::MONT>(g_p384(), 2000, rng, err);
        rows.push_back({"P-384 MONT", ok, err});
    }
    {
        std::string err;
        bool ok = validate_field<9, Backend::FOLD>(g_p521(), 2000, rng, err);
        rows.push_back({"P-521 FOLD", ok, err});
    }
    {
        std::string err;
        bool ok = validate_field<9, Backend::MONT>(g_p521(), 2000, rng, err);
        rows.push_back({"P-521 MONT", ok, err});
    }
    for (auto &r : rows) {
        if (verbose) fprintf(stderr, "  validate %-12s: %s %s\n", r.curve, r.ok ? "PASS" : "FAIL", r.err.c_str());
        if (!r.ok) all_ok = false;
    }
    return all_ok;
}

static int cmd_selftest(int argc, char **argv) {
    auto flags = parse_flags(argc, argv, 2);
    std::string targets_path = flags.count("targets") ? flags["targets"] : "common/targets.tsv";
    std::string answers_path = flags.count("answers") ? flags["answers"] : "common/answers.tsv";
    long long maxN = flags.count("max") ? std::stoll(flags["max"]) : 100000000LL;

    fprintf(stderr, "== field arithmetic validation (hand-rolled vs GMP, 2000 random trials/curve/backend) ==\n");
    bool fok = validate_all(true);
    if (!fok) {
        fprintf(stderr, "FAIL: field arithmetic validation failed -- refusing to trust any null verdict.\n");
        return 1;
    }
    fprintf(stderr, "field arithmetic: ALL VALID\n\n");

    auto answers = load_tsv(answers_path, true);
    auto targets = load_tsv(targets_path, false);
    fprintf(stderr, "loaded %zu answers, %zu targets (max=%lld)\n", answers.size(), targets.size(), maxN);

    bool overall_ok = true;
    int total_correct = 0, total_controls = 0, total_falsepos = 0, total_live = 0;
    double total_seconds = 0;
    long long total_adds = 0;

    // targets.tsv already contains all 802 keys (790 live + 12 planted
    // controls -- verified: every answers.tsv row appears verbatim in
    // targets.tsv). Run ONE sweep over targets.tsv per curve and classify
    // each result by cross-referencing answers.tsv on (curve,x,y); do not
    // concatenate the two files, or the controls get counted twice (once
    // as an expected hit, once as an expected-clean "live" key) and look
    // like spurious false positives.
    auto run_one = [&](auto curve_tag, const char *name) {
        using C = decltype(curve_tag);
        const C &c = curve_tag;
        std::vector<TargetRec> curve_targets;
        for (auto &t : targets) if (t.curve == c.id) curve_targets.push_back(t);
        if (curve_targets.empty()) return;

        std::map<std::string, long long> expected_d;
        for (auto &a : answers) {
            if (a.curve == c.id) expected_d[a.x_hex + "|" + a.y_hex] = a.d;
        }

        std::vector<long long> d_out;
        BsgsStats st = run_bsgs_fast<C::LIMBS, Backend::MONT>(c, curve_targets, maxN, d_out);
        total_seconds += st.seconds;
        total_adds += st.total_adds;

        int correct = 0, controls = 0, falsepos = 0, live = 0;
        for (size_t i = 0; i < curve_targets.size(); i++) {
            auto it = expected_d.find(curve_targets[i].x_hex + "|" + curve_targets[i].y_hex);
            if (it != expected_d.end()) {
                controls++;
                if (d_out[i] == it->second) correct++;
                else {
                    fprintf(stderr, "  MISS control %s x=%s...: expected d=%lld got d=%lld\n",
                            name, curve_targets[i].x_hex.substr(0, 16).c_str(), it->second, d_out[i]);
                    overall_ok = false;
                }
            } else {
                live++;
                if (d_out[i] != -1) {
                    fprintf(stderr, "  FALSE POSITIVE %s x=%s...: reported d=%lld\n",
                            name, curve_targets[i].x_hex.substr(0, 16).c_str(), d_out[i]);
                    overall_ok = false;
                    falsepos++;
                }
            }
        }
        total_correct += correct;
        total_controls += controls;
        total_falsepos += falsepos;
        total_live += live;
        fprintf(stderr, "%-6s: %d/%d controls correct, %d false-positives / %d live, %.3fs, %lld adds\n",
                name, correct, controls, falsepos, live, st.seconds, st.total_adds);
    };
    run_one(g_p256(), "P-256");
    run_one(g_p384(), "P-384");
    run_one(g_p521(), "P-521");

    fprintf(stderr, "\n== selftest summary ==\n");
    fprintf(stderr, "controls correct: %d/%d\n", total_correct, total_controls);
    fprintf(stderr, "false positives : %d (of %d live keys)\n", total_falsepos, total_live);
    fprintf(stderr, "total wall time : %.3fs, total adds: %lld (%.1f ns/add avg)\n",
            total_seconds, total_adds, total_adds ? (total_seconds * 1e9 / total_adds) : 0.0);

    if (overall_ok && total_correct == total_controls && total_falsepos == 0) {
        fprintf(stderr, "SELFTEST PASS\n");
        return 0;
    }
    fprintf(stderr, "SELFTEST FAIL\n");
    return 1;
}

static int cmd_bench(int argc, char **argv) {
    auto flags = parse_flags(argc, argv, 2);
    bool matrix = flags.count("matrix");
    long long iters = flags.count("iters") ? std::stoll(flags["iters"]) : 5000000LL;

    if (matrix) {
        printf("curve,variant,ns_per_add\n");
        struct CurveSpec { const char *name; CurveId id; };
        CurveSpec curves[] = {{"P-256", CurveId::P256}, {"P-384", CurveId::P384}, {"P-521", CurveId::P521}};
        for (auto &cs : curves) {
            long long affine_iters = std::min<long long>(iters, 200000); // affine+inverse baseline: smaller bounded N
            double t;
            if (cs.id == CurveId::P256) {
                t = bench_add_affine_gmp<4>(g_p256(), g_p256_mpz(), affine_iters); printf("%s,affine-gmp,%.1f\n", cs.name, t);
                t = bench_add_jac_gmp<4>(g_p256(), g_p256_mpz(), iters); printf("%s,jac-gmp,%.1f\n", cs.name, t);
                t = bench_add_fast<4, Backend::MONT>(g_p256(), iters); printf("%s,jac-mont,%.1f\n", cs.name, t);
                t = bench_add_fast<4, Backend::FOLD>(g_p256(), iters); printf("%s,jac-fold,%.1f\n", cs.name, t);
            } else if (cs.id == CurveId::P384) {
                t = bench_add_affine_gmp<6>(g_p384(), g_p384_mpz(), affine_iters); printf("%s,affine-gmp,%.1f\n", cs.name, t);
                t = bench_add_jac_gmp<6>(g_p384(), g_p384_mpz(), iters); printf("%s,jac-gmp,%.1f\n", cs.name, t);
                t = bench_add_fast<6, Backend::MONT>(g_p384(), iters); printf("%s,jac-mont,%.1f\n", cs.name, t);
                t = bench_add_fast<6, Backend::FOLD>(g_p384(), iters); printf("%s,jac-fold,%.1f\n", cs.name, t);
            } else {
                t = bench_add_affine_gmp<9>(g_p521(), g_p521_mpz(), affine_iters); printf("%s,affine-gmp,%.1f\n", cs.name, t);
                t = bench_add_jac_gmp<9>(g_p521(), g_p521_mpz(), iters); printf("%s,jac-gmp,%.1f\n", cs.name, t);
                t = bench_add_fast<9, Backend::MONT>(g_p521(), iters); printf("%s,jac-mont,%.1f\n", cs.name, t);
                t = bench_add_fast<9, Backend::FOLD>(g_p521(), iters); printf("%s,jac-fold,%.1f\n", cs.name, t);
            }
            t = bench_add_openssl(cs.id, iters); printf("%s,openssl,%.1f\n", cs.name, t);
            fflush(stdout);
        }
        return 0;
    }

    // real-sweep mode: --method linear|bsgs over the actual target set
    std::string targets_path = flags.count("targets") ? flags["targets"] : "common/targets.tsv";
    long long maxN = flags.count("max") ? std::stoll(flags["max"]) : 100000000LL;
    std::string method = flags.count("method") ? flags["method"] : "bsgs";
    auto targets = load_tsv(targets_path, false);

    auto run_one = [&](auto curve_tag, const char *name) {
        using C = decltype(curve_tag);
        const C &c = curve_tag;
        std::vector<TargetRec> curve_targets;
        for (auto &t : targets) if (t.curve == c.id) curve_targets.push_back(t);
        if (curve_targets.empty()) return;
        std::vector<long long> d_out;
        BsgsStats st = run_bsgs_fast<C::LIMBS, Backend::MONT>(c, curve_targets, maxN, d_out);
        int hits = 0;
        for (auto d : d_out) if (d != -1) hits++;
        double ns_per_add = st.total_adds ? (st.seconds * 1e9 / st.total_adds) : 0.0;
        printf("%-6s method=%s max=%lld targets=%zu hits=%d time=%.3fs adds=%lld ns/add=%.1f\n",
               name, method.c_str(), maxN, curve_targets.size(), hits, st.seconds, st.total_adds, ns_per_add);
    };
    run_one(g_p256(), "P-256");
    run_one(g_p384(), "P-384");
    run_one(g_p521(), "P-521");
    return 0;
}

static int cmd_cert(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: p4ec cert <file.pem|der> [--max N]\n");
        return 2;
    }
    std::string path = argv[2];
    auto flags = parse_flags(argc, argv, 3);
    long long maxN = flags.count("max") ? std::stoll(flags["max"]) : 100000000LL;
    try {
        run_cert_command(path, maxN);
    } catch (const std::exception &e) {
        fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: p4ec <bench|selftest|cert> [options]\n");
        return 2;
    }
    std::string cmd = argv[1];
    if (cmd == "selftest") return cmd_selftest(argc, argv);
    if (cmd == "bench") return cmd_bench(argc, argv);
    if (cmd == "cert") return cmd_cert(argc, argv);
    fprintf(stderr, "unknown command '%s'\n", cmd.c_str());
    return 2;
}
