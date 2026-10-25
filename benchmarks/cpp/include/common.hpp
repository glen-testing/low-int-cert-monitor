#pragma once
#include "curve_params.hpp"
#include <chrono>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

struct TargetRec {
    CurveId curve;
    std::string curve_name;
    std::string x_hex, y_hex;
    long long d = -1; // -1 if unknown (targets.tsv), set for answers.tsv
};

inline bool parse_curve_name(const std::string &s, CurveId &out) {
    if (s == "P-256") { out = CurveId::P256; return true; }
    if (s == "P-384") { out = CurveId::P384; return true; }
    if (s == "P-521") { out = CurveId::P521; return true; }
    return false;
}

inline std::vector<std::string> split_tab(const std::string &line) {
    std::vector<std::string> out;
    std::stringstream ss(line);
    std::string tok;
    while (std::getline(ss, tok, '\t')) out.push_back(tok);
    return out;
}

inline std::vector<TargetRec> load_tsv(const std::string &path, bool has_d) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open " + path);
    std::vector<TargetRec> out;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto cols = split_tab(line);
        if (cols.size() < 3) continue;
        TargetRec t;
        t.curve_name = cols[0];
        if (!parse_curve_name(cols[0], t.curve)) continue;
        t.x_hex = cols[1];
        t.y_hex = cols[2];
        if (has_d && cols.size() >= 4) t.d = std::stoll(cols[3]);
        out.push_back(t);
    }
    return out;
}

using Clock = std::chrono::steady_clock;
inline double elapsed_ns(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::nano>(b - a).count();
}
