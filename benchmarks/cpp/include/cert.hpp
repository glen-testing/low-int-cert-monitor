// Single-certificate check: extract the EC public key natively via OpenSSL's
// EVP_PKEY/OSSL_PARAM APIs (no shelling out), then sweep with BSGS.
#pragma once
#include "common.hpp"
#include "curves_global.hpp"
#include "fast_driver.hpp"
#include <cstdio>
#include <cstring>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdexcept>
#include <vector>

struct CertPoint {
    CurveId curve;
    std::vector<unsigned char> x, y;
};

inline bool curve_name_to_id(const std::string &name, CurveId &out) {
    if (name == "prime256v1" || name == "P-256" || name == "secp256r1") { out = CurveId::P256; return true; }
    if (name == "secp384r1" || name == "P-384") { out = CurveId::P384; return true; }
    if (name == "secp521r1" || name == "P-521") { out = CurveId::P521; return true; }
    return false;
}

inline CertPoint extract_pubkey(const std::string &path) {
    FILE *f = fopen(path.c_str(), "rb");
    if (!f) throw std::runtime_error("cannot open " + path);
    std::vector<unsigned char> buf;
    unsigned char tmp[4096];
    size_t n;
    while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0) buf.insert(buf.end(), tmp, tmp + n);
    fclose(f);

    X509 *x509 = nullptr;
    // try DER first
    const unsigned char *p = buf.data();
    x509 = d2i_X509(nullptr, &p, (long)buf.size());
    if (!x509) {
        BIO *bio = BIO_new_mem_buf(buf.data(), (int)buf.size());
        x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
    }
    if (!x509) throw std::runtime_error("failed to parse certificate (tried DER and PEM)");

    EVP_PKEY *pkey = X509_get_pubkey(x509);
    if (!pkey) throw std::runtime_error("certificate has no public key");

    char group_name[80] = {0};
    size_t gnlen = 0;
    if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, group_name, sizeof(group_name), &gnlen))
        throw std::runtime_error("public key is not an EC key with a group name (not EC, or unsupported key type)");

    CurveId cid;
    if (!curve_name_to_id(group_name, cid)) throw std::runtime_error(std::string("unsupported curve: ") + group_name);

    unsigned char point_buf[256];
    size_t point_len = 0;
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, point_buf, sizeof(point_buf), &point_len))
        throw std::runtime_error("failed to extract EC public key octets");

    if (point_len < 2 || point_buf[0] != 0x04) throw std::runtime_error("public key is not uncompressed-point encoded");
    size_t coord_len = (point_len - 1) / 2;

    CertPoint cp;
    cp.curve = cid;
    cp.x.assign(point_buf + 1, point_buf + 1 + coord_len);
    cp.y.assign(point_buf + 1 + coord_len, point_buf + 1 + 2 * coord_len);

    EVP_PKEY_free(pkey);
    X509_free(x509);
    return cp;
}

inline std::string bytes_to_hex(const std::vector<unsigned char> &b) {
    static const char *hexd = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (auto c : b) {
        s.push_back(hexd[c >> 4]);
        s.push_back(hexd[c & 0xF]);
    }
    // strip leading zero nibbles/bytes to match the unpadded hex convention used elsewhere
    size_t i = 0;
    while (i + 1 < s.size() && s[i] == '0') i++;
    return s.substr(i);
}

// Returns d if found (<=maxN), else -1.
template <size_t N, Backend B>
long long sweep_single(const CurveParams<N> &c, const std::string &x_hex, const std::string &y_hex, long long maxN) {
    TargetRec t;
    t.curve = c.id;
    t.x_hex = x_hex;
    t.y_hex = y_hex;
    std::vector<TargetRec> v{t};
    std::vector<long long> d_out;
    run_bsgs_fast<N, B>(c, v, maxN, d_out);
    return d_out[0];
}

inline void run_cert_command(const std::string &path, long long maxN) {
    CertPoint cp = extract_pubkey(path);
    std::string xh = bytes_to_hex(cp.x), yh = bytes_to_hex(cp.y);
    long long d = -1;
    const char *curve_name = "?";
    if (cp.curve == CurveId::P256) { curve_name = "P-256"; d = sweep_single<4, Backend::MONT>(g_p256(), xh, yh, maxN); }
    else if (cp.curve == CurveId::P384) { curve_name = "P-384"; d = sweep_single<6, Backend::MONT>(g_p384(), xh, yh, maxN); }
    else if (cp.curve == CurveId::P521) { curve_name = "P-521"; d = sweep_single<9, Backend::MONT>(g_p521(), xh, yh, maxN); }

    printf("cert: %s\n", path.c_str());
    printf("curve: %s\n", curve_name);
    printf("x: %s\n", xh.c_str());
    printf("y: %s\n", yh.c_str());
    if (d >= 1) {
        printf("VERDICT: WEAK -- private key d = %lld (Q = d*G for small d, swept to %lld)\n", d, maxN);
    } else {
        printf("VERDICT: clean -- no d <= %lld found with d*G = Q\n", maxN);
    }
}
