#include "curves.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

curve_params_t g_curves[CURVE_COUNT];

static const struct {
    const char *name; int bits; int n;
    const char *p, *b, *gx, *gy, *order;
} raw[CURVE_COUNT] = {
    { "P-256", 256, 4,
      "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
      "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
      "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
      "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
      "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551" },
    { "P-384", 384, 6,
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
      "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
      "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
      "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973" },
    { "P-521", 521, 9,
      "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
      "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
      "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
      "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
      "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409" },
};

// Export mpz -> fixed n-limb little-endian uint64 array (zero padded).
static void mpz_to_limbs(uint64_t *out, int n, const mpz_t v) {
    bn_zero(out, n);
    size_t count = 0;
    mpz_export(out, &count, -1 /*little word order*/, sizeof(uint64_t), 0 /*native endian within word*/, 0, v);
    if (count > (size_t)n) { fprintf(stderr, "curve constant too large for %d limbs\n", n); exit(1); }
}

void curves_init(void) {
    for (int i = 0; i < CURVE_COUNT; i++) {
        curve_params_t *c = &g_curves[i];
        memset(c, 0, sizeof(*c));
        c->name = raw[i].name;
        c->bits = raw[i].bits;
        c->n = raw[i].n;
        c->is_mersenne = (i == CURVE_P521);

        mpz_init_set_str(c->P, raw[i].p, 16);
        mpz_init_set_str(c->B, raw[i].b, 16);
        mpz_init_set_str(c->GX, raw[i].gx, 16);
        mpz_init_set_str(c->GY, raw[i].gy, 16);
        mpz_init_set_str(c->ORDER, raw[i].order, 16);

        mpz_to_limbs(c->p, c->n, c->P);
        mpz_to_limbs(c->b, c->n, c->B);
        mpz_to_limbs(c->gx, c->n, c->GX);
        mpz_to_limbs(c->gy, c->n, c->GY);

        if (!c->is_mersenne) {
            // mu = floor(2^(2*64*n) / p), fits in n+1 limbs.
            mpz_t mu, pow;
            mpz_init(mu); mpz_init(pow);
            mpz_ui_pow_ui(pow, 2, (unsigned long)(2 * 64 * c->n));
            mpz_tdiv_q(mu, pow, c->P);
            mpz_to_limbs(c->mu, c->n + 1 <= BN_MAXLIMBS ? c->n + 1 : BN_MAXLIMBS, mu);
            mpz_clear(mu); mpz_clear(pow);
        }
    }
}

int curve_name_to_id(const char *name, curve_id_t *out) {
    for (int i = 0; i < CURVE_COUNT; i++) {
        if (strcmp(name, g_curves[i].name) == 0) { *out = (curve_id_t)i; return 1; }
    }
    return 0;
}
