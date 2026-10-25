#ifndef OPENSSL_REF_H
#define OPENSSL_REF_H
#include "curves.h"
#include "field_fast.h"

// Returns ns/add for `iterations` EC_POINT_add calls (reference datapoint, #5
// optional). group accumulator starts at G and repeatedly adds G.
double openssl_bench_add_ns(curve_id_t cid, long iterations);

// Shell out to `openssl x509 -pubkey` + `openssl pkey -pubin -text`, parse the
// curve name and uncompressed public point (04||X||Y) out of the text output.
// Returns 1 on success.
int cert_extract_pubkey(const char *path, curve_id_t *cid, fe_t x, fe_t y);

#endif
