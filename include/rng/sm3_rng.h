#ifndef SM3_RNG_H
#define SM3_RNG_H

#include <time.h>
#include <stdint.h>
#include "rng/jitterentropy/jitterentropy-sm3.h"
#include "rng/entropy.h"

#define SM3_RNG_MAX_RESEED_COUNTER (1<<20)
#define SM3_RNG_MAX_RESEED_SECONDS 600

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        uint8_t V[55];
        uint8_t C[55];
        uint32_t reseed_counter;
        time_t last_reseed_time;
    } sm3_rng;

    int sm3_rng_alloc(void **ctx);

    void sm3_rng_dealloc(void *ctx);

    int sm3_rng_init(sm3_rng *rng, const uint8_t *nonce, size_t nonce_len,
        const uint8_t *label, size_t label_len);

    int sm3_rng_reseed(sm3_rng *rng, const uint8_t *addin, size_t addin_len);

    int sm3_rng_generate(sm3_rng *rng, const uint8_t *addin, size_t addin_len,
        uint8_t *out, size_t outlen);

#ifdef __cplusplus
}
#endif
#endif
