#ifndef ENTROPY_H
#define ENTROPY_H

#include "rng/jitterentropy/jitterentropy.h"

#ifdef __cplusplus
extern "C" {
#endif

    typedef union {
        volatile uint32_t pool_32[128];
        volatile uint8_t pool_8[512];
    } entropy_pool;

    typedef struct{
        entropy_pool pool;
        void *entropy_source;
    }entropy;

    int entropy_alloc(void **pool);

    void entropy_dealloc(void *pool);

    int entropy_init(entropy *ctx, int hash_mode);

    int entropy_update(entropy *ctx);

    int Get_entropy(uint8_t *buf, size_t len, int hash_mode);
    
#ifdef __cplusplus
}
#endif

#endif /* entropy.h */