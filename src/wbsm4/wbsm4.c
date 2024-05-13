/*
 * @Author: Weijie Li
 * @Date: 2017-11-08 19:35:45
 * @Last Modified by: Weijie Li
 * @Last Modified time: 2017-12-22 17:06:15
 */



#include "wbcrypto/wbsm4.h"
#include <string.h>
#include "crypto/sm4.h"

#ifndef GET32
#define GET32(pc)  (					\
	((uint32_t)(pc)[0] << 24) ^			\
	((uint32_t)(pc)[1] << 16) ^			\
	((uint32_t)(pc)[2] <<  8) ^			\
	((uint32_t)(pc)[3]))
#endif //GET32

#ifndef SK32
#define SK32(A)						\
    ((skbox[0   +  (((A) >> 24) & 0xff)]) ^		\
    (skbox[256 +  (((A) >> 16) & 0xff)]) ^		\
    (skbox[512 +  (((A) >>  8) & 0xff)]) ^		\
    (skbox[768 +  (((A))       & 0xff)]      ))
#endif //SK32


#ifndef PUT32
#define PUT32(st, ct)					\
	(ct)[0] = (uint8_t)((st) >> 24);		\
	(ct)[1] = (uint8_t)((st) >> 16);		\
	(ct)[2] = (uint8_t)((st) >>  8);		\
	(ct)[3] = (uint8_t)(st)
#endif // PUT32


#ifndef ROUND
#define ROUND(x0, x1, x2, x3, x4, i)			\
xt1 = affineU32(sm4_wb_ctx->M[i][0], x1); \
xt2 = affineU32(sm4_wb_ctx->M[i][1], x2); \
xt3 = affineU32(sm4_wb_ctx->M[i][2], x3); \
x4 = xt1 ^ xt2 ^ xt3;			\
x4 = SK32(x4);					        \
skbox += 1024;                         \
xt0 = affineU32(sm4_wb_ctx->C[i], x0); \
xt4 = affineU32(sm4_wb_ctx->D[i], x4); \
x4 = xt0 ^ xt4;
#endif //ROUND

void wbcrypto_wbsm4_encrypt(const unsigned char *in, unsigned char *out, const wbcrypto_wbsm4_context *sm4_wb_ctx) {
    // const uint32_t *rk = key->rk;

    uint32_t x0, x1, x2, x3, x4;

    uint32_t xt0, xt1, xt2, xt3, xt4;

	x0 = GET32(in     );
	x1 = GET32(in +  4);
	x2 = GET32(in +  8);
    x3 = GET32(in + 12);

    uint32_t *skbox;
    x0 = affineU32(sm4_wb_ctx->SE[0], x0);
    x1 = affineU32(sm4_wb_ctx->SE[1], x1);
    x2 = affineU32(sm4_wb_ctx->SE[2], x2);
    x3 = affineU32(sm4_wb_ctx->SE[3], x3);

    skbox = (uint32_t*)sm4_wb_ctx->ssbox_enc;

    #if SM4_WHITEBOX_UNROLL_F
        assert(sm4_wb_ctx->rounds==32);
        ROUNDS(x0, x1, x2, x3, x4);
    #else
        int r = 0;
        int sm4_rounds = sm4_wb_ctx->rounds;
        const int unroll_rounds = sm4_rounds/5*5;
        while(r < unroll_rounds ) {
            ROUND(x0, x1, x2, x3, x4, r);
            r++;
            ROUND(x1, x2, x3, x4, x0, r);
            r++;
            ROUND(x2, x3, x4, x0, x1, r);
            r++;
            ROUND(x3, x4, x0, x1, x2, r);
            r++;
            ROUND(x4, x0, x1, x2, x3, r);
            r++;
        }
        while(r < sm4_rounds ) {
            ROUND(x0, x1, x2, x3, x4, r);
            r++;
            x0 = x1;
            x1 = x2;
            x2 = x3;
            x3 = x4;
        }
        x4 = x2;
        x2 = x0;
        x0 = x3;
        x3 = x1;
    #endif

    x0 = affineU32(sm4_wb_ctx->FE[3], x0);
    x4 = affineU32(sm4_wb_ctx->FE[2], x4);
    x3 = affineU32(sm4_wb_ctx->FE[1], x3);
    x2 = affineU32(sm4_wb_ctx->FE[0], x2);

    PUT32(x0, out     );
	PUT32(x4, out +  4);
	PUT32(x3, out +  8);
	PUT32(x2, out + 12);

	x0 = x1 = x2 = x3 = x4 = 0;

}

void wbcrypto_wbsm4_decrypt(const unsigned char *in, unsigned char *out, const wbcrypto_wbsm4_context *sm4_wb_ctx){
    wbcrypto_wbsm4_encrypt(in, out, sm4_wb_ctx);
}

int wbcrypto_wbsm4_export_to_str(const wbcrypto_wbsm4_context* ctx, void **dest) {
    int sz = 0;
    sz = sizeof(wbcrypto_wbsm4_context);
    sz += sizeof(uint32_t);

    *dest = malloc(sz);
    *((uint32_t *)*dest) = sz;
    uint8_t* ds  = (*(uint8_t**)dest) + sizeof(uint32_t);
    memcpy(ds, ctx, sizeof(wbcrypto_wbsm4_context));

    return sz;
}

wbcrypto_wbsm4_context* wbcrypto_wbsm4_import_from_str(const void *source) {

    wbcrypto_wbsm4_context *result = malloc(sizeof(wbcrypto_wbsm4_context));
    const uint8_t  *ptr = source;
    ptr += sizeof(uint32_t);
    memcpy(result, ptr, sizeof(wbcrypto_wbsm4_context));
    return result;

}


