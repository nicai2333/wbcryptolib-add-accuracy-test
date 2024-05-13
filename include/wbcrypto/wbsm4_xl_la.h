/*
 * @Author:
 * @Date: 2023/5/27 23:48
 * @Description: the whitebox sm4 of xiao lai with lookup tables of affine
 */

#ifndef WBCRYPTO_WBSM4_XL_LUT_AFFINE_H
#define WBCRYPTO_WBSM4_XL_LUT_AFFINE_H

#include "wbmatrix/WBMatrix.h"
#include "stdint.h"
#include "crypto/sm4.h"

#ifdef __cplusplus
extern "C" {
#endif

    #define GET32(pc)  (\
    ((uint32_t)(pc)[0] << 24) ^\
    ((uint32_t)(pc)[1] << 16) ^\
    ((uint32_t)(pc)[2] <<  8) ^\
    ((uint32_t)(pc)[3]))

    #define PUT32(st, ct)\
    (ct)[0] = (uint8_t)((st) >> 24);\
    (ct)[1] = (uint8_t)((st) >> 16);\
    (ct)[2] = (uint8_t)((st) >>  8);\
    (ct)[3] = (uint8_t)(st)

    typedef struct wbcrypto_wbsm4xl_la_context {
        uint32_t MM[32][3][4][256];
        uint32_t CC[32][4][256];
        uint32_t DD[32][4][256];
        uint32_t SE[4][4][256];
        uint32_t FE[4][4][256];
        uint32_t Table[32][4][256];
    }wbcrypto_wbsm4xl_la_context;
    
    void wbcrypto_wbsm4_xl_la_gen(wbcrypto_wbsm4xl_la_context *ctx, const unsigned char *key);
    void wbcrypto_wbsm4_xl_la_encrypt(const unsigned char *in, unsigned char *out, wbcrypto_wbsm4xl_la_context *ctx);
    void wbcrypto_wbsm4_xl_la_encrypt_withEX(const unsigned char *in, unsigned char *out, wbcrypto_wbsm4xl_la_context *ctx);
    int wbcrypto_wbsm4_xl_la_ecb_encrypt(wbcrypto_wbsm4xl_la_context *ctx, const unsigned char *input, size_t ilen, unsigned char *output);
    int wbcrypto_wbsm4_xl_la_cbc_encrypt(wbcrypto_wbsm4xl_la_context *ctx, unsigned char* iv, const unsigned char *input, size_t ilen, 
                                            unsigned char *output);
    int wbcrypto_wbsm4_xl_la_cbc_encrypt_withEX(wbcrypto_wbsm4xl_la_context *ctx, unsigned char* iv, const unsigned char *input, size_t ilen, 
                                            unsigned char *output);
    int wbcrypto_wbsm4_xl_la_gcm_encrypt_init(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, wbcrypto_wbsm4xl_la_context *ctx, unsigned char* iv, 
                                            size_t ivlen, unsigned char* aad, size_t aadlen);
    int wbcrypto_wbsm4_xl_la_gcm_encrypt_init_withEX(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, wbcrypto_wbsm4xl_la_context *ctx, unsigned char* iv, 
                                            size_t ivlen, unsigned char* aad, size_t aadlen);
    int wbcrypto_wbsm4_xl_la_gcm_encrypt(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, const unsigned char *input, size_t ilen, 
                                            unsigned char *output);
    int wbcrypto_wbsm4_xl_la_gcm_encrypt_withEX(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, const unsigned char *input,
                                            size_t ilen, unsigned char *output);
    int wbcrypto_wbsm4_xl_la_ctr_encrypt(wbcrypto_wbsm4xl_la_context *ctx, unsigned char* iv, unsigned char* ecount_buf, unsigned int* num, const unsigned char *input, size_t ilen, unsigned char *out);
    int wbcrypto_wbsm4_xl_la_ctr_encrypt_withEX(wbcrypto_wbsm4xl_la_context *ctx, unsigned char* iv, unsigned char* ecount_buf, unsigned int* num, const unsigned char *input, size_t ilen, unsigned char *output);
    void wbcrypto_wbsm4_xl_la_free(wbcrypto_wbsm4xl_la_context *ctx);

#ifdef __cplusplus
}
#endif
#endif //WBCRYPTO_WBSM4_XL_LUT_AFFINE_H
