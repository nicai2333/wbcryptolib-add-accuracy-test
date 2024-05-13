/*
 * @Author: RyanCLQ
 * @Date: 2023-06-18 10:36:41
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-06-20 16:45:57
 * @Description: 请填写简介
 */
#ifndef WBCRYPTO_WBSM4_XL_H
#define WBCRYPTO_WBSM4_XL_H

#include "wbmatrix/WBMatrix.h"
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

    typedef struct wbcrypto_wbsm4xl_context {
        Aff32 M[32][3];
        Aff32 C[32];
        Aff32 D[32];
        Aff32 SE[4];
        Aff32 FE[4];
        uint32_t Table[32][4][256];
    }wbcrypto_wbsm4xl_context;

    void wbcrypto_wbsm4_xl_gen(wbcrypto_wbsm4xl_context *ctx, uint8_t *key);
    void wbcrypto_wbsm4_xl_encrypt(const unsigned char *in, unsigned char *out, wbcrypto_wbsm4xl_context *ctx);
    int wbcrypto_wbsm4_xl_ecb_encrypt(wbcrypto_wbsm4xl_context *ctx, const unsigned char *input, size_t ilen, unsigned char *output);
    int wbcrypto_wbsm4_xl_cbc_encrypt(wbcrypto_wbsm4xl_context *ctx, unsigned char* iv, const unsigned char *input, size_t ilen, unsigned char *output);
    int wbcrypto_wbsm4_xl_gcm_encrypt_init(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, wbcrypto_wbsm4xl_context *ctx, unsigned char* iv, size_t ivlen, 
                                            unsigned char* aad, size_t aadlen);
    int wbcrypto_wbsm4_xl_gcm_encrypt(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, const unsigned char *input, size_t ilen, 
                                            unsigned char *output);
    int wbcrypto_wbsm4_xl_ctr_encrypt(wbcrypto_wbsm4xl_context *ctx, unsigned char* iv, unsigned char* ecount_buf, unsigned int* num, const unsigned char *input, size_t ilen, unsigned char *output);
    void wbcrypto_wbsm4_xl_free(wbcrypto_wbsm4xl_context *ctx);

#ifdef __cplusplus
}
#endif
#endif