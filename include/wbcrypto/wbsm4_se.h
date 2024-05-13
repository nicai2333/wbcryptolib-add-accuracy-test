/*
 * @Author: RyanCLQ
 * @LastEditors: RyanCLQ
 * @Date: 2023/5/28 12:56
 * @Description:
 */

#ifndef WBCRYPTO_WBSM4_SE_H
#define WBCRYPTO_WBSM4_SE_H
#include "wbmatrix/WBMatrix.h"
#include "crypto/sm4.h"

#ifdef __cplusplus
extern "C" {
#endif
    
    typedef unsigned char  u8;
    typedef unsigned int   u32;
    static Aff8 A[2039], B[2039];

    void wbcrypto_wbsm4_se_initial();

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

    typedef struct wbcrypto_wbsm4se_context {
        Aff32 M[32][3];
        Aff32 C[32];
        Aff32 D[32];
        Aff32 SE[4];
        Aff32 FE[4];
    }wbcrypto_wbsm4se_context;

    void wbcrypto_wbsm4_se_gen(wbcrypto_wbsm4se_context *ctx, const unsigned char *key);
    void wbcrypto_wbsm4_se_encrypt(const unsigned char *in, unsigned char *out, wbcrypto_wbsm4se_context *ctx);
    int wbcrypto_wbsm4_se_ecb_encrypt(wbcrypto_wbsm4se_context *ctx, const unsigned char *input, size_t ilen, unsigned char *output);
    int wbcrypto_wbsm4_se_cbc_encrypt(wbcrypto_wbsm4se_context *ctx, unsigned char* iv, const unsigned char *input, size_t ilen, unsigned char *output);
    int wbcrypto_wbsm4_se_gcm_encrypt_init(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, wbcrypto_wbsm4se_context *ctx, unsigned char* iv, size_t ivlen, 
                                            unsigned char* aad, size_t aadlen);
    int wbcrypto_wbsm4_se_gcm_encrypt(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, const unsigned char *input, size_t ilen, 
                                            unsigned char *output);
    int wbcrypto_wbsm4_se_ctr_encrypt(wbcrypto_wbsm4se_context *ctx, unsigned char* iv, unsigned char* ecount_buf, unsigned int* num, const unsigned char *input, size_t ilen, unsigned char *output);
    void wbcrypto_wbsm4_se_free(wbcrypto_wbsm4se_context *ctx);

#ifdef __cplusplus
}
#endif
#endif //WBCRYPTO_WBSM4_SE_H
