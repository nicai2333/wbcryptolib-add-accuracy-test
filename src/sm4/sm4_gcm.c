/*
 * @Author: RyanCLQ
 * @Date: 2023-05-28 12:45:52
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-05-29 22:11:53
 * @Description: 请填写简介
 */
#include "crypto/sm4.h"

int wbcrypto_sm4_gcm128_init(SM4_GCM128_CONTEXT *gcm_ctx, wbcrypto_sm4_context *wb_gcm_ctx) {
    WBCRYPTO_gcm128_init(gcm_ctx, wb_gcm_ctx, (WBCRYPTO_block128_f)wbcrypto_sm4_encrypt);
    return 0;
}

int wbcrypto_sm4_gcm128_setiv(SM4_GCM128_CONTEXT *gcm_ctx, const unsigned char *ivec,
                         size_t len) {
    WBCRYPTO_gcm128_setiv(gcm_ctx, ivec, len);
    return 0;
}

int wbcrypto_sm4_gcm128_aad(SM4_GCM128_CONTEXT *gcm_ctx, const unsigned char *aad,
                      size_t len) {
    return WBCRYPTO_gcm128_aad(gcm_ctx, aad, len);
}

int wbcrypto_sm4_gcm128_crypt(SM4_GCM128_CONTEXT *gcm_ctx, const int mode, const unsigned char *in,
                          size_t length, unsigned char *out ) {
    int ret;
    if (mode)
        ret = WBCRYPTO_gcm128_encrypt(gcm_ctx, in, out, length);
    else
        ret = WBCRYPTO_gcm128_decrypt(gcm_ctx, in, out, length);
    return ret;
}

void wbcrypto_sm4_gcm128_tag(SM4_GCM128_CONTEXT *gcm_ctx, unsigned char *tag,
                       size_t len) {
    WBCRYPTO_gcm128_tag(gcm_ctx, tag, len);
}

int wbcrypto_sm4_gcm128_finish(SM4_GCM128_CONTEXT *gcm_ctx, const unsigned char *tag,
                         size_t len) {
    return WBCRYPTO_gcm128_finish(gcm_ctx, tag, len);
}

void wbcrypto_sm4_gcm128_release(SM4_GCM128_CONTEXT *gcm_ctx) {
    WBCRYPTO_gcm128_release(gcm_ctx);
}