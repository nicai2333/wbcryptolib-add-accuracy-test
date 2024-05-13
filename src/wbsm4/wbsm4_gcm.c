/*
 * @Author: Weijie Li
 * @Date: 2017-12-22 17:17:43
 * @Last Modified by: Weijie Li
 * @Last Modified time: 2017-12-27 11:37:44
 */

#include "wbcrypto/wbsm4.h"
#include "crypto/modes.h"

void wbcrypto_wbsm4_gcm128_init(WBSM4_GCM128_CONTEXT *gcm_ctx, wbcrypto_wbsm4_context *wb_gcm_ctx) {
    WBCRYPTO_gcm128_init(gcm_ctx, wb_gcm_ctx, (WBCRYPTO_block128_f)wbcrypto_wbsm4_encrypt);
}

void wbcrypto_wbsm4_gcm128_setiv(WBSM4_GCM128_CONTEXT *gcm_ctx, const unsigned char *ivec,
                         size_t len) {
    WBCRYPTO_gcm128_setiv(gcm_ctx, ivec, len);
}

int wbcrypto_wbsm4_gcm128_aad(WBSM4_GCM128_CONTEXT *gcm_ctx, const unsigned char *aad,
                      size_t len) {
    return WBCRYPTO_gcm128_aad(gcm_ctx, aad, len);
}

int wbcrypto_wbsm4_gcm128_encrypt(const unsigned char *in, unsigned char *out,
                          size_t length, WBSM4_GCM128_CONTEXT *gcm_ctx, const int enc) {
    int ret;
    if (enc)
        ret = WBCRYPTO_gcm128_encrypt(gcm_ctx, in, out, length);
    else
        ret = WBCRYPTO_gcm128_decrypt(gcm_ctx, in, out, length);
    return ret;
}

void wbcrypto_wbsm4_gcm128_tag(WBSM4_GCM128_CONTEXT *gcm_ctx, unsigned char *tag,
                       size_t len) {
    WBCRYPTO_gcm128_tag(gcm_ctx, tag, len);
}

int wbcrypto_wbsm4_gcm128_finish(WBSM4_GCM128_CONTEXT *gcm_ctx, const unsigned char *tag,
                         size_t len) {
    return WBCRYPTO_gcm128_finish(gcm_ctx, tag, len);
}

void wbcrypto_wbsm4_gcm128_release(WBSM4_GCM128_CONTEXT *gcm_ctx) {

    WBCRYPTO_gcm128_release(gcm_ctx);
}

int wbcrypto_wbsm4_crypt_gcm(wbcrypto_wbsm4_context *ctx,
                             int mode,size_t length,
                             unsigned char *iv, size_t iv_length,
                             unsigned char *aad, size_t aad_length,
                             const unsigned char *input,
                             unsigned char *output){
    WBSM4_GCM128_CONTEXT gcm_ctx;
    wbcrypto_wbsm4_gcm128_init(&gcm_ctx, ctx);
    wbcrypto_wbsm4_gcm128_setiv(&gcm_ctx,iv, iv_length);
    wbcrypto_wbsm4_gcm128_aad(&gcm_ctx, aad, aad_length);
    wbcrypto_wbsm4_gcm128_encrypt(input, output, length, &gcm_ctx, mode);
    return 0;
}

int wbcrypto_wbsm4_gcm_encrypt(wbcrypto_wbsm4_context *ctx,
                               size_t length,
                               const unsigned char *input,
                               unsigned char *output){
    return wbcrypto_wbsm4_crypt_gcm(ctx, WBCRYPTO_WBSM4_ENCRYPT ,length,\
    "0123456789abcdef", 16, "0123456789abcdef",16, input, output);
}

int wbcrypto_wbsm4_gcm_decrypt(wbcrypto_wbsm4_context *ctx,
                               size_t length,
                               const unsigned char *input,
                               unsigned char *output){
    return wbcrypto_wbsm4_crypt_gcm(ctx, WBCRYPTO_WBSM4_DECRYPT ,length,\
    "0123456789abcdef", 16, "0123456789abcdef",16, input, output);
}