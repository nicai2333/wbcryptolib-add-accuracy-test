/*
 * @Author: RyanCLQ
 * @Date: 2023-05-28 20:25:22
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-06-09 22:21:07
 * @Description: 请填写简
 */
#ifndef WBAES_H
#define WBAES_H

#include "crypto/aes.h"
#include "crypto/modes.h"
#include "wbmatrix/WBMatrix.h"

#ifdef __cplusplus
extern "C" {
#endif

        /******************************************************************
        * CHOW Whitebox-AES
        *****************************************************************/

        struct wbaes_context {
            uint32_t TypeII[10][16][256];
            uint32_t TypeIII[9][16][256];
            uint8_t TypeIV_II[9][4][3][8][16][16];
            uint8_t TypeIV_III[9][4][3][8][16][16];
            uint8_t TypeIa[16][256];
            uint8_t TypeIb[16][256];
        };

        typedef struct wbaes_context wbcrypto_wbaes_context;
        void generatePermutation(unsigned char *permutation,  unsigned char *inverse);
        void wbcrypto_wbaes_gen(wbcrypto_wbaes_context *ctx, const unsigned char *key);
        void wbcrypto_wbaes_encrypt(const unsigned char *in, unsigned char *out, wbcrypto_wbaes_context *ctx);
        void wbcrypto_wbaes_encrypt_withEX(const unsigned char *in, unsigned char *out, wbcrypto_wbaes_context *ctx);
        int wbcrypto_wbaes_ecb_encrypt(wbcrypto_wbaes_context *ctx, const unsigned char *input, size_t ilen, unsigned char *output);
        int wbcrypto_wbaes_cbc_encrypt(wbcrypto_wbaes_context *ctx, unsigned char *iv, const unsigned char *input, size_t ilen, unsigned char *output);
        int wbcrypto_wbaes_ctr_encrypt(wbcrypto_wbaes_context *ctx, unsigned char *iv, unsigned char *ecount_buf, unsigned int *num, const unsigned char *input, size_t ilen, unsigned char *output);
        int wbcrypto_wbaes_gcm_encrypt_init(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, wbcrypto_wbaes_context *ctx, unsigned char* iv, size_t ivlen, unsigned char* aad, size_t aadlen);
        int wbcrypto_wbaes_gcm_encrypt(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, const unsigned char *input, size_t ilen, unsigned char *output);
        void wbcrypto_wbaes_free(wbcrypto_wbaes_context *ctx);
#ifdef __cplusplus
}
#endif

#endif //WBAES_H
