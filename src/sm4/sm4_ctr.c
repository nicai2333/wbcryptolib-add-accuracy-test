/*
 * @Author: RyanCLQ
 * @Date: 2023-05-29 15:35:35
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-05-29 16:03:18
 * @Description: 请填写简介
 */
#include "crypto/sm4.h"
int wbcrypto_sm4_crypt_ctr(const wbcrypto_sm4_context *ctx,
                            unsigned char *iv,
                            unsigned char *ecount_buf,
                            unsigned int *num,
                            const unsigned char *input,
                            size_t length,
                            unsigned char *output)
{
    WBCRYPTO_ctr128_encrypt(input, output, length, ctx, iv, ecount_buf, num, (WBCRYPTO_block128_f)wbcrypto_sm4_encrypt);
    return 0;
}
