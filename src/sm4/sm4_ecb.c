/*
 * @Author: RyanCLQ
 * @Date: 2023-05-28 12:45:52
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-05-30 10:29:31
 * @Description: 请填写简介
 */

#include "crypto/sm4.h"

int wbcrypto_sm4_crypt_ecb(const wbcrypto_sm4_context *ctx, const unsigned char *input, size_t length, unsigned char *output)
{
    WBCRYPTO_ecb128_encrypt(input, output, length, ctx, (WBCRYPTO_block128_f) wbcrypto_sm4_encrypt);
    return 0;
}
