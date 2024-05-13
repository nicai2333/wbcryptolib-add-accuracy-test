/*
 * @Author: RyanCLQ
 * @Date: 2023-05-29 21:08:03
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-05-30 10:36:41
 * @Description: 请填写简介
 */
#include "wbcrypto/wbaes.h"
#include "crypto/modes.h"

int wbcrypto_wbaes_ctr_encrypt(wbcrypto_wbaes_context *ctx,
                            unsigned char *iv,
                            unsigned char *ecount_buf,
                            unsigned int *num,
                            const unsigned char *input,
                            size_t length,
                            unsigned char *output)
{
    WBCRYPTO_ctr128_encrypt(input, output, length, ctx, iv, ecount_buf, num, (WBCRYPTO_block128_f)wbcrypto_wbaes_encrypt);
    return 0;
}