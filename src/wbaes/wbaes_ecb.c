/*
 * @Author: Bin Li
 * @Date: 2023/5/28 15:58
 * @Description:
 */

#include "wbcrypto/wbaes.h"
#include "crypto/modes.h"
int wbcrypto_wbaes_ecb_encrypt(wbcrypto_wbaes_context *ctx, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    WBCRYPTO_ecb128_encrypt(IN, OUT, ilen, ctx, (WBCRYPTO_block128_f)wbcrypto_wbaes_encrypt);
    return 0;
}