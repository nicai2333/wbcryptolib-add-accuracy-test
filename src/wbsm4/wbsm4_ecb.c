#include "wbcrypto/wbsm4.h"



int wbcrypto_wbsm4_crypt_ecb(const wbcrypto_wbsm4_context *ctx, int mode, const unsigned char *input, unsigned char *output)
{
    if (mode)
        wbcrypto_wbsm4_encrypt(input, output, ctx);
    else	wbcrypto_wbsm4_decrypt(input, output, ctx);

    return 0;
}

int wbcrypto_wbsm4_ecb_encrypt(const wbcrypto_wbsm4_context *ctx,
                               const unsigned  char *input, unsigned char *output){
    wbcrypto_wbsm4_crypt_ecb(ctx, WBCRYPTO_WBSM4_ENCRYPT, input, output);
}

int wbcrypto_wbsm4_ecb_decrypt(const wbcrypto_wbsm4_context *ctx,
                               const unsigned  char *input, unsigned char *output){
    wbcrypto_wbsm4_crypt_ecb(ctx, WBCRYPTO_WBSM4_DECRYPT, input, output);
}
