#include "wbcrypto/wbsm4.h"
#include <string.h>
#include "crypto/modes.h"
int wbcrypto_wbsm4_crypt_cbc(const wbcrypto_wbsm4_context *ctx,
                           int mode,
                           size_t length,
                           unsigned char *iv,
                           const unsigned char *input,
                           unsigned char *output)
{

    if(mode == WBCRYPTO_WBSM4_ENCRYPT){
        WBCRYPTO_cbc128_encrypt(input, output, length, ctx, iv, (WBCRYPTO_block128_f)wbcrypto_wbsm4_encrypt);
    }
    else{

        WBCRYPTO_cbc128_decrypt(input, output,length, ctx, iv,  (WBCRYPTO_block128_f)wbcrypto_wbsm4_encrypt );

    }
    return 0;

}




int wbcrypto_wbsm4_cbc_encrypt(const wbcrypto_wbsm4_context *ctx,
                               size_t length,
                               unsigned char *input,
                               unsigned char *output){
    return wbcrypto_wbsm4_crypt_cbc(ctx, WBCRYPTO_WBSM4_ENCRYPT, length,  "0123456789abcdef", input, output);
}

int wbcrypto_wbsm4_cbc_decrypt(const wbcrypto_wbsm4_context *ctx,
                               size_t length,
                               unsigned char *input,
                               unsigned char *output){
    return wbcrypto_wbsm4_crypt_cbc(ctx, WBCRYPTO_WBSM4_DECRYPT, length,  "0123456789abcdef", input, output);
}


