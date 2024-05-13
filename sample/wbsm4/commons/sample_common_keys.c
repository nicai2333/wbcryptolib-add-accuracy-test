#include "sample_common_keys.h"

#define ASSERT_SUCCESS(func)       \
    do                           \
    {                            \
        if( ( ret = (func) ) != 0 ) \
            goto cleanup;        \
    } while( 0 )



//the sm4 whitebox table context for encryption
 wbcrypto_wbsm4_context  enc_ctx;

//the sm4 whitebox table context for decryption
 wbcrypto_wbsm4_context  dec_ctx;

int setup_wbsm4_keys(){
    int ret;

    unsigned char key[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    ASSERT_SUCCESS(wbcrypto_wbsm4_gentable_enc(&enc_ctx, key));

    ASSERT_SUCCESS(wbcrypto_wbsm4_gentable_dec(&dec_ctx, key));


    cleanup:

    return ret;



}

