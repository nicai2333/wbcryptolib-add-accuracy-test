/*
 * @Author: RyanCLQ
 * @Date: 2023-05-28 12:45:52
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-05-30 10:32:43
 * @Description: 请填写简介
 */


#include "crypto/sm4.h"
#include <string.h>

int wbcrypto_sm4_crypt_cbc(const wbcrypto_sm4_context *ctx,
                            int mode,
                            unsigned char *iv,
                            const unsigned char *input,
                            size_t length,
                            unsigned char *output)
{

    int i;
    int p = 0;
    unsigned char temp[16];

    if( mode == WBCRYPTO_SM4_DECRYPT )
    {
        if(length % 16)
        return (WBCRYPTO_ERR_SM4_INVALID_INPUT_LENGTH);

        while( length )
        {
            memcpy( temp, input, 16 );
            wbcrypto_sm4_crypt_ecb( ctx, input, 16, output );

            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }
    else
    {

#ifndef WBCRYPTO_CIPHER_MODE_WITH_PADDING
        if(length % 16)
        return (WBCRYPTO_ERR_SM4_INVALID_INPUT_LENGTH);
#endif
        while( p < length )
        {

            if(length - p < 16){

                memcpy(temp, input,length - p);

                for(int j = length -p; j < 16; j++){

                    temp[j] = 16 - length - p;
                }

            }
            else{
                memcpy( temp, input, 16 );
            }

            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( temp[i] ^ iv[i] );

            wbcrypto_sm4_crypt_ecb( ctx, output, 16, output );
            memcpy( iv, output, 16 );

            input  += 16;
            output += 16;
            p      += 16;
        }
    }

    return 0;
}
