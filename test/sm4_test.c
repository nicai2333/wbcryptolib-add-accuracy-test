/*
 * @Author: RyanCLQ
 * @Date: 2023-06-08 09:55:40
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-06-08 10:12:58
 * @Description: 请填写简介
 */
 #include "crypto/sm4.h"
 #include <string.h>
 #include <stdio.h>


 int test_sm4_ebc_crypt(){

    unsigned char key[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char plaintext[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char cypher[16] = {
            0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
            0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
    };

     unsigned char output[16] = {0};

     wbcrypto_sm4_context enc_ctx;
     wbcrypto_sm4_setkey_enc(&enc_ctx, key);

     wbcrypto_sm4_context dec_ctx;
     wbcrypto_sm4_setkey_dec(&dec_ctx, key);

     wbcrypto_sm4_crypt_ecb(&enc_ctx, plaintext, 16, output);

     if(memcmp(output, cypher, sizeof(plaintext)) != 0){
         printf("sm4 encrypt not pass!\n");
     }

     wbcrypto_sm4_crypt_ecb(&dec_ctx, cypher, 16, output);

     if(memcmp(output, plaintext, sizeof(plaintext)) != 0){
         printf("sm4 decrypt not pass!\n");
     }

     return 0;

 }



 int main() {

     int ret = 0;
     ret = test_sm4_ebc_crypt();


     return ret;
 }