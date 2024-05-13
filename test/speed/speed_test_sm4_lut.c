
/*
 * @Author: RyanCLQ
 * @Date: 2023-05-09 22:33:39
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-06-13 11:11:34
 * @Description: 
 */
#include <string.h>
#include <stdio.h>
#include "crypto/speed.h"
#include "crypto/sm4_lut.h"

// unsigned char key[] = {
//         0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,
//         0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08,
// };
// unsigned char aad[] = {
//         0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x03,0x7f,0xff,0xff,0xfe,0x89,0x2c,0x38,0x00,
//         0x00,0x5c,0x36,0x5c,0x36,0x5c,0x36
// };
// unsigned char iv_enc[] = {
//         0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
//         0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
// };
// unsigned char ecount_buf[16]={0x00};
// unsigned int num = 0;
// unsigned char input[16384]={0};
// unsigned char output[16384];
// wbcrypto_sm4_lut_context ctx;
// WBCRYPTO_GCM128_CONTEXT gcm_ctx;

// size_t test_sm4_lut_gcm_crypt_loop(size_t size){
//     size_t count = 0;

//     for (count = 0; run && count < 0xffffffffffffffff; count++)
//     {
//         wbcrypto_sm4_lut_gcm_encrypt(&gcm_ctx, input, size, output);
//     }
    
//     return count;
// }

// size_t test_sm4_lut_ctr_crypt_loop(size_t size){
//     size_t count = 0;

//     for (count = 0; run && count < 0xffffffffffffffff; count++)
//     {
//         wbcrypto_sm4_lut_ctr_encrypt(&ctx, iv_enc, ecount_buf, &num, input, size, output);
//     }
    
//     return count;
// }

// size_t test_sm4_lut_cbc_crypt_loop(size_t size){
//     size_t count = 0;

//     for (count = 0; run && count < 0xffffffffffffffff; count++)
//     {
//         wbcrypto_sm4_lut_cbc_encrypt(&ctx, iv_enc, input, size, output);
//     }
    
//     return count;
// }

// size_t test_sm4_lut_ecb_crypt_loop(size_t size){
//     size_t count = 0;

//     for (count = 0; run && count < 0xffffffffffffffff; count++)
//     {
//         wbcrypto_sm4_lut_ecb_encrypt(&ctx, input, size, output);
//     }
    
//     return count;
// }

int main() {
    size_t size[6] = {16, 64, 256, 1024, 8192, 16384};
    // uint8_t key_vector[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    
    // uint8_t pt_vector[16] =  {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    // uint8_t cipher_vector[16] = {0};
    // wbcrypto_sm4_lut_setkey_enc(&ctx, key_vector);
    // wbcrypto_sm4_lut_ecb_encrypt(&ctx,pt_vector,16,cipher_vector);
    // dump_hex(cipher_vector,16);
    // wbcrypto_sm4_lut_gcm_encrypt_init(&gcm_ctx, &ctx, iv_enc, sizeof(iv_enc), aad, sizeof(aad));

    // printf("\nsm4_lut_ecb:\n");
    // performance_test_enc(test_sm4_lut_ecb_crypt_loop, size, 6, 3);
    // printf("\nsm4_lut_cbc:\n");
    // performance_test_enc(test_sm4_lut_cbc_crypt_loop, size, 6, 3);
    // printf("\nsm4_lut_ctr:\n");
    // performance_test_enc(test_sm4_lut_ctr_crypt_loop, size, 6, 3);
    // printf("\nsm4_lut_gcm:\n");
    // performance_test_enc(test_sm4_lut_gcm_crypt_loop, size, 6, 3);
    sm4_lut_accuracy_test();
    performance_test_sm4_lut();


    return 0;
}
