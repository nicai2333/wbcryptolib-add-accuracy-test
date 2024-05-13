/*
 * @Author: RyanCLQ
 * @Date: 2023-06-06 20:46:42
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-06-08 10:47:47
 * @Description: 请填写简介
 */

#include <string.h>
#include <stdio.h>
#include "crypto/speed.h"
#include "wbcrypto/wbaes.h"

unsigned char key[] = {
        0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,
        0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08,
};
unsigned char aad[] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x03,0x7f,0xff,0xff,0xfe,0x89,0x2c,0x38,0x00,
        0x00,0x5c,0x36,0x5c,0x36,0x5c,0x36
};
unsigned char iv_enc[] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
unsigned char ecount_buf[16]={0x00};
unsigned int num = 0;
unsigned char input[16384]={0};
unsigned char output[16384];
wbcrypto_wbaes_context ctx;
WBCRYPTO_GCM128_CONTEXT gcm_ctx;

size_t test_wbaes_gcm_crypt_loop(size_t size){
    size_t count = 0;

    for (count = 0; run && count < 0xffffffffffffffff; count++)
    {
        wbcrypto_wbaes_gcm_encrypt(&gcm_ctx, input, size, output);
    }
    
    return count;
}

size_t test_wbaes_ctr_crypt_loop(size_t size){
    size_t count = 0;

    for (count = 0; run && count < 0xffffffffffffffff; count++)
    {
        wbcrypto_wbaes_ctr_encrypt(&ctx, iv_enc, ecount_buf, &num, input, size, output);
    }
    
    return count;
}

size_t test_wbaes_cbc_crypt_loop(size_t size){
    size_t count = 0;

    for (count = 0; run && count < 0xffffffffffffffff; count++)
    {
        wbcrypto_wbaes_cbc_encrypt(&ctx, iv_enc, input, size, output);
    }
    
    return count;
}

size_t test_wbaes_ecb_crypt_loop(size_t size){
    size_t count = 0;

    for (count = 0; run && count < 0xffffffffffffffff; count++)
    {
        wbcrypto_wbaes_ecb_encrypt(&ctx, input, size, output);
    }
    
    return count;
}

int main() {
    size_t size[6] = {16, 64, 256, 1024, 8192, 16384};
    
    wbcrypto_wbaes_gen(&ctx, key);
    wbcrypto_wbaes_gcm_encrypt_init(&gcm_ctx, &ctx, iv_enc, sizeof(iv_enc), aad, sizeof(aad));

    printf("\nwbaes_ecb:\n");
    performance_test_enc(test_wbaes_ecb_crypt_loop, size, 6, 3);
    printf("\nwbaes_cbc:\n");
    performance_test_enc(test_wbaes_cbc_crypt_loop, size, 6, 3);
    printf("\nwbaes_ctr:\n");
    performance_test_enc(test_wbaes_ctr_crypt_loop, size, 6, 3);
    printf("\nwbaes_gcm:\n");
    performance_test_enc(test_wbaes_gcm_crypt_loop, size, 6, 3);
    
    
    return 0;
}
