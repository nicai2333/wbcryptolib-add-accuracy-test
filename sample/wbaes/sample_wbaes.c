/*
 * @Author:
 * @LastEditors: RyanCLQ
 * @Date: 2023/5/28 12:58
 * @Description:
 */

#include <string.h>
#include <stdio.h>
#include "wbcrypto/wbaes.h"
#include "crypto/aes.h"

void dump_hex(uint8_t * h, int len)
{
    while(len--)
    {   
        printf("%02hhx ",*h++);
        if(len%16==0) printf("\n");
    }
}

void test_ecb(void){
    unsigned char key[] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    };
    unsigned char input[32]={0};
    unsigned char output[32]={0};
    unsigned char output1[32]={0};

    wbcrypto_wbaes_context *wbaes_enc_ctx = malloc(sizeof(wbcrypto_wbaes_context));
    wbcrypto_wbaes_gen(wbaes_enc_ctx,key);

    //使用普通的aes加密密文，验证白盒aes的正确性
    wbcrypto_aes_context *aes_enc_ctx = malloc(sizeof(wbcrypto_aes_context));
    wbcrypto_aes_setkey_enc(aes_enc_ctx,key);

    wbcrypto_wbaes_ecb_encrypt(wbaes_enc_ctx, input, 32, output);
    printf("\nwbaes_ecb\n");
    dump_hex(output, 32);
    wbcrypto_aes_crypt_ecb(aes_enc_ctx, input, 32, output1);
    printf("\naes_ecb\n");
    dump_hex(output1, 32);

    wbcrypto_wbaes_free(wbaes_enc_ctx);
    wbcrypto_aes_free(aes_enc_ctx);
}

void test_cbc(void){
    unsigned char key[] = {
            0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,
            0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08,
    };
    unsigned char iv_enc[] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    unsigned char input[32]={0};
    unsigned char output[32]={0};
    unsigned char output1[32]={0};
    
    wbcrypto_wbaes_context *wbaes_enc_ctx = malloc(sizeof(wbcrypto_wbaes_context));
    wbcrypto_wbaes_gen(wbaes_enc_ctx,key);

    //使用普通的aes加密密文，验证白盒aes的正确性
    wbcrypto_aes_context *aes_enc_ctx = malloc(sizeof(wbcrypto_aes_context));
    wbcrypto_aes_setkey_enc(aes_enc_ctx,key);

    wbcrypto_wbaes_cbc_encrypt(wbaes_enc_ctx, iv_enc, input, 32, output);
    printf("\nwbaes_cbc\n");
    dump_hex(output, 32);
    wbcrypto_aes_crypt_cbc(aes_enc_ctx, 1, iv_enc, input, 32, output1);
    printf("\naes_cbc\n");
    dump_hex(output1, 32);

    wbcrypto_wbaes_free(wbaes_enc_ctx);
    wbcrypto_aes_free(aes_enc_ctx);
}

void test_ctr(void){
    static const uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char iv_enc1[] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    unsigned char iv_enc2[] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const unsigned char ecount_buf1[16]={0x00};
    const unsigned char ecount_buf2[16]={0x00};
    const unsigned int num1 = 0;
    const unsigned int num2 = 0;
    unsigned char input[32]={0};
    unsigned char output[32]={0};
    unsigned char output1[32]={0};

    wbcrypto_wbaes_context *wbaes_enc_ctx = malloc(sizeof(wbcrypto_wbaes_context));
    wbcrypto_wbaes_gen(wbaes_enc_ctx, key);

    //GCM,CTR模式解密，由于GCM,CTR模式加解密时只用到分组密码的加密，所以需要加密的轮密钥
    wbcrypto_aes_context *aes_enc_ctx = malloc(sizeof(wbcrypto_aes_context));
    wbcrypto_aes_setkey_enc(aes_enc_ctx, key);

    wbcrypto_wbaes_ctr_encrypt(wbaes_enc_ctx, iv_enc1, ecount_buf1, &num1, input, 32, output);
    printf("\nwbaes_ctr\n");
    dump_hex(output, 32);
    
    wbcrypto_aes_crypt_ctr(aes_enc_ctx, iv_enc2, ecount_buf2, &num2, input, 32, output1);
    printf("\naes_ctr\n");
    dump_hex(output1, 32);

    wbcrypto_wbaes_free(wbaes_enc_ctx);
    wbcrypto_aes_free(aes_enc_ctx);
}

void test_gcm(void){
    unsigned char key[] = {
            0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,
            0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08,
    };
    unsigned char iv_enc[] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    unsigned char aad[] = {
            0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x03,0x7f,0xff,0xff,0xfe,0x89,0x2c,0x38,0x00,
            0x00,0x5c,0x36,0x5c,0x36,0x5c,0x36
    };
    unsigned char ecount_buf[16]={0x00};
    unsigned int num = 0;
    unsigned char input[32]={0};
    unsigned char output[32]={0};
    unsigned char output1[32]={0};

    wbcrypto_wbaes_context *wbaes_enc_ctx = malloc(sizeof(wbcrypto_wbaes_context));
    wbcrypto_wbaes_gen(wbaes_enc_ctx, key);
    WBCRYPTO_GCM128_CONTEXT *wbaes_gcm_ctx = malloc(sizeof(WBCRYPTO_GCM128_CONTEXT));
    wbcrypto_wbaes_gcm_encrypt_init(wbaes_gcm_ctx, wbaes_enc_ctx, iv_enc, sizeof(iv_enc), aad, sizeof(aad));

    //GCM,CTR模式解密，由于GCM,CTR模式加解密时只用到分组密码的加密，所以需要加密的轮密钥
    wbcrypto_aes_context *aes_enc_ctx = malloc(sizeof(wbcrypto_aes_context));
    wbcrypto_aes_setkey_enc(aes_enc_ctx, key);
    WBCRYPTO_GCM128_CONTEXT *aes_gcm_ctx = malloc(sizeof(WBCRYPTO_GCM128_CONTEXT));//黑盒aes的GCM
    wbcrypto_aes_crypt_gcm_init(aes_gcm_ctx, aes_enc_ctx, iv_enc,sizeof(iv_enc), aad, sizeof(aad));

    wbcrypto_wbaes_gcm_encrypt(wbaes_gcm_ctx, input, 32, output);//白盒aes加密
    printf("\nwbaes_gcm\n");
    dump_hex(output, 32);
    wbcrypto_aes_crypt_gcm(aes_gcm_ctx, input, 32, output1);//黑盒aes解密
    printf("\naes_gcm\n");
    dump_hex(output1, 32);

    wbcrypto_wbaes_free(wbaes_enc_ctx);
    wbcrypto_aes_free(aes_enc_ctx);
    WBCRYPTO_gcm128_release(wbaes_gcm_ctx);
    WBCRYPTO_gcm128_release(aes_gcm_ctx);

}

int main() {
    test_ecb();
    test_cbc();
    test_ctr();
    test_gcm();
    return 0;
}