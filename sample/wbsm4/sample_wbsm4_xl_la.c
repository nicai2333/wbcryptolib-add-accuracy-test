/*
 * @Author:
 * @LastEditors: RyanCLQ
 * @Date: 2023/5/28 12:58
 * @Description:
 */

#include <string.h>
#include <stdio.h>
#include "wbcrypto/wbsm4_xl_la.h"
#include "crypto/sm4.h"

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
            0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
            0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    unsigned char input[32]={
            0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
            0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    unsigned char output[32]={0};
    unsigned char recover[32]={0};
    unsigned char ct_vector[16]={
            0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
            0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };

    wbcrypto_wbsm4xl_la_context *ctx = malloc(sizeof(wbcrypto_wbsm4xl_la_context));
    wbcrypto_wbsm4_xl_la_gen(ctx, key);

    //使用普通的SM4来解密，验证白盒SM4的正确性，用于ECB,CBC的解密
    wbcrypto_sm4_context *dec_ctx = malloc(sizeof(wbcrypto_sm4_context));
    wbcrypto_sm4_setkey_dec(dec_ctx, key);

    wbcrypto_wbsm4_xl_la_ecb_encrypt(ctx, input, 32, output);
    printf("\nwbsm4xl_la_ecb\n");
    dump_hex(output, 32);
    if(memcmp(ct_vector,output,16)==0)
        printf("SM4_xl_la ECB 1 block encrypt Test passed!\n");
    wbcrypto_sm4_crypt_ecb(dec_ctx, output, 16, recover);//ecb模式的解密这里只解密16个字节，需要解密多组只要循环调用就行了
    printf("\nsm4_ecb_dec\n");
    dump_hex(recover, 16);

    wbcrypto_wbsm4_xl_la_free(ctx);
    wbcrypto_sm4_free(dec_ctx);
}

void test_cbc(void){
    unsigned char key[] = {
            0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
            0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    unsigned char iv_enc[] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    unsigned char input[32]={0};
    unsigned char output[32]={0};
    unsigned char recover[32]={0};

    wbcrypto_wbsm4xl_la_context *ctx = malloc(sizeof(wbcrypto_wbsm4xl_la_context));
    wbcrypto_wbsm4_xl_la_gen(ctx, key);

    //使用普通的SM4来解密，验证白盒SM4的正确性，用于ECB,CBC的解密
    wbcrypto_sm4_context *dec_ctx = malloc(sizeof(wbcrypto_sm4_context));
    wbcrypto_sm4_setkey_dec(dec_ctx, key);

    wbcrypto_wbsm4_xl_la_cbc_encrypt(ctx, iv_enc, input, 32, output);
    printf("\nwbsm4xl_la_cbc\n");
    dump_hex(output, 32);

    wbcrypto_sm4_crypt_cbc(dec_ctx, WBCRYPTO_SM4_DECRYPT, iv_enc, output, 32, recover);
    printf("\nsm4_cbc_dec\n");
    dump_hex(recover, 32);

    wbcrypto_wbsm4_xl_la_free(ctx);
    wbcrypto_sm4_free(dec_ctx);
}

void test_ctr(void){
    static const uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char iv_enc1[] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };//加密后会变化
    unsigned char iv_enc2[] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const unsigned char ecount_buf1[16]={0x00};
    const unsigned char ecount_buf2[16]={0x00};
    const unsigned int num1 = 0;
    const unsigned int num2 = 0;
    unsigned char input[0]={0};
    unsigned char output[32]={0};
    unsigned char recover[32]={0};
    unsigned char output1[32]={0};

    wbcrypto_wbsm4xl_la_context *ctx = malloc(sizeof(wbcrypto_wbsm4xl_la_context));
    wbcrypto_wbsm4_xl_la_gen(ctx, key);

    //GCM,CTR模式解密，由于GCM,CTR模式加解密时只用到分组密码的加密，所以需要加密的轮密钥
    wbcrypto_sm4_context *enc_ctx = malloc(sizeof(wbcrypto_sm4_context));
    wbcrypto_sm4_setkey_enc(enc_ctx, key);
    wbcrypto_wbsm4_xl_la_ctr_encrypt(ctx, iv_enc1, ecount_buf1, &num1, input, 32, output);
    printf("\nwbsm4xl_la_ctr\n");
    dump_hex(output, 32);
    wbcrypto_sm4_crypt_ctr(enc_ctx, iv_enc2, ecount_buf2, &num2, output, 32, recover);
    printf("\nsm4_ctr_dec\n");
    dump_hex(recover, 32);

    wbcrypto_wbsm4_xl_la_free(ctx);
    wbcrypto_sm4_free(enc_ctx);
}

void test_gcm(void){
    unsigned char key[] = {
            0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
            0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
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
    unsigned char recover[32]={0};

    wbcrypto_wbsm4xl_la_context *ctx = malloc(sizeof(wbcrypto_wbsm4xl_la_context));
    wbcrypto_wbsm4_xl_la_gen(ctx, key);

    WBCRYPTO_GCM128_CONTEXT *gcm_ctx = malloc(sizeof(WBCRYPTO_GCM128_CONTEXT));//白盒SM4的GCM
    wbcrypto_wbsm4_xl_la_gcm_encrypt_init(gcm_ctx, ctx, iv_enc, sizeof(iv_enc), aad, sizeof(aad));

    //GCM,CTR模式解密，由于GCM,CTR模式加解密时只用到分组密码的加密，所以需要加密的轮密钥
    wbcrypto_sm4_context *enc_ctx = malloc(sizeof(wbcrypto_sm4_context));
    wbcrypto_sm4_setkey_enc(enc_ctx,key);
    SM4_GCM128_CONTEXT *gcm_dec_ctx = malloc(sizeof(WBCRYPTO_GCM128_CONTEXT));//黑盒SM4的GCM
    wbcrypto_sm4_gcm128_init(gcm_dec_ctx, enc_ctx);
    wbcrypto_sm4_gcm128_setiv(gcm_dec_ctx, iv_enc, sizeof(iv_enc));
    wbcrypto_sm4_gcm128_aad(gcm_dec_ctx, aad, sizeof(aad));

    wbcrypto_wbsm4_xl_la_gcm_encrypt(gcm_ctx, input, 32, output);//白盒SM4加密
    printf("\nwbsm4xl_la_gcm\n");
    dump_hex(output, 32);
    
    wbcrypto_sm4_gcm128_crypt(gcm_dec_ctx, WBCRYPTO_SM4_DECRYPT, output, 32, recover);//黑盒SM4解密
    printf("\nsm4_gcm_dec\n");
    dump_hex(recover, 32);

    wbcrypto_wbsm4_xl_la_free(ctx);
    wbcrypto_sm4_free(enc_ctx);
    WBCRYPTO_gcm128_release(gcm_ctx);
    WBCRYPTO_gcm128_release(gcm_dec_ctx);
}

int main() {
    test_ecb();
    test_cbc();
    test_ctr();
    test_gcm();
    
    return 0;
}