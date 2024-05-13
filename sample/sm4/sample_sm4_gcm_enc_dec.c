#include "crypto/sm4.h"
#include <string.h>
#include <stdio.h>
#include "hex_utils.h"

// 使用wbsm4_gcm模式进行加解密和产生tag
int sample_standard_sm4_gcm(){
    int ret = 0;
    unsigned char key[] = {
            0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,
            0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08,
    };
    unsigned char plaintext[] = {
            0x08,0x06,0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01,0x00,0x03,0x7f,0xff,0xff,0xfe,
            0xc0,0xa8,0x14,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xa8,0x14,0x0d,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };
    unsigned char A[] = {
            0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x03,0x7f,0xff,0xff,0xfe,0x89,0x2c,0x38,0x00,
            0x00,0x5c,0x36,0x5c,0x36,0x5c,0x36
    };
    unsigned char iv_enc[] = {
            0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36
    };
    unsigned char ciphertext[48];
    unsigned char output[48];  // 存放解密后的明文
    unsigned char tag1[16];
    unsigned char tag2[16];

    // 生成加密 enc_ctx
    wbcrypto_sm4_context enc_ctx;
     wbcrypto_sm4_setkey_enc(&enc_ctx, key);

    // // 利用wbsm4创建wbsm4_gcm
    SM4_GCM128_CONTEXT gcm_enc_ctx;
    wbcrypto_sm4_gcm128_init(&gcm_enc_ctx, &enc_ctx);
    wbcrypto_sm4_gcm128_setiv(&gcm_enc_ctx, iv_enc, sizeof(iv_enc));
    wbcrypto_sm4_gcm128_aad(&gcm_enc_ctx, A, sizeof(A));
    wbcrypto_sm4_gcm128_crypt(&gcm_enc_ctx,WBCRYPTO_SM4_ENCRYPT,plaintext,sizeof(plaintext), ciphertext);
    wbcrypto_sm4_gcm128_tag(&gcm_enc_ctx, &tag1, 16);
    print_buf_in_hex("tag1",tag1, 16);
    print_buf_in_hex("ciphertext",ciphertext, 48);

    // 解密密钥和加密密钥一样
    wbcrypto_sm4_context dec_ctx;
    wbcrypto_sm4_setkey_enc(&dec_ctx, key);

    SM4_GCM128_CONTEXT gcm_dec_ctx;
    wbcrypto_sm4_gcm128_init(&gcm_dec_ctx, &dec_ctx);
    wbcrypto_sm4_gcm128_setiv(&gcm_dec_ctx, iv_enc, sizeof(iv_enc));
    wbcrypto_sm4_gcm128_aad(&gcm_dec_ctx, A, sizeof(A));
    wbcrypto_sm4_gcm128_crypt(&gcm_dec_ctx, WBCRYPTO_SM4_DECRYPT,ciphertext,sizeof(ciphertext), output);
    wbcrypto_sm4_gcm128_tag(&gcm_dec_ctx, &tag2, 16);
    print_buf_in_hex("tag2",tag2, 16);
    print_buf_in_hex("output",output, 48);

    // 验证加解密的tag
    if (memcmp(tag1, tag2, sizeof(tag1)) != 0) {
        printf("tag1 和 tag2 不相等！\n");
        ret = -1;
        goto end;
    }
    
    // 验证是否正确解密明文
    if (memcmp(output, plaintext, sizeof(output)) != 0) {
        printf("output 和 plaintext 不相等！\n");
        ret = -1;
        goto end;
    }
end:
    return ret;
}

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

int main(){

    int ret;

    // 测试gcm加解密和产生tag
    if(sample_standard_sm4_gcm())
        printf("standard_sm4_gcm 执行出错！\n");
    else
        printf("standard_sm4_gcm 执行成功！\n");
    // //setup
    // ASSERT_SUCCESS(setup_wbsm4_keys());

    // //run actual samples
    // ASSERT_SUCCESS(sample_gcm_encryption());
    // ASSERT_SUCCESS(sample_gcm_decryption());

    cleanup:

    return ret;

}