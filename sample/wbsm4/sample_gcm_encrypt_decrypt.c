/**
 * Sample: Encrypt & Decrypt
 * this sample demonstrates the capability of encrypt & decrypt with WBSM4 algorithm
 */

#include "wbcrypto/wbsm4.h"
#include "commons/sample_common_keys.h"
#include "hex_utils.h"

#define ASSERT_SUCCESS(func)       \
    do                           \
    {                            \
        if( ( ret = (func) ) != 0 ) \
            goto cleanup;        \
    } while( 0 )

// instead of generating all the keys, we now load them manually to exhibit another way of doing it
//    this is done in sample_common_keys.c

//the plaintexts
char plaintext_buffer[] = "White Box SM4 Crypto Algorithm";
size_t plaintext_size = 30;

//the ciphertexts

uint8_t ciphertext_buffer[30] = {0};

uint8_t recovered_buffer[30] = {0};


int sample_gcm_encryption() {
    int ret;

    //run encrypt algorithm, the IV and AAD in gcm mode are specified in "0123456789abcdef"
    // if want to customize IV,use the following method "wbcrypto_wbsm4_crypt_gcm()".
    ASSERT_SUCCESS(wbcrypto_wbsm4_gcm_encrypt(&enc_ctx, plaintext_size,plaintext_buffer, ciphertext_buffer));

    //done!
    printf("encryption success!\n");
    print_buf_in_hex("ciphertext", ciphertext_buffer, sizeof(ciphertext_buffer));

    cleanup:
    return ret;
}


int sample_gcm_decryption() {
    int ret;

    //run decrypt algorithm, the IV and AAD in gcm mode are specified in "0123456789abcdef"
    // if want to customize IV,use the following method "wbcrypto_wbsm4_crypt_gcm()".
    ASSERT_SUCCESS(wbcrypto_wbsm4_gcm_decrypt(&dec_ctx, plaintext_size, ciphertext_buffer, recovered_buffer));

    //done!
    printf("\ndecryption success!");
    print_buf_in_hex("\nplaintext", plaintext_buffer, plaintext_size);
    print_buf_in_hex("\nrecovered", recovered_buffer, sizeof(recovered_buffer));

    cleanup:
    return ret;
}

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
    unsigned char cypher[] ={
            0x0a,0x59,0x91,0xa6,0x70,0xdc,0x0e,0xa2,0x6f,0x84,0xe4,0x55,0xa1,0xc0,0x61,0x47,
            0x8a,0xa0,0x9f,0x2f,0xbe,0x90,0x49,0x46,0x29,0xbc,0x58,0xe7,0x5b,0xe5,0xe9,0x1d,
            0xbc,0x6d,0x21,0x49,0xbc,0x1f,0xba,0xca,0xca,0xa9,0x72,0x2d,0x61,0x0f,0xde,0x1d
    };
    unsigned char output[48];
    unsigned char tag[16];
    // // 使用key生成查找表
    wbcrypto_wbsm4_context wbsm4_ctx;
    wbcrypto_wbsm4_gentable_enc_with_randseed(&wbsm4_ctx, key, -1);

    // // 利用wbsm4创建wbsm4_gcm
    WBSM4_GCM128_CONTEXT wbsm4_gcm_ctx;
    wbcrypto_wbsm4_gcm128_init(&wbsm4_gcm_ctx, &wbsm4_ctx);
    wbcrypto_wbsm4_gcm128_setiv(&wbsm4_gcm_ctx, iv_enc, sizeof(iv_enc));
    wbcrypto_wbsm4_gcm128_aad(&wbsm4_gcm_ctx, A, sizeof(A));
    wbcrypto_wbsm4_gcm128_encrypt(plaintext, output, sizeof(plaintext), &wbsm4_gcm_ctx, WBCRYPTO_WBSM4_ENCRYPT);
    if (memcmp(output, cypher, sizeof(cypher)) != 0) {
        printf("output 和 cipher 不相等！\n");
        ret = -1;
        goto end;
    }
    wbcrypto_wbsm4_gcm128_tag(&wbsm4_gcm_ctx, &tag, 16);
    print_buf_in_hex("tag",tag,16);
    end:
    return ret;
    // wbcrypto_wbsm4_context sm4_ctx;
    // wbcrypto_wbsm4_gentable_enc_with_randseed(&sm4_ctx, key,-1);
    // wbcrypto_wbsm4_crypt_gcm(&sm4_ctx, WBCRYPTO_WBSM4_ENCRYPT, sizeof(plaintext), iv_enc, sizeof(iv_enc)
    // ,A, sizeof(A), plaintext, output);
    // if (memcmp(output, cypher, sizeof(cypher)) != 0) {
    //     ret = -1;
    //     goto end;
    // }
    // end:
    // return ret;
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