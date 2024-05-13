#include "wbcrypto/wbsm4_generator.h"
#include <string.h>
#include <stdio.h>
#include "wbcrypto/wbsm4.h"
#define TEST_MSG "abcdefghijklmnopqrstyvwxyz1234567890"



int test_standard_wbsm4_ecb_crypt(){
    int ret = 0;
    unsigned char key[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char plaintext[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char cypher1[16] = {
            0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
            0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
    };
    unsigned char cypher2[16] = {
            0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
            0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66
    };
    unsigned char output[16];
    wbcrypto_wbsm4_context wbsm4_enc;
    wbcrypto_wbsm4_context wbsm4_dec;

    wbcrypto_wbsm4_gentable_enc_with_randseed(&wbsm4_enc, key, 1000);
    wbcrypto_wbsm4_ecb_encrypt(&wbsm4_enc, plaintext, output);

    if (memcmp(output, cypher1, sizeof(cypher1)) != 0) {
        ret = -1;
        goto end;
    }

    /*
     * 1000000 times encrypt test cost too much time
     */
//    unsigned char buf[16];
//    memcpy(buf, plaintext, sizeof(plaintext));
//    for(int i=0;i<1000000;i++){
//        wbcrypto_wbsm4_ecb_encrypt(&wbsm4_enc, buf, buf);
//    }
//
//    if (memcmp(output, cypher1, sizeof(cypher2)) != 0) {
//        ret = -1;
//        goto end;
//    }

    wbcrypto_wbsm4_gentable_dec_with_randseed(&wbsm4_dec, key, 1000);
    wbcrypto_wbsm4_ecb_decrypt(&wbsm4_dec, cypher1, output);

    if (memcmp(output, plaintext, sizeof(plaintext)) != 0) {
        ret = -1;
        goto end;
    }

end:
    return ret;


}




int test_standard_wbsm4_gcm_crypt(){
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

    wbcrypto_wbsm4_context sm4_ctx;
    wbcrypto_wbsm4_gentable_enc_with_randseed(&sm4_ctx, key,-1);
    wbcrypto_wbsm4_crypt_gcm(&sm4_ctx, WBCRYPTO_WBSM4_ENCRYPT, sizeof(plaintext), iv_enc, sizeof(iv_enc)
    ,A, sizeof(A), plaintext, output);
    if (memcmp(output, cypher, sizeof(cypher)) != 0) {
        ret = -1;
        goto end;
    }
    end:
    return ret;
}


int test_drm_gcm_encrypt_decrypt(){

    int ret =0;
    unsigned char key[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    int blocksize;

    wbcrypto_wbsm4_context enc_ctx;
    wbcrypto_wbsm4_gentable_enc_with_randseed(&enc_ctx, key, -1);


    for(int i=1;i<16;i++){
        blocksize = i*16+i;
        int n = blocksize;
        unsigned char *plaintext = malloc(blocksize);
        unsigned char *cypher = malloc(blocksize);
        unsigned char *output = malloc(blocksize);
        unsigned char *p = plaintext;
        while(n/16){
            memcpy(p, TEST_MSG, 16);
            p+=16;
            n-=16;
        }
        memcpy(plaintext, TEST_MSG, blocksize%16);

        wbcrypto_wbsm4_gcm_encrypt(&enc_ctx, blocksize, plaintext,  cypher);
        if (memcmp(cypher + blocksize - (blocksize % 16), plaintext+ blocksize - (blocksize % 16), blocksize % 16) != 0) {
            ret = -1;
            goto end;
        }
        wbcrypto_wbsm4_gcm_decrypt(&enc_ctx, blocksize, cypher, output);
        if (memcmp(output, plaintext, blocksize) != 0) {
            ret = -1;
            goto end;
        }
    }

    end:
    return ret;
}

int test_drm_cbc_encrypt_decrypt(){

    int ret =0;
    unsigned char key[16] = {
            0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,
            0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08,
    };
    int blocksize;

    wbcrypto_wbsm4_context enc_ctx;
    wbcrypto_wbsm4_gentable_enc_with_randseed(&enc_ctx, key, -1);

    wbcrypto_wbsm4_context dec_ctx;
    wbcrypto_wbsm4_gentable_dec_with_randseed(&dec_ctx, key, -1);
    for(int i=1;i<16;i++){
        blocksize = i*16+i;
        int n = blocksize;
        unsigned char *plaintext = malloc(blocksize);
        unsigned char *cypher = malloc(blocksize);
        unsigned char *output = malloc(blocksize);
        unsigned char *p = plaintext;
        while(n/16){
            memcpy(p, TEST_MSG, 16);
            p+=16;
            n-=16;
        }
        memcpy(plaintext, TEST_MSG, blocksize%16);

        wbcrypto_wbsm4_cbc_encrypt(&enc_ctx, blocksize, plaintext, cypher);
        if (memcmp(cypher + blocksize - (blocksize % 16), plaintext+ blocksize - (blocksize % 16), blocksize % 16) != 0) {
            ret = -1;
            goto end;
        }
        wbcrypto_wbsm4_cbc_decrypt(&dec_ctx, blocksize, cypher, output);
        if (memcmp(output, plaintext, blocksize) != 0) {
            ret = -1;
            goto end;
        }
    }

    end:
    return ret;
}

int test_whitebox_table_export_import(){

    int ret = 0;
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
    unsigned char output[16];

    size_t table_size;
    uint8_t *wbsm4_ptr = NULL;

    wbcrypto_wbsm4_context enc_ctx;

    wbcrypto_wbsm4_gentable_enc_to_bit(&wbsm4_ptr, key, 1000, &table_size);

    enc_ctx = *(wbcrypto_wbsm4_import_from_str(wbsm4_ptr));

    wbcrypto_wbsm4_ecb_encrypt(&enc_ctx, plaintext,output);

    if (memcmp(output, cypher, 16) != 0) {
        ret = -1;
        goto end;
    }

    end:
    return ret;

}

int main() {
    int ret = 0;
    if(test_standard_wbsm4_ecb_crypt() !=0){
        ret = -1;
        goto end;
    }
    if(test_standard_wbsm4_gcm_crypt() !=0){
        ret = -1;
        goto end;
    }
    if(test_drm_cbc_encrypt_decrypt() !=0){
        ret = -1;
        goto end;
    }
    if(test_drm_gcm_encrypt_decrypt() !=0){
        ret = -1;
        goto end;
    }
    if(test_whitebox_table_export_import() !=0){
        ret = -1;
        goto end;
    }

    end:
    return ret;
}