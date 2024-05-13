/*
 * @Author: RyanCLQ
 * @Date: 2023-06-13 16:38:23
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-06-18 15:26:08
 * @Description: 请填写简介
 */

#include "crypto/speed_test.h"

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
int count = 100;
int sizes[] = {16, 64, 256, 1024, 8192, 16384};
double begin,end;

#define SPEED_TEST(prestr, func, threads_num, block_size)                                                  \
    for (int x = 1; x <= threads_num; x*=2) {                                                              \  
        begin = omp_get_wtime();                                                                           \ 
        _Pragma("omp parallel for num_threads(x)")                                                         \
        for(int y = 0; y < count; y++){                                                                    \  
            func;                                                                                          \  
        }                                                                                                  \  
        end = omp_get_wtime();                                                                             \  
        printf("\n%s block_size: %d threads: %d run %d byte, total time: %f s, per second run %f kbyte\n", \
                prestr, block_size, x, count*block_size, (end-begin), count*block_size/(end-begin)/1000);  \
    }


int wbcrypto_block_cipher_speed_test(int algorithm, int mode, int threads_num){
    int ret = 0;
    if (threads_num == 0){
        return -1;//线程数不为0
        goto end;
    }
    
    if(algorithm == WBAES_CEJO){
        
        wbcrypto_wbaes_context *ctx = malloc(sizeof(wbcrypto_wbaes_context));
        WBCRYPTO_GCM128_CONTEXT *gcm_ctx = malloc(sizeof(WBCRYPTO_GCM128_CONTEXT));
        
        wbcrypto_wbaes_gen(ctx, key);
        wbcrypto_wbaes_gcm_encrypt_init(gcm_ctx, ctx, iv_enc, sizeof(iv_enc), aad, sizeof(aad));

        switch (mode)
        {
        case ECB:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBAES_CEJO_ECB enc test ", wbcrypto_wbaes_ecb_encrypt(ctx, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        case CBC:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBAES_CEJO_CBC enc test ", wbcrypto_wbaes_cbc_encrypt(ctx, iv_enc, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        case CTR:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBAES_CEJO_CTR enc test ", wbcrypto_wbaes_ctr_encrypt(ctx, iv_enc, ecount_buf, &num, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        case GCM:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBAES_CEJO_GCM enc test ", wbcrypto_wbaes_gcm_encrypt(gcm_ctx, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        default:
            ret = -2;//mode不在范围内
            break;
        }
        goto end;
    }else if(algorithm == WBSM4_SE){
        
        wbcrypto_wbsm4se_context *ctx = malloc(sizeof(wbcrypto_wbsm4se_context));
        WBCRYPTO_GCM128_CONTEXT *gcm_ctx = malloc(sizeof(WBCRYPTO_GCM128_CONTEXT));
        
        wbcrypto_wbsm4_se_gen(ctx, key);
        wbcrypto_wbsm4_se_gcm_encrypt_init(gcm_ctx, ctx, iv_enc, sizeof(iv_enc), aad, sizeof(aad));

        switch (mode)
        {
        case ECB:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBSM4_SE_ECB enc test ", wbcrypto_wbsm4_se_ecb_encrypt(ctx, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        case CBC:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBSM4_SE_CBC enc test ", wbcrypto_wbsm4_se_cbc_encrypt(ctx, iv_enc, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        case CTR:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBSM4_SE_CTR enc test ", wbcrypto_wbsm4_se_ctr_encrypt(ctx, iv_enc, ecount_buf, &num, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        case GCM:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBSM4_SE_GCM enc test ", wbcrypto_wbsm4_se_gcm_encrypt(gcm_ctx, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        default:
            ret = -2;//mode不在范围内
            break;
        }
        goto end;
    }else if(algorithm == WBSM4_XL){
        
        wbcrypto_wbsm4xl_context *ctx = malloc(sizeof(wbcrypto_wbsm4xl_context));
        WBCRYPTO_GCM128_CONTEXT *gcm_ctx = malloc(sizeof(WBCRYPTO_GCM128_CONTEXT));
        
        wbcrypto_wbsm4_xl_gen(ctx, key);
        wbcrypto_wbsm4_xl_gcm_encrypt_init(gcm_ctx, ctx, iv_enc, sizeof(iv_enc), aad, sizeof(aad));

        switch (mode)
        {
        case ECB:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBSM4_XL_ECB enc test ", wbcrypto_wbsm4_xl_ecb_encrypt(ctx, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        case CBC:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBSM4_XL_CBC enc test ", wbcrypto_wbsm4_xl_cbc_encrypt(ctx, iv_enc, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        case CTR:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBSM4_XL_CTR enc test ", wbcrypto_wbsm4_xl_ctr_encrypt(ctx, iv_enc, ecount_buf, &num, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        case GCM:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBSM4_XL_GCM enc test ", wbcrypto_wbsm4_xl_gcm_encrypt(gcm_ctx, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        default:
            ret = -2;//mode不在范围内
            break;
        }
        goto end;
    }else if(algorithm == WBSM4_XL_LA){
        
        wbcrypto_wbsm4xl_la_context *ctx = malloc(sizeof(wbcrypto_wbsm4xl_la_context));
        WBCRYPTO_GCM128_CONTEXT *gcm_ctx = malloc(sizeof(WBCRYPTO_GCM128_CONTEXT));
        
        wbcrypto_wbsm4_xl_la_gen(ctx, key);
        wbcrypto_wbsm4_xl_la_gcm_encrypt_init(gcm_ctx, ctx, iv_enc, sizeof(iv_enc), aad, sizeof(aad));

        switch (mode)
        {
        case ECB:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBSM4_XL_LA_ECB enc test ", wbcrypto_wbsm4_xl_la_ecb_encrypt(ctx, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        case CBC:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBSM4_XL_LA_CBC enc test ", wbcrypto_wbsm4_xl_la_cbc_encrypt(ctx, iv_enc, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        case CTR:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBSM4_XL_LA_CTR enc test ", wbcrypto_wbsm4_xl_la_ctr_encrypt(ctx, iv_enc, ecount_buf, &num, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        case GCM:
            for (size_t i = 0; i < 6; i++){
                SPEED_TEST("WBSM4_XL_LA_GCM enc test ", wbcrypto_wbsm4_xl_la_gcm_encrypt(gcm_ctx, input, sizes[i], output), threads_num, sizes[i]);
            }
            break;
        default:
            ret = -2;//mode不在范围内
            break;
        }
        goto end;
    }else{
        ret = -3;//algorithm不存在
    }
    
    end:
        return ret;
}


