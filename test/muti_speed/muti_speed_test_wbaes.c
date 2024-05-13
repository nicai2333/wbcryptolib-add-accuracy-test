/*
 * @Author: RyanCLQ
 * @Date: 2023-06-06 21:55:39
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-06-13 11:14:02
 * @Description: 请填写简介
 */
#include <stdio.h>
#include "wbcrypto/wbaes.h"
#include <omp.h>

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
wbcrypto_wbaes_context ctx;
WBCRYPTO_GCM128_CONTEXT gcm_ctx;

void test_ecb(void){
    for (int thread_num = 1; thread_num <= 16; thread_num*=2) {
        double begin,end;
        int sizes[] = {16, 64, 256, 1024, 8192, 16384};
        for(int i = 0; i < 6; i++){
            begin = omp_get_wtime();
            #pragma omp parallel for num_threads(thread_num)
            for(int j = 0; j < count;j++){
                wbcrypto_wbaes_ecb_encrypt(&ctx, input, sizes[i], output);
            }
            end = omp_get_wtime();
            printf("\nwbaes_ecb enc block_size: %d threads: %d run %d byte, total time: %f s, per second run %f kbyte\n", \
                    sizes[i], thread_num, count*sizes[i], (end-begin), count*sizes[i]/(end-begin)/1000);
        }
    }
}

void test_cbc(void){
    for (int thread_num = 1; thread_num <= 16; thread_num*=2) {
        double begin,end;
        int sizes[] = {16, 64, 256, 1024, 8192, 16384};
        for(int i = 0; i < 6; i++){
            begin = omp_get_wtime();
            #pragma omp parallel for num_threads(thread_num)
            for(int j = 0; j < count;j++){
                wbcrypto_wbaes_cbc_encrypt(&ctx, iv_enc, input, sizes[i], output);
            }
            end = omp_get_wtime();
            printf("\nwbaes_cbc enc block_size: %d threads: %d run %d byte, total time: %f s, per second run %f kbyte\n", \
                    sizes[i], thread_num, count*sizes[i], (end-begin), count*sizes[i]/(end-begin)/1000);
        }
    }
}

void test_ctr(void){
    for (int thread_num = 1; thread_num <= 16; thread_num*=2) {
            double begin,end;
            int sizes[] = {16, 64, 256, 1024, 8192, 16384};
            for(int i = 0; i < 6; i++){
                begin = omp_get_wtime();
                #pragma omp parallel for num_threads(thread_num)
                for(int j = 0; j < count; j++){
                    wbcrypto_wbaes_ctr_encrypt(&ctx, iv_enc, ecount_buf, &num, input, sizes[i], output);
                }
                end = omp_get_wtime();
                printf("\nwbaes_ctr enc block_size: %d threads: %d run %d byte, total time: %f s, per second run %f kbyte\n", \
                    sizes[i], thread_num, count*sizes[i], (end-begin), count*sizes[i]/(end-begin)/1000);
                }
        }
}

void test_gcm(void){
    for (int thread_num = 1; thread_num <= 16; thread_num*=2) {
            double begin,end;
            int sizes[] = {16, 64, 256, 1024, 8192, 16384};
            for(int i = 0; i < 6; i++){
                begin = omp_get_wtime();
                #pragma omp parallel for num_threads(thread_num)
                for(int j = 0; j < count; j++){
                    wbcrypto_wbaes_gcm_encrypt(&gcm_ctx, input, sizes[i], output);
                }
                end = omp_get_wtime();
                printf("\nwbaes_gcm enc block_size: %d threads: %d run %d byte, total time: %f s, per second run %f kbyte\n", \
                    sizes[i], thread_num, count*sizes[i], (end-begin), count*sizes[i]/(end-begin)/1000);
            }
        }
}


int main() {
    
    wbcrypto_wbaes_gen(&ctx, key);
    wbcrypto_wbaes_gcm_encrypt_init(&gcm_ctx, &ctx, iv_enc, sizeof(iv_enc), aad, sizeof(aad));

    test_ecb();
    test_cbc();
    test_ctr();
    test_gcm();

    return 0;
}