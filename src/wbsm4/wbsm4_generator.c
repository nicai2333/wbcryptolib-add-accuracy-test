

#include "wbcrypto/wbsm4_generator.h"
#include "wbmatrix/WBMatrix.h"
#include "wbmatrix/random.h"
#include <string.h>
#include "crypto/sm4.h"


uint8_t SBOX[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

typedef struct Sm4WhiteboxAssistant{
    int rounds;
    Aff32 P[SM4_WHITEBOX_NUM_STATES][2];
    Aff8 E[SM4_WHITEBOX_NUM_STATES][4][2];
    Aff32 EC[SM4_WHITEBOX_NUM_STATES][2];
    Aff32 Q[SM4_WHITEBOX_NUM_STATES][2];
    uint8_t skbox_enc[SM4_WHITEBOX_NUM_STATES][4][256];

} Sm4WhiteboxAssistant;

//CSL matrix
// x + (x<<<2) + (x<<<10) + (x<<<18) + (x<<<24)
uint32_t sm4_csl_xor_matrix[32] = {0xA0202080, 0x50101040, 0x28080820, 0x14040410, 0xA020208, 0x5010104, 0x2808082, 0x1404041, 0x80A02020, 0x40501010, 0x20280808, 0x10140404, 0x80A0202, 0x4050101, 0x82028080, 0x41014040, 0x2080A020, 0x10405010, 0x8202808, 0x4101404, 0x2080A02, 0x1040501, 0x80820280, 0x40410140, 0x202080A0, 0x10104050, 0x8082028, 0x4041014, 0x202080A, 0x1010405, 0x80808202, 0x40404101};

void sm4_wb_gen_secrect_sbox(SM4_KEY_CTX *sm4_key, Sm4WhiteboxAssistant *assistant, uint8_t* dummy_array, int rounds) {
    uint8_t *sst;
    uint32_t *rk = sm4_key->sk;
    sst = (uint8_t*)assistant->skbox_enc;
    int not_dummy_round = 0;
    for (int i=0; i< rounds; i++) {
        if (dummy_array[i]==0) {
            for (int j=0; j<256; j++) {
                sst[   0 + j ] = SBOX[ j ^ ((rk[not_dummy_round] >> 24) & 0xff) ];
                sst[ 256 + j ] = SBOX[ j ^ ((rk[not_dummy_round] >> 16) & 0xff) ];
                sst[ 512 + j ] = SBOX[ j ^ ((rk[not_dummy_round] >>  8) & 0xff) ];
                sst[ 768 + j ] = SBOX[ j ^ ((rk[not_dummy_round]      ) & 0xff) ];
            }
            not_dummy_round++;
        } else {
            memset(sst, 0, sizeof(uint8_t)*1024);
        }
        sst += 1024;
    }
}


void sm4_wb_gen_affine(wbcrypto_wbsm4_context *sm4_wb_ctx, Sm4WhiteboxAssistant *assistant) {
    int i,j;
    int rounds = sm4_wb_ctx->rounds + 4;
    assistant->rounds = rounds;
    for (i=0; i<rounds; i++) {
        //gen P affine matrix
          genaffinepairM32(&assistant->P[i][0],&assistant->P[i][1]);

        //gen E affine matrix
        for (j=0; j<4; j++) {
            genaffinepairM8(&assistant->E[i][j][0],&assistant->E[i][j][1]);
        }

          // combine 4 E8 to 1 E32
        affinecomM8to32(assistant->E[i][0][1], assistant->E[i][1][1], assistant->E[i][2][1], assistant->E[i][3][1], &assistant->EC[i][1]);


        genaffinepairM32(&assistant->Q[i][0], &assistant->Q[i][1]);


    }

}


int sm4_combine_affine_table(wbcrypto_wbsm4_context *sm4_wb_ctx, Sm4WhiteboxAssistant *assistant, M32 csl_matrix) {
    int i,j;
    int rounds = sm4_wb_ctx->rounds;
    for (i=0; i<rounds; i++) {

        //part 1. gen M affine matrix

        affinemixM32(assistant->EC[i][1], assistant->P[i+1][1], &sm4_wb_ctx->M[i][0]);
        affinemixM32(assistant->EC[i][1], assistant->P[i+2][1], &sm4_wb_ctx->M[i][1]);
        affinemixM32(assistant->EC[i][1], assistant->P[i+3][1], &sm4_wb_ctx->M[i][2]);

        //part 2. gen Q combine L into 4 matrix

        M32 QL;
        MatMulMatM32(assistant->Q[i][0].Mat, csl_matrix, &QL.M);
        M32 QLi[4];
        for(j = 0; j<4; j++){
            for (int ii=0; ii<32; ii++) {
                    QLi[j].M[ii] = (uint8_t)(QL.M[ii] >> (8 * j));
            }
        }

        int k;
        uint32_t r = assistant->Q[i][0].Vec.V;

        for (k=0; k<256; k++) {

            for (int d=0; d<4; d++) {

               int kd =  affineU8(assistant->E[i][d][0], k);


                kd = assistant->skbox_enc[i][d][kd];

                uint32_t temp = 0;


                if(xorU8((uint8_t)(QLi[3-d].M[0]) & kd)) temp = 0x00000001;
                else temp = 0x00000000;

                for(int ii = 1; ii<32;ii++){
                    temp = temp << 1;
                    if(xorU8((uint8_t)(QLi[3-d].M[ii]) & kd)) temp ^= 0x00000001;

                }

                sm4_wb_ctx->ssbox_enc[i][d][k] = temp;

            }

            sm4_wb_ctx->ssbox_enc[i][3][k] = sm4_wb_ctx->ssbox_enc[i][3][k] ^ r;

        }

        //part 3. gen C D matrix, C for Xi0, D for T(Xi1+Xi2+Xi3+rk)

        affinemixM32(assistant->P[i+4][0], assistant->P[i][1], &sm4_wb_ctx->C[i]);

        affinemixM32(assistant->P[i+4][0], assistant->Q[i][1], &sm4_wb_ctx->D[i]);

        sm4_wb_ctx->D[i].Vec.V ^= assistant->P[i+4]->Vec.V ;


    }

    //external encoding

    for (int i=0; i<4; i++) {

        sm4_wb_ctx->SE[i].Mat = assistant->P[i][0].Mat;
        sm4_wb_ctx->SE[i].Vec = assistant->P[i][0].Vec;

        sm4_wb_ctx->FE[i].Mat = assistant->P[rounds+i][1].Mat;
        sm4_wb_ctx->FE[i].Vec = assistant->P[rounds+i][1].Vec;
    }

    return 0;
}

void initMatfromArray(M32 *Mat, uint32_t *array, int len) {
    for(int i = 0; i<len; i++){
        (*Mat).M[i] = array[i];
    }

}
/**
 * dummyrounds: 1 dummyrounds will expands 4 times
 * */

uint8_t * sm4_wb_gen_dummyround_array(int rounds, int dummyrounds) {
    int len_origin = rounds + dummyrounds;
    uint8_t *da = (uint8_t*) malloc(sizeof(uint8_t)*(len_origin));

    memset(da, 0, rounds);
    memset(da+rounds, 1, dummyrounds);
    int len_result = rounds + 4*dummyrounds;
    uint8_t *result = (uint8_t*) malloc(sizeof(uint8_t)*(len_result));
    uint8_t *iter = result;
    int i;
    for (i=0; i<len_origin; i++) {
        *iter = *(da+i);
        if (*iter) {
            memset(iter, 1, 4*sizeof(uint8_t));
            iter += 4;
        } else {
            iter ++;
        }
    }
    free(da);
    return result;
}



int sm4_wb_gen_tables_with_dummyrounds(const uint8_t *key, wbcrypto_wbsm4_context *sm4_wb_ctx, int enc, int dummyrounds, int randSeed) {

    if(randSeed != -1) SetRandSeed(randSeed);
    SM4_KEY_CTX sm4_enc_key;
    int ret = 0;
    int rounds = WBCRYPTO_SM4_NUM_ROUNDS + 4*dummyrounds;

    Sm4WhiteboxAssistant assistant;
    sm4_wb_ctx->rounds = rounds;
    assistant.rounds = rounds;

    if (enc==WBCRYPTO_WBSM4_ENCRYPT)
        wbcrypto_sm4_setkey_enc(&sm4_enc_key, key);
    else
        wbcrypto_sm4_setkey_dec(&sm4_enc_key, key);

    uint8_t* dummy_array = sm4_wb_gen_dummyround_array(WBCRYPTO_SM4_NUM_ROUNDS, dummyrounds);

    sm4_wb_gen_secrect_sbox(&sm4_enc_key, &assistant, dummy_array, rounds);

    sm4_wb_gen_affine(sm4_wb_ctx, &assistant);

    M32 csl_matrix;

    initMatfromArray(&csl_matrix, sm4_csl_xor_matrix, 32);


    ret = sm4_combine_affine_table(sm4_wb_ctx, &assistant, csl_matrix);


    free(dummy_array);

    return ret;
}



int wbcrypto_wbsm4_gentable_enc(wbcrypto_wbsm4_context *sm4_wb_ctx, const unsigned char *key) {
    return sm4_wb_gen_tables_with_dummyrounds(key, sm4_wb_ctx, WBCRYPTO_WBSM4_ENCRYPT, SM4_WHITEBOX_DUMMY_ROUND, 0);
}

int wbcrypto_wbsm4_gentable_enc_with_randseed(wbcrypto_wbsm4_context *sm4_wb_ctx, const unsigned char *key, int randSeed) {
    return sm4_wb_gen_tables_with_dummyrounds(key, sm4_wb_ctx, WBCRYPTO_WBSM4_ENCRYPT, SM4_WHITEBOX_DUMMY_ROUND,randSeed );
}

int wbcrypto_wbsm4_gentable_dec(wbcrypto_wbsm4_context *sm4_wb_ctx, const unsigned char *key) {
    return sm4_wb_gen_tables_with_dummyrounds(key, sm4_wb_ctx, WBCRYPTO_WBSM4_DECRYPT, SM4_WHITEBOX_DUMMY_ROUND, 0);
}

int wbcrypto_wbsm4_gentable_dec_with_randseed(wbcrypto_wbsm4_context *sm4_wb_ctx, const unsigned char *key, int randSeed) {
    return sm4_wb_gen_tables_with_dummyrounds(key, sm4_wb_ctx, WBCRYPTO_WBSM4_DECRYPT, SM4_WHITEBOX_DUMMY_ROUND, randSeed);
}

int wbcrypto_wbsm4_gentable_dec_to_bit(unsigned char *ptr, const unsigned char *key, int randSeed, size_t *table_size){
    int ret;
    wbcrypto_wbsm4_context dec_ctx;
    wbcrypto_wbsm4_gentable_dec_with_randseed(&dec_ctx, key, randSeed);
    *table_size = wbcrypto_wbsm4_export_to_str(&dec_ctx, ptr);
    return ret;
}

int wbcrypto_wbsm4_gentable_enc_to_bit(unsigned char *ptr, const unsigned char *key, int randSeed, size_t *table_size){
    int ret = 0;
    wbcrypto_wbsm4_context enc_ctx;
    wbcrypto_wbsm4_gentable_enc_with_randseed(&enc_ctx, key, randSeed);
    *table_size = wbcrypto_wbsm4_export_to_str(&enc_ctx, ptr);
    return ret;
}


