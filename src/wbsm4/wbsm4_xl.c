/*
 * @Author: RyanCLQ
 * @Date: 2023-06-18 10:36:52
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-06-18 15:14:48
 * @Description: 请填写简介
 */
#include "wbcrypto/wbsm4_xl.h"

static M32 L_matrix = {
    .M[0] = 0xA0202080, 
    .M[1] = 0x50101040, 
    .M[2] = 0x28080820, 
    .M[3] = 0x14040410,
    .M[4] = 0xA020208, 
    .M[5] = 0x5010104, 
    .M[6] = 0x2808082, 
    .M[7] = 0x1404041, 
    .M[8] = 0x80A02020, 
    .M[9] = 0x40501010, 
    .M[10] = 0x20280808, 
    .M[11] = 0x10140404, 
    .M[12] = 0x80A0202, 
    .M[13] = 0x4050101, 
    .M[14] = 0x82028080, 
    .M[15] = 0x41014040, 
    .M[16] = 0x2080A020, 
    .M[17] = 0x10405010, 
    .M[18] = 0x8202808, 
    .M[19] = 0x4101404, 
    .M[20] = 0x2080A02, 
    .M[21] = 0x1040501, 
    .M[22] = 0x80820280, 
    .M[23] = 0x40410140, 
    .M[24] = 0x202080A0, 
    .M[25] = 0x10104050, 
    .M[26] = 0x8082028, 
    .M[27] = 0x4041014, 
    .M[28] = 0x202080A, 
    .M[29] = 0x1010405, 
    .M[30] = 0x80808202, 
    .M[31] = 0x40404101
};


void wbcrypto_wbsm4_xl_gen(wbcrypto_wbsm4xl_context *ctx, uint8_t *key)
{
    int i, j, x;
    Aff32 P[36];
    Aff32 P_inv[36];
    Aff8 Eij[32][4];
    Aff8 Eij_inv[32][4];
    Aff32 Ei_inv[32];
    Aff32 Q[32];
    Aff32 Q_inv[32];

    wbcrypto_sm4_context sm4_ctx;
    wbcrypto_sm4_setkey_enc(&sm4_ctx, key);
    InitRandom(((unsigned int)time(NULL)));

    for (i = 0; i < 36; i++) 
    {
        //affine P
        genaffinepairM32(&P[i], &P_inv[i]);
    }

    for (i = 0; i < 32; i++) 
    {
        //affine E
        for (j = 0; j < 4; j++) 
        {
            genaffinepairM8(&Eij[i][j], &Eij_inv[i][j]);
        }

        // combine 4 E8 to 1 E32
        affinecomM8to32(Eij_inv[i][0], Eij_inv[i][1], Eij_inv[i][2], Eij_inv[i][3], &Ei_inv[i]);

        //affine M
        affinemixM32(Ei_inv[i], P_inv[i + 1], &ctx->M[i][0]);//todo 可能需要加括号
        affinemixM32(Ei_inv[i], P_inv[i + 2], &ctx->M[i][1]);
        affinemixM32(Ei_inv[i], P_inv[i + 3], &ctx->M[i][2]);

        //affine Q
        genaffinepairM32(&Q[i], &Q_inv[i]);

        //affine C D, C for Xi0, D for T(Xi1+Xi2+Xi3+rk)
        affinemixM32(P[i + 4], P_inv[i], &ctx->C[i]);
        affinemixM32(P[i + 4], Q_inv[i], &ctx->D[i]);
        uint32_t temp_u32 = cus_random();
        ctx->C[i].Vec.V ^= temp_u32;
        ctx->D[i].Vec.V ^= P[i + 4].Vec.V ^ temp_u32;
    }

    for (i = 0; i < 32; i++)
    {
        //combine QL
        M32 QL;
        MatMulMatM32(Q[i].Mat, L_matrix, &QL);

        uint32_t Q_constant[3] = {0};
        for(j = 0; j < 3; j++)
        {
            Q_constant[j] = cus_random();
        }

        for (x = 0; x < 256; x++) 
        {
            for (j = 0; j < 4; j++) 
            {
                uint8_t temp_u8 = affineU8(Eij[i][j], x);
                temp_u8 = SM4_SBOX[temp_u8 ^ ((sm4_ctx.sk[i] >> (24 - j * 8)) & 0xff)];
                uint32_t temp_32 = temp_u8 << (24 - j * 8);
                ctx->Table[i][j][x] = MatMulNumM32(QL, temp_32);
            }
            for(j = 0; j < 3; j++)
            {
                ctx->Table[i][j][x] ^= Q_constant[j];
            }
            ctx->Table[i][3][x] ^=  Q[i].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
        }
    }

    //external encoding
    for (i = 0; i < 4; i++) 
    {
        ctx->SE[i].Mat = P[i].Mat;
        ctx->SE[i].Vec = P[i].Vec;

        ctx->FE[i].Mat = P_inv[35 - i].Mat;
        ctx->FE[i].Vec = P_inv[35 - i].Vec;
    }
}

void wbcrypto_wbsm4_xl_encrypt(const unsigned char IN[], unsigned char OUT[], wbcrypto_wbsm4xl_context *ctx)
{
    int i;
    uint32_t x0, x1, x2, x3, x4;
    uint32_t xt0, xt1, xt2, xt3, xt4;
    
    x0 = GET32(IN);
    x1 = GET32(IN + 4);
    x2 = GET32(IN + 8);
    x3 = GET32(IN + 12);

    x0 = affineU32(ctx->SE[0], x0);
    x1 = affineU32(ctx->SE[1], x1);
    x2 = affineU32(ctx->SE[2], x2);
    x3 = affineU32(ctx->SE[3], x3);

    for(i = 0; i < 32; i++)
    {
        xt1 = affineU32(ctx->M[i][0], x1);
        xt2 = affineU32(ctx->M[i][1], x2);
        xt3 = affineU32(ctx->M[i][2], x3);
        x4 = xt1 ^ xt2 ^ xt3;
        x4 = ctx->Table[i][0][(x4 >> 24) & 0xff] ^ ctx->Table[i][1][(x4 >> 16) & 0xff] ^ ctx->Table[i][2][(x4 >> 8) & 0xff] ^ ctx->Table[i][3][x4 & 0xff];
        xt0 = affineU32(ctx->C[i], x0);
        xt4 = affineU32(ctx->D[i], x4);
        x4 = xt0 ^ xt4;
        
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = x4;
    }

    x0 = affineU32(ctx->FE[3], x0);
    x1 = affineU32(ctx->FE[2], x1);
    x2 = affineU32(ctx->FE[1], x2);
    x3 = affineU32(ctx->FE[0], x3);

    PUT32(x3, OUT);
    PUT32(x2, OUT + 4);
    PUT32(x1, OUT + 8);
    PUT32(x0, OUT + 12);
}

int wbcrypto_wbsm4_xl_ecb_encrypt(wbcrypto_wbsm4xl_context *ctx, const unsigned char IN[], size_t ilen, unsigned char OUT[]){
    WBCRYPTO_ecb128_encrypt(IN, OUT, ilen, ctx, (WBCRYPTO_block128_f)wbcrypto_wbsm4_xl_encrypt);
    return 0;
}
int wbcrypto_wbsm4_xl_cbc_encrypt(wbcrypto_wbsm4xl_context *ctx, unsigned char* iv, const unsigned char IN[], size_t ilen, unsigned char OUT[]){
    WBCRYPTO_cbc128_encrypt(IN, OUT, ilen, ctx, iv, (WBCRYPTO_block128_f)wbcrypto_wbsm4_xl_encrypt);
    return 0;
}
int wbcrypto_wbsm4_xl_gcm_encrypt_init(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, wbcrypto_wbsm4xl_context *ctx, unsigned char* iv, size_t ivlen, 
                                        unsigned char* aad, size_t aadlen){
    WBCRYPTO_gcm128_init(gcm_ctx, ctx, (WBCRYPTO_block128_f)wbcrypto_wbsm4_xl_encrypt);
    WBCRYPTO_gcm128_setiv(gcm_ctx, iv, ivlen);
    WBCRYPTO_gcm128_aad(gcm_ctx, aad, aadlen);
}
int wbcrypto_wbsm4_xl_gcm_encrypt(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, const unsigned char IN[], size_t ilen, unsigned char OUT[]){
    return WBCRYPTO_gcm128_encrypt(gcm_ctx, IN, OUT, ilen);
}
int wbcrypto_wbsm4_xl_ctr_encrypt(wbcrypto_wbsm4xl_context *ctx, unsigned char* iv, unsigned char* ecount_buf, unsigned int* num, const unsigned char IN[], size_t ilen, unsigned char OUT[]){
    WBCRYPTO_ctr128_encrypt(IN, OUT, ilen, ctx, iv, ecount_buf, num, (WBCRYPTO_block128_f)wbcrypto_wbsm4_xl_encrypt);
    return 0;
}
void wbcrypto_wbsm4_xl_free(wbcrypto_wbsm4xl_context *ctx){
    memset( ctx, 0, sizeof(wbcrypto_wbsm4xl_context) );
    if(ctx!=NULL){
        free(ctx);
        ctx=NULL;
    }
}