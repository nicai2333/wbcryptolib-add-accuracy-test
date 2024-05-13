/*
 * @Author: Bin Li
 * @Date: 2023/5/28 12:55
 * @Description:
 */
#include "wbcrypto/wbsm4_se.h"
#include "wbcrypto/wbsm4_se_local.h"

#if 1
M32 L_matrix = {
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

void wbcrypto_wbsm4_se_gen(wbcrypto_wbsm4se_context *ctx, const uint8_t *key)
{
    int i, j, x;
    Aff32 P[36];
    Aff32 K[32];
    Aff32 L;
    Aff32 P_inv[36];
    Aff32 AA[32], BB[32];

    wbcrypto_sm4_context sm4_ctx;
    wbcrypto_sm4_setkey_enc(&sm4_ctx, key);
    InitRandom(((unsigned int)time(NULL)));

    wbcrypto_wbsm4_se_initial(A,B);

    //affine L for linear layer
    L.Mat = L_matrix;
    L.Vec.V = 0;

    for (i = 0; i < 36; i++)
    {
        //affine P
        genaffinepairM32(&P[i], &P_inv[i]);
    }

    for (i = 0; i < 32; i++)
    {
        // combine 4 A8 to 1 A32
        int a0, a1, a2, a3;
        a0 = cus_random() % 2039;
        a1 = cus_random() % 2039;
        a2 = cus_random() % 2039;
        a3 = cus_random() % 2039;
        affinecomM8to32(A[a0], A[a1], A[a2], A[a3], &AA[i]);
        affinecomM8to32(B[a0], B[a1], B[a2], B[a3], &BB[i]);

        //affine K for round key
        identityM32(&K[i].Mat);
        K[i].Vec.V = sm4_ctx.sk[i];

        //affine M
        affinemixM32(K[i], P_inv[i + 1], &ctx->M[i][0]);
        affinemixM32(AA[i], ctx->M[i][0], &ctx->M[i][0]);

        affinemixM32(K[i], P_inv[i + 2], &ctx->M[i][1]);
        affinemixM32(AA[i], ctx->M[i][1], &ctx->M[i][1]);

        affinemixM32(K[i], P_inv[i + 3], &ctx->M[i][2]);
        affinemixM32(AA[i], ctx->M[i][2], &ctx->M[i][2]);

        //affine C D, C for Xi0, D for Pi+4 L B
        affinemixM32(P[i + 4], P_inv[i], &ctx->C[i]);

        affinemixM32(L, BB[i], &ctx->D[i]);
        affinemixM32(P[i + 4], ctx->D[i], &ctx->D[i]);

        uint32_t temp_u32 = cus_random();
        ctx->C[i].Vec.V ^= temp_u32;
        ctx->D[i].Vec.V ^= P[i + 4].Vec.V ^ temp_u32;
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
#endif

void wbcrypto_wbsm4_se_encrypt(const unsigned char IN[], unsigned char OUT[], wbcrypto_wbsm4se_context *ctx)
{
    int i;
    uint32_t x0, x1, x2, x3, x4;
    uint32_t xt0, xt1, xt2, xt3, xt4;

    x0 = GET32(IN);
    x1 = GET32(IN + 4);
    x2 = GET32(IN + 8);
    x3 = GET32(IN + 12);

    //外部编码 计算无外部编码的性能时去掉
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
    x4 = (SM4_SBOX[(x4 >> 24) & 0xff] << 24) | (SM4_SBOX[(x4 >> 16) & 0xff] << 16) | (SM4_SBOX[(x4 >> 8) & 0xff] << 8) | SM4_SBOX[x4 & 0xff];
    xt0 = affineU32(ctx->C[i], x0);
    xt4 = affineU32(ctx->D[i], x4);
    x4 = xt0 ^ xt4;

    x0 = x1;
    x1 = x2;
    x2 = x3;
    x3 = x4;
}

//外部编码 计算无外部编码的性能时去掉
x0 = affineU32(ctx->FE[3], x0);
x1 = affineU32(ctx->FE[2], x1);
x2 = affineU32(ctx->FE[1], x2);
x3 = affineU32(ctx->FE[0], x3);

PUT32(x3, OUT);
PUT32(x2, OUT + 4);
PUT32(x1, OUT + 8);
PUT32(x0, OUT + 12);
}

int wbcrypto_wbsm4_se_ecb_encrypt(wbcrypto_wbsm4se_context *ctx, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    WBCRYPTO_ecb128_encrypt(IN, OUT, ilen, ctx, (WBCRYPTO_block128_f)wbcrypto_wbsm4_se_encrypt);
    return 0;
}

int wbcrypto_wbsm4_se_gcm_encrypt_init(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, wbcrypto_wbsm4se_context *ctx, unsigned char* iv, size_t ivlen, unsigned char* aad, size_t aadlen)
{
    WBCRYPTO_gcm128_init(gcm_ctx, ctx, (WBCRYPTO_block128_f)wbcrypto_wbsm4_se_encrypt);
    WBCRYPTO_gcm128_setiv(gcm_ctx, iv, ivlen);
    WBCRYPTO_gcm128_aad(gcm_ctx, aad, aadlen);
    return 0;
}

int wbcrypto_wbsm4_se_cbc_encrypt(wbcrypto_wbsm4se_context *ctx, unsigned char* iv, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    WBCRYPTO_cbc128_encrypt(IN, OUT, ilen, ctx, iv, (WBCRYPTO_block128_f)wbcrypto_wbsm4_se_encrypt);
    return 0;
}

int wbcrypto_wbsm4_se_gcm_encrypt(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    return WBCRYPTO_gcm128_encrypt(gcm_ctx, IN, OUT, ilen);
}
int wbcrypto_wbsm4_se_ctr_encrypt(wbcrypto_wbsm4se_context *ctx, unsigned char* iv, unsigned char* ecount_buf, unsigned int* num, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    WBCRYPTO_ctr128_encrypt(IN, OUT, ilen, ctx, iv, ecount_buf, num, (WBCRYPTO_block128_f)wbcrypto_wbsm4_se_encrypt);
    return 0;
}
void wbcrypto_wbsm4_se_free(wbcrypto_wbsm4se_context *ctx)
{
    memset( ctx, 0, sizeof(wbcrypto_wbsm4se_context) );
    if(ctx!=NULL){
        free(ctx);
        ctx=NULL;
    }
}
