/*
 * @Author:
 * @Date: 2023/5/27 23:47
 * @Description: the whitebox sm4 of xiao lai with lookup tables of affine
 */
#include "wbcrypto/wbsm4_xl_la.h"

M32 LA_L_matrix = {
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

void wbcrypto_wbsm4_xl_la_gen(wbcrypto_wbsm4xl_la_context *ctx, const uint8_t *key)
{
    int i, j, x;
    uint8_t temp_u8;
    uint32_t temp_u32;
    Aff32 P[36];
    Aff32 P_inv[36];
    Aff8 Eij[32][4];
    Aff8 Eij_inv[32][4];
    Aff32 Ei_inv[32];
    Aff32 Q[32];
    Aff32 Q_inv[32];

    Aff32 M[32][3];
    Aff32 C[32];
    Aff32 D[32];
    uint32_t Q_constant[3] = {0};

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
        affinemixM32(Ei_inv[i], P_inv[i + 1], &M[i][0]);
        affinemixM32(Ei_inv[i], P_inv[i + 2], &M[i][1]);
        affinemixM32(Ei_inv[i], P_inv[i + 3], &M[i][2]);

        for(j = 0; j < 3; j++)
        {
            Q_constant[j] = cus_random();
        }
        for (x = 0; x < 256; x++)
        {
            for (j = 0; j < 4; j++)
            {
                temp_u32 = x << (24 - j * 8);
                ctx->MM[i][0][j][x] = affineU32(M[i][0], temp_u32);
                ctx->MM[i][1][j][x] = affineU32(M[i][1], temp_u32);
                ctx->MM[i][2][j][x] = affineU32(M[i][2], temp_u32);
            }
            for(j = 0; j < 3; j++)
            {
                ctx->MM[i][0][j][x] ^= Q_constant[j];
                ctx->MM[i][1][j][x] ^= Q_constant[j];
                ctx->MM[i][2][j][x] ^= Q_constant[j];
            }
            ctx->MM[i][0][3][x] ^=  M[i][0].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
            ctx->MM[i][1][3][x] ^=  M[i][1].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
            ctx->MM[i][2][3][x] ^=  M[i][2].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
        }

        //affine Q
        genaffinepairM32(&Q[i], &Q_inv[i]);

        //affine C D, C for Xi0, D for T(Xi1+Xi2+Xi3+rk)
        affinemixM32(P[i + 4], P_inv[i], &C[i]);
        affinemixM32(P[i + 4], Q_inv[i], &D[i]);
        uint32_t temp_u32 = cus_random();
        C[i].Vec.V ^= temp_u32;
        D[i].Vec.V ^= P[i + 4].Vec.V ^ temp_u32;
        for(j = 0; j < 3; j++)
        {
            Q_constant[j] = cus_random();
        }
        for (x = 0; x < 256; x++)
        {
            for (j = 0; j < 4; j++)
            {
                temp_u32 = x << (24 - j * 8);
                ctx->CC[i][j][x] = affineU32(C[i], temp_u32);
                ctx->DD[i][j][x] = affineU32(D[i], temp_u32);
            }
            for(j = 0; j < 3; j++)
            {
                ctx->CC[i][j][x] ^= Q_constant[j];
                ctx->DD[i][j][x] ^= Q_constant[j];
            }
            ctx->CC[i][3][x] ^=  C[i].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
            ctx->DD[i][3][x] ^=  D[i].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
        }
    }

    for (i = 0; i < 32; i++)
    {
        //combine QL
        M32 QL;
        MatMulMatM32(Q[i].Mat, LA_L_matrix, &QL);

        for(j = 0; j < 3; j++)
        {
            Q_constant[j] = cus_random();
        }

        for (x = 0; x < 256; x++)
        {
            for (j = 0; j < 4; j++)
            {
                temp_u8 = affineU8(Eij[i][j], x);
                temp_u8 = SM4_SBOX[temp_u8 ^ ((sm4_ctx.sk[i] >> (24 - j * 8)) & 0xff)];
                temp_u32 = temp_u8 << (24 - j * 8);
                ctx->Table[i][j][x] = MatMulNumM32(QL, temp_u32);
            }
            for(j = 0; j < 3; j++)
            {
                ctx->Table[i][j][x] ^= Q_constant[j];
            }
            ctx->Table[i][3][x] ^=  Q[i].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
        }
    }

    //external encoding
    for(j = 0; j < 3; j++)
    {
        Q_constant[j] = cus_random();
    }
    for (i = 0; i < 4; i++)
    {
        for(x = 0; x < 256; x++)
        {
            for(j = 0; j < 4; j++)
            {
                temp_u32 = x << (24 - j * 8);
                ctx->SE[i][j][x] = affineU32(P[i], temp_u32);
                ctx->FE[i][j][x] = affineU32(P_inv[35 - i], temp_u32);
            }
            for(j = 0; j < 3; j++)
            {
                ctx->SE[i][j][x] ^= Q_constant[j];
                ctx->FE[i][j][x] ^= Q_constant[j];
            }
            ctx->SE[i][3][x] ^=  P[i].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
            ctx->FE[i][3][x] ^=  P_inv[35 - i].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
        }
    }
}
void wbcrypto_wbsm4_xl_la_encrypt(const unsigned char IN[], unsigned char OUT[], wbcrypto_wbsm4xl_la_context *ctx)//消去外部编码的加密
{
    unsigned char EX_IN[16];
    unsigned char EX_OUT[16];
    int i;
    uint32_t x0, x1, x2, x3, x4;
    uint32_t xt0, xt1, xt2, xt3, xt4;

    x0 = GET32(IN);
    x1 = GET32(IN + 4);
    x2 = GET32(IN + 8);
    x3 = GET32(IN + 12);
    x0 = ctx->SE[0][0][(x0 >> 24) & 0xff] ^ ctx->SE[0][1][(x0 >> 16) & 0xff] ^ ctx->SE[0][2][(x0 >> 8) & 0xff] ^ ctx->SE[0][3][x0 & 0xff];
    x1 = ctx->SE[1][0][(x1 >> 24) & 0xff] ^ ctx->SE[1][1][(x1 >> 16) & 0xff] ^ ctx->SE[1][2][(x1 >> 8) & 0xff] ^ ctx->SE[1][3][x1 & 0xff];
    x2 = ctx->SE[2][0][(x2 >> 24) & 0xff] ^ ctx->SE[2][1][(x2 >> 16) & 0xff] ^ ctx->SE[2][2][(x2 >> 8) & 0xff] ^ ctx->SE[2][3][x2 & 0xff];
    x3 = ctx->SE[3][0][(x3 >> 24) & 0xff] ^ ctx->SE[3][1][(x3 >> 16) & 0xff] ^ ctx->SE[3][2][(x3 >> 8) & 0xff] ^ ctx->SE[3][3][x3 & 0xff];
    PUT32(x0, EX_IN);
    PUT32(x1, EX_IN + 4);
    PUT32(x2, EX_IN + 8);
    PUT32(x3, EX_IN + 12);
    wbcrypto_wbsm4_xl_la_encrypt_withEX(EX_IN, EX_OUT, ctx);
    x0 = GET32(EX_OUT);
    x1 = GET32(EX_OUT + 4);
    x2 = GET32(EX_OUT + 8);
    x3 = GET32(EX_OUT + 12);
    x0 = ctx->FE[0][0][(x0 >> 24) & 0xff] ^ ctx->FE[0][1][(x0 >> 16) & 0xff] ^ ctx->FE[0][2][(x0 >> 8) & 0xff] ^ ctx->FE[0][3][x0 & 0xff];
    x1 = ctx->FE[1][0][(x1 >> 24) & 0xff] ^ ctx->FE[1][1][(x1 >> 16) & 0xff] ^ ctx->FE[1][2][(x1 >> 8) & 0xff] ^ ctx->FE[1][3][x1 & 0xff];
    x2 = ctx->FE[2][0][(x2 >> 24) & 0xff] ^ ctx->FE[2][1][(x2 >> 16) & 0xff] ^ ctx->FE[2][2][(x2 >> 8) & 0xff] ^ ctx->FE[2][3][x2 & 0xff];
    x3 = ctx->FE[3][0][(x3 >> 24) & 0xff] ^ ctx->FE[3][1][(x3 >> 16) & 0xff] ^ ctx->FE[3][2][(x3 >> 8) & 0xff] ^ ctx->FE[3][3][x3 & 0xff];
    PUT32(x0, OUT);
    PUT32(x1, OUT + 4);
    PUT32(x2, OUT + 8);
    PUT32(x3, OUT + 12);
}

void wbcrypto_wbsm4_xl_la_encrypt_withEX(const unsigned char IN[], unsigned char OUT[],wbcrypto_wbsm4xl_la_context *ctx)//未消去外部编码的加密
{
    int i;
    uint32_t x0, x1, x2, x3, x4;
    uint32_t xt0, xt1, xt2, xt3, xt4;

    x0 = GET32(IN);
    x1 = GET32(IN + 4);
    x2 = GET32(IN + 8);
    x3 = GET32(IN + 12);


    for(i = 0; i < 32; i++)
    {
        xt1 = ctx->MM[i][0][0][(x1 >> 24) & 0xff] ^ ctx->MM[i][0][1][(x1 >> 16) & 0xff] ^ ctx->MM[i][0][2][(x1 >> 8) & 0xff] ^ ctx->MM[i][0][3][x1 & 0xff];
        xt2 = ctx->MM[i][1][0][(x2 >> 24) & 0xff] ^ ctx->MM[i][1][1][(x2 >> 16) & 0xff] ^ ctx->MM[i][1][2][(x2 >> 8) & 0xff] ^ ctx->MM[i][1][3][x2 & 0xff];
        xt3 = ctx->MM[i][2][0][(x3 >> 24) & 0xff] ^ ctx->MM[i][2][1][(x3 >> 16) & 0xff] ^ ctx->MM[i][2][2][(x3 >> 8) & 0xff] ^ ctx->MM[i][2][3][x3 & 0xff];
        x4 = xt1 ^ xt2 ^ xt3;
        x4 = ctx->Table[i][0][(x4 >> 24) & 0xff] ^ ctx->Table[i][1][(x4 >> 16) & 0xff] ^ ctx->Table[i][2][(x4 >> 8) & 0xff] ^ ctx->Table[i][3][x4 & 0xff];
        xt0 = ctx->CC[i][0][(x0 >> 24) & 0xff] ^ ctx->CC[i][1][(x0 >> 16) & 0xff] ^ ctx->CC[i][2][(x0 >> 8) & 0xff] ^ ctx->CC[i][3][x0 & 0xff];
        xt4 = ctx->DD[i][0][(x4 >> 24) & 0xff] ^ ctx->DD[i][1][(x4 >> 16) & 0xff] ^ ctx->DD[i][2][(x4 >> 8) & 0xff] ^ ctx->DD[i][3][x4 & 0xff];
        x4 = xt0 ^ xt4;

        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = x4;
    }

    PUT32(x3, OUT);
    PUT32(x2, OUT + 4);
    PUT32(x1, OUT + 8);
    PUT32(x0, OUT + 12);
}
int wbcrypto_wbsm4_xl_la_ecb_encrypt(wbcrypto_wbsm4xl_la_context *ctx, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    WBCRYPTO_ecb128_encrypt(IN, OUT, ilen, ctx, (WBCRYPTO_block128_f)wbcrypto_wbsm4_xl_la_encrypt);
    return 0;
}
int wbcrypto_wbsm4_xl_la_ctr_encrypt(wbcrypto_wbsm4xl_la_context *ctx, unsigned char* iv, unsigned char* ecount_buf, unsigned int* num, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    WBCRYPTO_ctr128_encrypt(IN, OUT, ilen, ctx, iv, ecount_buf, num, (WBCRYPTO_block128_f)wbcrypto_wbsm4_xl_la_encrypt);
    return 0;
}
int wbcrypto_wbsm4_xl_la_ctr_encrypt_withEX(wbcrypto_wbsm4xl_la_context *ctx, unsigned char* iv, unsigned char* ecount_buf, unsigned int* num, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    WBCRYPTO_ctr128_encrypt(IN, OUT, ilen, ctx, iv, ecount_buf, num, (WBCRYPTO_block128_f)wbcrypto_wbsm4_xl_la_encrypt_withEX);
    return 0;
}
int wbcrypto_wbsm4_xl_la_cbc_encrypt(wbcrypto_wbsm4xl_la_context *ctx, unsigned char* iv, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    WBCRYPTO_cbc128_encrypt(IN, OUT, ilen, ctx, iv, (WBCRYPTO_block128_f)wbcrypto_wbsm4_xl_la_encrypt);
    return 0;
}

int wbcrypto_wbsm4_xl_la_cbc_encrypt_withEX(wbcrypto_wbsm4xl_la_context *ctx, unsigned char* iv, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    WBCRYPTO_cbc128_encrypt(IN, OUT, ilen, ctx, iv, (WBCRYPTO_block128_f)wbcrypto_wbsm4_xl_la_encrypt_withEX);
    return 0;
}

int wbcrypto_wbsm4_xl_la_gcm_encrypt_init(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, wbcrypto_wbsm4xl_la_context *ctx, unsigned char* iv, size_t ivlen, unsigned char* aad, size_t aadlen)
{
    WBCRYPTO_gcm128_init(gcm_ctx, ctx, (WBCRYPTO_block128_f)wbcrypto_wbsm4_xl_la_encrypt);
    WBCRYPTO_gcm128_setiv(gcm_ctx, iv, ivlen);
    WBCRYPTO_gcm128_aad(gcm_ctx, aad, aadlen);
    return 0;
}

int wbcrypto_wbsm4_xl_la_gcm_encrypt_init_withEX(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, wbcrypto_wbsm4xl_la_context *ctx, unsigned char* iv, size_t ivlen, unsigned char* aad, size_t aadlen)
{
    WBCRYPTO_gcm128_init(gcm_ctx, ctx, (WBCRYPTO_block128_f)wbcrypto_wbsm4_xl_la_encrypt_withEX);
    WBCRYPTO_gcm128_setiv(gcm_ctx, iv, ivlen);
    WBCRYPTO_gcm128_aad(gcm_ctx, aad, aadlen);
    return 0;
}

int wbcrypto_wbsm4_xl_la_gcm_encrypt(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    return WBCRYPTO_gcm128_encrypt(gcm_ctx, IN, OUT, ilen);
}

int wbcrypto_wbsm4_xl_la_gcm_encrypt_withEX(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    return WBCRYPTO_gcm128_encrypt(gcm_ctx, IN, OUT, ilen);
}

void wbcrypto_wbsm4_xl_la_free(wbcrypto_wbsm4xl_la_context *ctx)
{
    memset( ctx, 0, sizeof(wbcrypto_wbsm4xl_la_context) );
    if(ctx!=NULL){
        free(ctx);
        ctx=NULL;
    }
}