#include "wbcrypto/wbsm4_se_la.h"
#include "wbcrypto/wbsm4_se_local.h"

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

void wbcrypto_wbsm4_se_la_gen(wbcrypto_wbsm4se_la_context *ctx, uint8_t *key)
{
    int i, j, x;
	uint32_t temp_u32;
    Aff32 P[36];
	Aff32 K[32];
	Aff32 L;
    Aff32 P_inv[36];
	Aff32 AA[32], BB[32];

	Aff32 M[32][3];
	Aff32 C[32];
	Aff32 D[32];

	uint32_t Q_constant[3] = {0};

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
        affinemixM32(K[i], P_inv[i + 1], &M[i][0]);
		affinemixM32(AA[i], M[i][0], &M[i][0]);

		affinemixM32(K[i], P_inv[i + 2], &M[i][1]);
		affinemixM32(AA[i], M[i][1], &M[i][1]);

		affinemixM32(K[i], P_inv[i + 3], &M[i][2]);
		affinemixM32(AA[i], M[i][2], &M[i][2]);

        //affine C D, C for Xi0, D for Pi+4 L B
        affinemixM32(P[i + 4], P_inv[i], &C[i]);

        affinemixM32(L, BB[i], &D[i]);
		affinemixM32(P[i + 4], D[i], &D[i]);

        uint32_t temp_u32 = cus_random();
        C[i].Vec.V ^= temp_u32;
        D[i].Vec.V ^= P[i + 4].Vec.V ^ temp_u32;
    }

	for(i = 0; i < 32; i++)
	{
		for(j = 0; j < 3; j++)
		{
			Q_constant[j] = cus_random();
		}
		for (x = 0; x < 256; x++) 
        {
			for (j = 0; j < 4; j++) 
            {
                temp_u32 = x << (24 - j * 8);
                ctx->MM[i][0][j][x] = affineU32(M[i][0], temp_u32);//分块矩阵乘法减少查找表的大小
                ctx->MM[i][1][j][x] = affineU32(M[i][1], temp_u32);
                ctx->MM[i][2][j][x] = affineU32(M[i][2], temp_u32);
				ctx->CC[i][j][x] = affineU32(C[i], temp_u32);
                ctx->DD[i][j][x] = affineU32(D[i], temp_u32);
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
	}

	for(i = 0; i < 32; i++)
	{
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
	
	//external encoding
    for (i = 0; i < 4; i++) 
    {
		for(j = 0; j < 3; j++)
		{
			Q_constant[j] = cus_random();
		}
        for(x = 0; x < 256; x++)
        {
            for(j = 0; j < 4; j++)
            {
                temp_u32 = x << (24 - j * 8);
                ctx->SEE[i][j][x] = affineU32(P[i], temp_u32);
                ctx->FEE[i][j][x] = affineU32(P_inv[35 - i], temp_u32);
            }
            for(j = 0; j < 3; j++)
            {
                ctx->SEE[i][j][x] ^= Q_constant[j];
                ctx->FEE[i][j][x] ^= Q_constant[j];
            }
            ctx->SEE[i][3][x] ^=  P[i].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
            ctx->FEE[i][3][x] ^=  P_inv[35 - i].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
        }
    }
}

void wbcrypto_wbsm4_se_la_encrypt(unsigned char IN[], unsigned char OUT[], wbcrypto_wbsm4se_la_context *ctx)
{
    int i;
    uint32_t x0, x1, x2, x3, x4;
    uint32_t xt0, xt1, xt2, xt3, xt4;

    x0 = GET32(IN);
    x1 = GET32(IN + 4);
    x2 = GET32(IN + 8);
    x3 = GET32(IN + 12);
    //external encoding
	x0 = ctx->SEE[0][0][(x0 >> 24) & 0xff] ^ ctx->SEE[0][1][(x0 >> 16) & 0xff] ^ ctx->SEE[0][2][(x0 >> 8) & 0xff] ^ ctx->SEE[0][3][x0 & 0xff];
    x1 = ctx->SEE[1][0][(x1 >> 24) & 0xff] ^ ctx->SEE[1][1][(x1 >> 16) & 0xff] ^ ctx->SEE[1][2][(x1 >> 8) & 0xff] ^ ctx->SEE[1][3][x1 & 0xff];
    x2 = ctx->SEE[2][0][(x2 >> 24) & 0xff] ^ ctx->SEE[2][1][(x2 >> 16) & 0xff] ^ ctx->SEE[2][2][(x2 >> 8) & 0xff] ^ ctx->SEE[2][3][x2 & 0xff];
    x3 = ctx->SEE[3][0][(x3 >> 24) & 0xff] ^ ctx->SEE[3][1][(x3 >> 16) & 0xff] ^ ctx->SEE[3][2][(x3 >> 8) & 0xff] ^ ctx->SEE[3][3][x3 & 0xff];
    
    for(i = 0; i < 32; i++)
    {
		xt1 = ctx->MM[i][0][0][(x1 >> 24) & 0xff] ^ ctx->MM[i][0][1][(x1 >> 16) & 0xff] ^ ctx->MM[i][0][2][(x1 >> 8) & 0xff] ^ ctx->MM[i][0][3][x1 & 0xff];
        xt2 = ctx->MM[i][1][0][(x2 >> 24) & 0xff] ^ ctx->MM[i][1][1][(x2 >> 16) & 0xff] ^ ctx->MM[i][1][2][(x2 >> 8) & 0xff] ^ ctx->MM[i][1][3][x2 & 0xff];
        xt3 = ctx->MM[i][2][0][(x3 >> 24) & 0xff] ^ ctx->MM[i][2][1][(x3 >> 16) & 0xff] ^ ctx->MM[i][2][2][(x3 >> 8) & 0xff] ^ ctx->MM[i][2][3][x3 & 0xff];
        x4 = xt1 ^ xt2 ^ xt3;
        x4 = (SM4_SBOX[(x4 >> 24) & 0xff] << 24) | (SM4_SBOX[(x4 >> 16) & 0xff] << 16) | (SM4_SBOX[(x4 >> 8) & 0xff] << 8) | SM4_SBOX[x4 & 0xff];
		xt0 = ctx->CC[i][0][(x0 >> 24) & 0xff] ^ ctx->CC[i][1][(x0 >> 16) & 0xff] ^ ctx->CC[i][2][(x0 >> 8) & 0xff] ^ ctx->CC[i][3][x0 & 0xff];
        xt4 = ctx->DD[i][0][(x4 >> 24) & 0xff] ^ ctx->DD[i][1][(x4 >> 16) & 0xff] ^ ctx->DD[i][2][(x4 >> 8) & 0xff] ^ ctx->DD[i][3][x4 & 0xff];
        x4 = xt0 ^ xt4;
        
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = x4;
    }
	//external encoding
	x0 = ctx->FEE[3][0][(x0 >> 24) & 0xff] ^ ctx->FEE[3][1][(x0 >> 16) & 0xff] ^ ctx->FEE[3][2][(x0 >> 8) & 0xff] ^ ctx->FEE[3][3][x0 & 0xff];
    x1 = ctx->FEE[2][0][(x1 >> 24) & 0xff] ^ ctx->FEE[2][1][(x1 >> 16) & 0xff] ^ ctx->FEE[2][2][(x1 >> 8) & 0xff] ^ ctx->FEE[2][3][x1 & 0xff];
    x2 = ctx->FEE[1][0][(x2 >> 24) & 0xff] ^ ctx->FEE[1][1][(x2 >> 16) & 0xff] ^ ctx->FEE[1][2][(x2 >> 8) & 0xff] ^ ctx->FEE[1][3][x2 & 0xff];
    x3 = ctx->FEE[0][0][(x3 >> 24) & 0xff] ^ ctx->FEE[0][1][(x3 >> 16) & 0xff] ^ ctx->FEE[0][2][(x3 >> 8) & 0xff] ^ ctx->FEE[0][3][x3 & 0xff];

    PUT32(x3, OUT);
    PUT32(x2, OUT + 4);
    PUT32(x1, OUT + 8);
    PUT32(x0, OUT + 12);
}
int wbcrypto_wbsm4_se_la_ecb_encrypt(wbcrypto_wbsm4se_la_context *ctx, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    WBCRYPTO_ecb128_encrypt(IN, OUT, ilen, ctx, (WBCRYPTO_block128_f)wbcrypto_wbsm4_se_la_encrypt);
    return 0;
}

int wbcrypto_wbsm4_se_la_gcm_encrypt_init(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, wbcrypto_wbsm4se_la_context *ctx, unsigned char* iv, size_t ivlen, unsigned char* aad, size_t aadlen)
{
    WBCRYPTO_gcm128_init(gcm_ctx, ctx, (WBCRYPTO_block128_f)wbcrypto_wbsm4_se_la_encrypt);
    WBCRYPTO_gcm128_setiv(gcm_ctx, iv, ivlen);
    WBCRYPTO_gcm128_aad(gcm_ctx, aad, aadlen);
    return 0;
}

int wbcrypto_wbsm4_se_la_cbc_encrypt(wbcrypto_wbsm4se_la_context *ctx, unsigned char* iv, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    WBCRYPTO_cbc128_encrypt(IN, OUT, ilen, ctx, iv, (WBCRYPTO_block128_f)wbcrypto_wbsm4_se_la_encrypt);
    return 0;
}

int wbcrypto_wbsm4_se_la_gcm_encrypt(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    return WBCRYPTO_gcm128_encrypt(gcm_ctx, IN, OUT, ilen);
}
int wbcrypto_wbsm4_se_la_ctr_encrypt(wbcrypto_wbsm4se_la_context *ctx, unsigned char* iv, unsigned char* ecount_buf, unsigned int* num, const unsigned char IN[], size_t ilen, unsigned char OUT[])
{
    WBCRYPTO_ctr128_encrypt(IN, OUT, ilen, ctx, iv, ecount_buf, num, (WBCRYPTO_block128_f)wbcrypto_wbsm4_se_la_encrypt);
    return 0;
}
void wbcrypto_wbsm4_se_la_free(wbcrypto_wbsm4se_la_context *ctx)
{
    memset( ctx, 0, sizeof(wbcrypto_wbsm4se_la_context) );
    if(ctx!=NULL){
        free(ctx);
        ctx=NULL;
    }
}